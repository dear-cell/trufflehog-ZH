package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/alecthomas/kingpin/v2"
	"github.com/felixge/fgprof"
	"github.com/go-logr/logr"
	"github.com/jpillora/overseer"
	"github.com/mattn/go-isatty"
	"go.uber.org/automaxprocs/maxprocs"

	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer"
	"github.com/trufflesecurity/trufflehog/v3/pkg/cache/simple"
	"github.com/trufflesecurity/trufflehog/v3/pkg/cleantemp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/defaults"
	"github.com/trufflesecurity/trufflehog/v3/pkg/feature"
	"github.com/trufflesecurity/trufflehog/v3/pkg/handlers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/log"
	"github.com/trufflesecurity/trufflehog/v3/pkg/output"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui"
	"github.com/trufflesecurity/trufflehog/v3/pkg/updater"
	"github.com/trufflesecurity/trufflehog/v3/pkg/verificationcache"
	"github.com/trufflesecurity/trufflehog/v3/pkg/version"
)

var (
	cli = kingpin.New("TruffleHog", "TruffleHog 是一个用于寻找凭证的工具。")
	cmd string
	// https://github.com/trufflesecurity/trufflehog/blob/main/CONTRIBUTING.md#logging-in-trufflehog
	logLevel            = cli.Flag("log-level", `日志级别，范围从 0（信息）到 5（追踪）。可以通过“-1”禁用日志。`).Default("0").Int()
	debug               = cli.Flag("debug", "以调试模式运行。").Hidden().Bool()
	trace               = cli.Flag("trace", "以追踪模式运行。").Hidden().Bool()
	profile             = cli.Flag("profile", "启用性能分析并在 :18066 启动 pprof 和 fgprof 服务器。").Bool()
	localDev            = cli.Flag("local-dev", "隐藏功能，禁用本地开发时的 overseer。").Hidden().Bool()
	jsonOut             = cli.Flag("json", "以 JSON 格式输出。").Short('j').Bool()
	jsonLegacy          = cli.Flag("json-legacy", "使用预 v3.0 的 JSON 格式。仅适用于 git、gitlab 和 github 来源。").Bool()
	gitHubActionsFormat = cli.Flag("github-actions", "以 GitHub Actions 格式输出。").Bool()
	concurrency         = cli.Flag("concurrency", "并发工作线程数。").Default(strconv.Itoa(runtime.NumCPU())).Int()
	noVerification      = cli.Flag("no-verification", "不验证结果。").Bool()
	onlyVerified        = cli.Flag("only-verified", "仅输出已验证的结果。").Hidden().Bool()
	results             = cli.Flag("results", "指定输出的结果类型：已验证、未知、未验证、过滤未验证。默认输出所有类型。").String()

	allowVerificationOverlap   = cli.Flag("allow-verification-overlap", "允许不同检测器检测到相似凭证时进行验证").Bool()
	filterUnverified           = cli.Flag("filter-unverified", "仅输出每个块每个检测器的第一个未验证结果，如果有多个结果。").Bool()
	filterEntropy              = cli.Flag("filter-entropy", "使用香农熵过滤未验证结果。建议从 3.0 开始。").Float64()
	scanEntireChunk            = cli.Flag("scan-entire-chunk", "扫描整个块以查找秘密。").Hidden().Default("false").Bool()
	compareDetectionStrategies = cli.Flag("compare-detection-strategies", "比较不同的检测策略以匹配跨度").Hidden().Default("false").Bool()
	configFilename             = cli.Flag("config", "配置文件路径。").ExistingFile()
	// rules = cli.Flag("rules", "包含自定义规则的文件路径。").String()
	printAvgDetectorTime = cli.Flag("print-avg-detector-time", "打印每个检测器的平均处理时间。").Bool()
	noUpdate             = cli.Flag("no-update", "不检查更新。").Bool()
	fail                 = cli.Flag("fail", "如果找到结果，则退出码为 183。").Bool()
	verifiers            = cli.Flag("verifier", "设置自定义验证端点。").StringMap()
	customVerifiersOnly  = cli.Flag("custom-verifiers-only", "仅使用自定义验证端点。").Bool()
	detectorTimeout      = cli.Flag("detector-timeout", "每个检测器扫描块的最大时间（例如：30s）。").Duration()
	archiveMaxSize       = cli.Flag("archive-max-size", "扫描的最大归档文件大小。（字节单位，如 512B、2KB、4MB）").Bytes()
	archiveMaxDepth      = cli.Flag("archive-max-depth", "扫描归档文件的最大深度。").Int()
	archiveTimeout       = cli.Flag("archive-timeout", "提取归档文件的最大时间。").Duration()
	includeDetectors     = cli.Flag("include-detectors", "包含的检测器类型列表，逗号分隔。可以使用 protobuf 名称或 ID，也可以使用范围。").Default("all").String()
	excludeDetectors     = cli.Flag("exclude-detectors", "排除的检测器类型列表，逗号分隔。可以使用 protobuf 名称或 ID，也可以使用范围。ID 在此处定义时优先于包含列表。").String()
	jobReportFile        = cli.Flag("output-report", "将扫描报告写入提供的路径。").Hidden().OpenFile(os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)

	noVerificationCache = cli.Flag("no-verification-cache", "禁用验证缓存").Bool()

	// 添加功能标志
	forceSkipBinaries  = cli.Flag("force-skip-binaries", "强制跳过二进制文件。").Bool()
	forceSkipArchives  = cli.Flag("force-skip-archives", "强制跳过归档文件。").Bool()
	skipAdditionalRefs = cli.Flag("skip-additional-refs", "跳过额外的引用。").Bool()
	userAgentSuffix    = cli.Flag("user-agent-suffix", "添加到 User-Agent 的后缀。").String()

	gitScan             = cli.Command("git", "在 Git 仓库中查找凭证。")
	gitScanURI          = gitScan.Arg("uri", "Git 仓库 URL。预期格式为 https://、file:// 或 ssh://。").Required().String()
	gitScanIncludePaths = gitScan.Flag("include-paths", "包含在扫描中的文件路径，路径文件内每行一个正则表达式。").Short('i').String()
	gitScanExcludePaths = gitScan.Flag("exclude-paths", "排除在扫描中的文件路径，路径文件内每行一个正则表达式。").Short('x').String()
	gitScanExcludeGlobs = gitScan.Flag("exclude-globs", "要排除的逗号分隔的 glob 列表。此选项在 `git log` 层级进行过滤，从而加速扫描。").String()
	gitScanSinceCommit  = gitScan.Flag("since-commit", "从某个提交开始扫描。").String()
	gitScanBranch       = gitScan.Flag("branch", "扫描指定分支。").String()
	gitScanMaxDepth     = gitScan.Flag("max-depth", "扫描的最大提交深度。").Int()
	gitScanBare         = gitScan.Flag("bare", "扫描裸仓库（例如，适用于 pre-receive 钩子时使用）。").Bool()
	_                   = gitScan.Flag("allow", "无操作标志，仅为向后兼容。").Bool()
	_                   = gitScan.Flag("entropy", "无操作标志，仅为向后兼容。").Bool()
	_                   = gitScan.Flag("regex", "无操作标志，仅为向后兼容。").Bool()
	githubScan                  = cli.Command("github", "在GitHub仓库中查找凭据。")
	githubScanEndpoint          = githubScan.Flag("endpoint", "GitHub端点。").Default("https://api.github.com").String()
	githubScanRepos             = githubScan.Flag("repo", `要扫描的GitHub仓库。你可以多次使用这个标志。示例： "https://github.com/dustin-decker/secretsandstuff"`).Strings()
	githubScanOrgs              = githubScan.Flag("org", `要扫描的GitHub组织。你可以多次使用这个标志。示例： "trufflesecurity"`).Strings()
	githubScanToken             = githubScan.Flag("token", "GitHub令牌。可以通过环境变量GITHUB_TOKEN提供。").Envar("GITHUB_TOKEN").String()
	githubIncludeForks          = githubScan.Flag("include-forks", "在扫描中包含分支。").Bool()
	githubIncludeMembers        = githubScan.Flag("include-members", "在扫描中包含组织成员的仓库。").Bool()
	githubIncludeRepos          = githubScan.Flag("include-repos", `在组织扫描中包含的仓库。也可以是一个glob模式。你可以多次使用这个标志。必须使用GitHub仓库的完整名称。示例： "trufflesecurity/trufflehog", "trufflesecurity/t*"`).Strings()
	githubIncludeWikis          = githubScan.Flag("include-wikis", "在扫描中包含仓库的wiki。").Bool()
	githubExcludeRepos          = githubScan.Flag("exclude-repos", `在组织扫描中排除的仓库。也可以是一个glob模式。你可以多次使用这个标志。必须使用GitHub仓库的完整名称。示例： "trufflesecurity/driftwood", "trufflesecurity/d*"`).Strings()
	githubScanIncludePaths      = githubScan.Flag("include-paths", "包含要扫描的文件的正则表达式的路径，每个正则表达式一行。").Short('i').String()
	githubScanExcludePaths      = githubScan.Flag("exclude-paths", "排除要扫描的文件的正则表达式的路径，每个正则表达式一行。").Short('x').String()
	githubScanIssueComments     = githubScan.Flag("issue-comments", "在扫描中包括问题描述和评论。").Bool()
	githubScanPRComments        = githubScan.Flag("pr-comments", "在扫描中包括拉取请求描述和评论。").Bool()
	githubScanGistComments      = githubScan.Flag("gist-comments", "在扫描中包括gist评论。").Bool()
	githubCommentsTimeframeDays = githubScan.Flag("comments-timeframe", "在扫描问题、PR和gist评论时回顾的天数。").Uint32()
	
	// GitHub跨分支对象引用实验特性
	githubExperimentalScan = cli.Command("github-experimental", "运行一个实验性的GitHub扫描。必须至少指定一个实验性子模块进行扫描：object-discovery。")
	// GitHub实验性子模块
	githubExperimentalObjectDiscovery = githubExperimentalScan.Flag("object-discovery", "发现GitHub仓库中的隐藏数据对象。").Bool()
	// GitHub实验性选项
	githubExperimentalToken              = githubExperimentalScan.Flag("token", "GitHub令牌。可以通过环境变量GITHUB_TOKEN提供。").Envar("GITHUB_TOKEN").String()
	githubExperimentalRepo               = githubExperimentalScan.Flag("repo", "要扫描的GitHub仓库。示例： https://github.com/<user>/<repo>.git").Required().String()
	githubExperimentalCollisionThreshold = githubExperimentalScan.Flag("collision-threshold", "在object-discovery子模块中短SHA碰撞的阈值。默认值为1。").Default("1").Int()
	githubExperimentalDeleteCache        = githubExperimentalScan.Flag("delete-cached-data", "在object-discovery密钥扫描后删除缓存数据。").Bool()
	
	gitlabScan = cli.Command("gitlab", "在GitLab仓库中查找凭据。")
	// TODO: 添加更多GitLab选项
	gitlabScanEndpoint     = gitlabScan.Flag("endpoint", "GitLab端点。").Default("https://gitlab.com").String()
	gitlabScanRepos        = gitlabScan.Flag("repo", "GitLab仓库url。你可以多次使用这个标志。留空以扫描提供凭证的所有仓库。示例： https://gitlab.com/org/repo.git").Strings()
	gitlabScanToken        = gitlabScan.Flag("token", "GitLab令牌。可以通过环境变量GITLAB_TOKEN提供。").Envar("GITLAB_TOKEN").Required().String()
	gitlabScanIncludePaths = gitlabScan.Flag("include-paths", "包含要扫描的文件的正则表达式的路径，每个正则表达式一行。").Short('i').String()
	gitlabScanExcludePaths = gitlabScan.Flag("exclude-paths", "排除要扫描的文件的正则表达式的路径，每个正则表达式一行。").Short('x').String()
	gitlabScanIncludeRepos = gitlabScan.Flag("include-repos", `在组织扫描中包含的仓库。也可以是一个glob模式。你可以多次使用这个标志。必须使用Gitlab仓库的完整名称。示例： "trufflesecurity/trufflehog", "trufflesecurity/t*"`).Strings()
	gitlabScanExcludeRepos = gitlabScan.Flag("exclude-repos", `在组织扫描中排除的仓库。也可以是一个glob模式。你可以多次使用这个标志。必须使用Gitlab仓库的完整名称。示例： "trufflesecurity/driftwood", "trufflesecurity/d*"`).Strings()
	
	filesystemScan  = cli.Command("filesystem", "在文件系统中查找凭据。")
	filesystemPaths = filesystemScan.Arg("path", "要扫描的文件或目录的路径。").Strings()
	// 已废弃：--directory已被参数替代。
	filesystemDirectories = filesystemScan.Flag("directory", "要扫描的目录路径。你可以多次使用这个标志。").Strings()
	// TODO: 添加更多文件系统扫描选项。当前仅支持扫描一系列目录。
	// filesystemScanRecursive = filesystemScan.Flag("recursive", "递归扫描。").Short('r').Bool()
	filesystemScanIncludePaths = filesystemScan.Flag("include-paths", "包含要扫描的文件的正则表达式的路径，每个正则表达式一行。").Short('i').String()
	filesystemScanExcludePaths = filesystemScan.Flag("exclude-paths", "排除要扫描的文件的正则表达式的路径，每个正则表达式一行。").Short('x').String()
	
	s3Scan              = cli.Command("s3", "在S3桶中查找凭据。")
	s3ScanKey           = s3Scan.Flag("key", "用于认证的S3密钥。可以通过环境变量AWS_ACCESS_KEY_ID提供。").Envar("AWS_ACCESS_KEY_ID").String()
	s3ScanRoleArns      = s3Scan.Flag("role-arn", "指定用于扫描的IAM角色的ARN。你可以多次使用这个标志。").Strings()
	s3ScanSecret        = s3Scan.Flag("secret", "用于认证的S3密钥。可以通过环境变量AWS_SECRET_ACCESS_KEY提供。").Envar("AWS_SECRET_ACCESS_KEY").String()
	s3ScanSessionToken  = s3Scan.Flag("session-token", "用于认证临时凭证的S3会话令牌。可以通过环境变量AWS_SESSION_TOKEN提供。").Envar("AWS_SESSION_TOKEN").String()
	s3ScanCloudEnv      = s3Scan.Flag("cloud-environment", "使用云环境中的IAM凭证。").Bool()
	s3ScanBuckets       = s3Scan.Flag("bucket", "要扫描的S3桶的名称。你可以多次使用这个标志。与--ignore-bucket不兼容。").Strings()
	s3ScanIgnoreBuckets = s3Scan.Flag("ignore-bucket", "要忽略的S3桶的名称。你可以多次使用这个标志。与--bucket不兼容。").Strings()
	s3ScanMaxObjectSize = s3Scan.Flag("max-object-size", "要扫描的对象的最大大小。大于此大小的对象将被跳过。（字节单位，例如512B，2KB，4MB）").Default("250MB").Bytes()
	
	gcsScan           = cli.Command("gcs", "在GCS桶中查找凭据。")
	gcsProjectID      = gcsScan.Flag("project-id", "用于认证的GCS项目ID。不能与无认证扫描一起使用。可以通过环境变量GOOGLE_CLOUD_PROJECT提供。").Envar("GOOGLE_CLOUD_PROJECT").String()
	gcsCloudEnv       = gcsScan.Flag("cloud-environment", "使用应用默认凭证、IAM凭证进行认证。").Bool()
	gcsServiceAccount = gcsScan.Flag("service-account", "GCS服务账户的JSON文件路径。").ExistingFile()
	gcsWithoutAuth    = gcsScan.Flag("without-auth", "在没有认证的情况下扫描GCS桶。仅适用于公共桶。").Bool()
	gcsAPIKey         = gcsScan.Flag("api-key", "用于认证的GCS API密钥。可以通过环境变量GOOGLE_API_KEY提供。").Envar("GOOGLE_API_KEY").String()
	gcsIncludeBuckets = gcsScan.Flag("include-buckets", "要扫描的桶。用逗号分隔的桶列表。你可以多次使用这个标志。支持glob模式").Short('I').Strings()
	gcsExcludeBuckets = gcsScan.Flag("exclude-buckets", "排除扫描的桶。用逗号分隔的桶列表。支持glob模式").Short('X').Strings()
	gcsIncludeObjects = gcsScan.Flag("include-objects", "要扫描的对象。用逗号分隔的对象列表。你可以多次使用这个标志。支持glob模式").Short('i').Strings()
	gcsExcludeObjects = gcsScan.Flag("exclude-objects", "排除扫描的对象。用逗号分隔的对象列表。你可以多次使用这个标志。支持glob模式").Short('x').Strings()
	gcsMaxObjectSize  = gcsScan.Flag("max-object-size", "要扫描的对象的最大大小。大于此大小的对象将被跳过。（字节单位，例如512B，2KB，4MB）").Default("10MB").Bytes()
	syslogScan     = cli.Command("syslog", "扫描 syslog")
	syslogAddress  = syslogScan.Flag("address", "监听 syslog 的地址和端口。例如: 127.0.0.1:514").String()
	syslogProtocol = syslogScan.Flag("protocol", "监听的协议。udp 或 tcp").String()
	syslogTLSCert  = syslogScan.Flag("cert", "TLS 证书的路径。").String()
	syslogTLSKey   = syslogScan.Flag("key", "TLS 密钥的路径。").String()
	syslogFormat   = syslogScan.Flag("format", "日志格式。可以是 rfc3164 或 rfc5424").String()
	
	circleCiScan      = cli.Command("circleci", "扫描 CircleCI")
	circleCiScanToken = circleCiScan.Flag("token", "CircleCI token。也可以通过环境变量提供").Envar("CIRCLECI_TOKEN").Required().String()
	
	dockerScan       = cli.Command("docker", "扫描 Docker 镜像")
	dockerScanImages = dockerScan.Flag("image", "要扫描的 Docker 镜像。使用 file:// 前缀来指向本地 tarball，否则假定为镜像仓库。").Required().Strings()
	dockerScanToken  = dockerScan.Flag("token", "Docker bearer token。也可以通过环境变量提供").Envar("DOCKER_TOKEN").String()
	
	travisCiScan      = cli.Command("travisci", "扫描 TravisCI")
	travisCiScanToken = travisCiScan.Flag("token", "TravisCI token。也可以通过环境变量提供").Envar("TRAVISCI_TOKEN").Required().String()
	
	// Postman 暂时隐藏，直到我们收到更多社区反馈。
	postmanScan  = cli.Command("postman", "扫描 Postman")
	postmanToken = postmanScan.Flag("token", "Postman token。也可以通过环境变量提供").Envar("POSTMAN_TOKEN").String()
	
	postmanWorkspaces   = postmanScan.Flag("workspace", "要扫描的 Postman 工作区。此标志可以重复。已弃用的标志。").Hidden().Strings()
	postmanWorkspaceIDs = postmanScan.Flag("workspace-id", "要扫描的 Postman 工作区 ID。此标志可以重复。").Strings()
	
	postmanCollections   = postmanScan.Flag("collection", "要扫描的 Postman 集合。此标志可以重复。已弃用的标志。").Hidden().Strings()
	postmanCollectionIDs = postmanScan.Flag("collection-id", "要扫描的 Postman 集合 ID。此标志可以重复。").Strings()
	
	postmanEnvironments = postmanScan.Flag("environment", "要扫描的 Postman 环境。此标志可以重复。").Strings()
	
	postmanIncludeCollections   = postmanScan.Flag("include-collections", "要包括在扫描中的集合。此标志可以重复。已弃用的标志。").Hidden().Strings()
	postmanIncludeCollectionIDs = postmanScan.Flag("include-collection-id", "要包括在扫描中的集合 ID。此标志可以重复。").Strings()
	
	postmanIncludeEnvironments = postmanScan.Flag("include-environments", "要包括在扫描中的环境。此标志可以重复。").Strings()
	
	postmanExcludeCollections   = postmanScan.Flag("exclude-collections", "要从扫描中排除的集合。此标志可以重复。已弃用的标志。").Hidden().Strings()
	postmanExcludeCollectionIDs = postmanScan.Flag("exclude-collection-id", "要从扫描中排除的集合 ID。此标志可以重复。").Strings()
	
	postmanExcludeEnvironments = postmanScan.Flag("exclude-environments", "要从扫描中排除的环境。此标志可以重复。").Strings()
	postmanWorkspacePaths      = postmanScan.Flag("workspace-paths", "Postman 工作区的路径。").Strings()
	postmanCollectionPaths     = postmanScan.Flag("collection-paths", "Postman 集合的路径。").Strings()
	postmanEnvironmentPaths    = postmanScan.Flag("environment-paths", "Postman 环境的路径。").Strings()
	
	elasticsearchScan           = cli.Command("elasticsearch", "扫描 Elasticsearch")
	elasticsearchNodes          = elasticsearchScan.Flag("nodes", "Elasticsearch 节点").Envar("ELASTICSEARCH_NODES").Strings()
	elasticsearchUsername       = elasticsearchScan.Flag("username", "Elasticsearch 用户名").Envar("ELASTICSEARCH_USERNAME").String()
	elasticsearchPassword       = elasticsearchScan.Flag("password", "Elasticsearch 密码").Envar("ELASTICSEARCH_PASSWORD").String()
	elasticsearchServiceToken   = elasticsearchScan.Flag("service-token", "Elasticsearch 服务令牌").Envar("ELASTICSEARCH_SERVICE_TOKEN").String()
	elasticsearchCloudId        = elasticsearchScan.Flag("cloud-id", "Elasticsearch 云 ID。也可以通过环境变量提供").Envar("ELASTICSEARCH_CLOUD_ID").String()
	elasticsearchAPIKey         = elasticsearchScan.Flag("api-key", "Elasticsearch API 密钥。也可以通过环境变量提供").Envar("ELASTICSEARCH_API_KEY").String()
	elasticsearchIndexPattern   = elasticsearchScan.Flag("index-pattern", "过滤要搜索的索引").Default("*").Envar("ELASTICSEARCH_INDEX_PATTERN").String()
	elasticsearchQueryJSON      = elasticsearchScan.Flag("query-json", "过滤要搜索的文档").Envar("ELASTICSEARCH_QUERY_JSON").String()
	elasticsearchSinceTimestamp = elasticsearchScan.Flag("since-timestamp", "过滤自此时间戳以来创建的文档；覆盖任何来自 --query-json 的时间戳").Envar("ELASTICSEARCH_SINCE_TIMESTAMP").String()
	elasticsearchBestEffortScan = elasticsearchScan.Flag("best-effort-scan", "尝试持续扫描集群").Envar("ELASTICSEARCH_BEST_EFFORT_SCAN").Bool()
	
	jenkinsScan                  = cli.Command("jenkins", "扫描 Jenkins")
	jenkinsURL                   = jenkinsScan.Flag("url", "Jenkins URL").Envar("JENKINS_URL").Required().String()
	jenkinsUsername              = jenkinsScan.Flag("username", "Jenkins 用户名").Envar("JENKINS_USERNAME").String()
	jenkinsPassword              = jenkinsScan.Flag("password", "Jenkins 密码").Envar("JENKINS_PASSWORD").String()
	jenkinsInsecureSkipVerifyTLS = jenkinsScan.Flag("insecure-skip-verify-tls", "跳过 TLS 验证").Envar("JENKINS_INSECURE_SKIP_VERIFY_TLS").Bool()
	
	huggingfaceScan     = cli.Command("huggingface", "在 HuggingFace 数据集、模型和空间中查找凭证。")
	huggingfaceEndpoint = huggingfaceScan.Flag("endpoint", "HuggingFace 端点。").Default("https://huggingface.co").String()
	huggingfaceModels   = huggingfaceScan.Flag("model", "要扫描的 HuggingFace 模型。此标志可以重复。示例: 'username/model'").Strings()
	huggingfaceSpaces   = huggingfaceScan.Flag("space", "要扫描的 HuggingFace 空间。此标志可以重复。示例: 'username/space'").Strings()
	huggingfaceDatasets = huggingfaceScan.Flag("dataset", "要扫描的 HuggingFace 数据集。此标志可以重复。示例: 'username/dataset'").Strings()
	huggingfaceOrgs     = huggingfaceScan.Flag("org", `要扫描的 HuggingFace 组织。此标志可以重复。示例: "trufflesecurity"`).Strings()
	huggingfaceUsers    = huggingfaceScan.Flag("user", `要扫描的 HuggingFace 用户。此标志可以重复。示例: "trufflesecurity"`).Strings()
	huggingfaceToken    = huggingfaceScan.Flag("token", "HuggingFace token。可以通过环境变量 HUGGINGFACE_TOKEN 提供。").Envar("HUGGINGFACE_TOKEN").String()
		


	huggingfaceIncludeModels      = huggingfaceScan.Flag("include-models", "在扫描中包含的模型。您可以重复此标志。必须使用 HuggingFace 模型的完整名称。例如：'username/model'（仅与 --user 或 --org 一起使用）").Strings()
	huggingfaceIncludeSpaces      = huggingfaceScan.Flag("include-spaces", "在扫描中包含的空间。您可以重复此标志。必须使用 HuggingFace 空间的完整名称。例如：'username/space'（仅与 --user 或 --org 一起使用）").Strings()
	huggingfaceIncludeDatasets    = huggingfaceScan.Flag("include-datasets", "在扫描中包含的数据集。您可以重复此标志。必须使用 HuggingFace 数据集的完整名称。例如：'username/dataset'（仅与 --user 或 --org 一起使用）").Strings()
	huggingfaceIgnoreModels       = huggingfaceScan.Flag("ignore-models", "在扫描中忽略的模型。您可以重复此标志。必须使用 HuggingFace 模型的完整名称。例如：'username/model'（仅与 --user 或 --org 一起使用）").Strings()
	huggingfaceIgnoreSpaces       = huggingfaceScan.Flag("ignore-spaces", "在扫描中忽略的空间。您可以重复此标志。必须使用 HuggingFace 空间的完整名称。例如：'username/space'（仅与 --user 或 --org 一起使用）").Strings()
	huggingfaceIgnoreDatasets     = huggingfaceScan.Flag("ignore-datasets", "在扫描中忽略的数据集。您可以重复此标志。必须使用 HuggingFace 数据集的完整名称。例如：'username/dataset'（仅与 --user 或 --org 一起使用）").Strings()
	huggingfaceSkipAllModels      = huggingfaceScan.Flag("skip-all-models", "跳过所有模型扫描。（仅与 --user 或 --org 一起使用）").Bool()
	huggingfaceSkipAllSpaces      = huggingfaceScan.Flag("skip-all-spaces", "跳过所有空间扫描。（仅与 --user 或 --org 一起使用）").Bool()
	huggingfaceSkipAllDatasets    = huggingfaceScan.Flag("skip-all-datasets", "跳过所有数据集扫描。（仅与 --user 或 --org 一起使用）").Bool()
	huggingfaceIncludeDiscussions = huggingfaceScan.Flag("include-discussions", "在扫描中包含讨论。").Bool()
	huggingfaceIncludePrs         = huggingfaceScan.Flag("include-prs", "在扫描中包含拉取请求（PR）。").Bool()
	
	analyzeCmd = analyzer.Command(cli)
	usingTUI   = false	
)

func init() {
	_, _ = maxprocs.Set()

	for i, arg := range os.Args {
		if strings.HasPrefix(arg, "--") {
			split := strings.SplitN(arg, "=", 2)
			split[0] = strings.ReplaceAll(split[0], "_", "-")
			os.Args[i] = strings.Join(split, "=")
		}
	}

	cli.Version("trufflehog " + version.BuildVersion)

	// Support -h for help
	cli.HelpFlag.Short('h')

	if isatty.IsTerminal(os.Stdout.Fd()) && (len(os.Args) <= 1 || os.Args[1] == analyzeCmd.FullCommand()) {
		args := tui.Run(os.Args[1:])
		if len(args) == 0 {
			os.Exit(0)
		}

		// Overwrite the Args slice so overseer works properly.
		os.Args = os.Args[:1]
		os.Args = append(os.Args, args...)
		usingTUI = true
	}

	cmd = kingpin.MustParse(cli.Parse(os.Args[1:]))

	// Configure logging.
	switch {
	case *trace:
		log.SetLevel(5)
	case *debug:
		log.SetLevel(2)
	default:
		l := int8(*logLevel)
		if l < -1 || l > 5 {
			fmt.Fprintf(os.Stderr, "无效的日志级别: %d\n", *logLevel)
			os.Exit(1)
		}

		if l == -1 {
			// Zap uses "5" as the value for fatal.
			// We need to pass in "-5" because `SetLevel` passes the negation.
			log.SetLevel(-5)
		} else {
			log.SetLevel(l)
		}
	}
}

func main() {
	// setup logger
	logFormat := log.WithConsoleSink
	if *jsonOut {
		logFormat = log.WithJSONSink
	}
	logger, sync := log.New("trufflehog", logFormat(os.Stderr, log.WithGlobalRedaction()))
	// make it the default logger for contexts
	context.SetDefaultLogger(logger)

	if *localDev {
		run(overseer.State{})
		os.Exit(0)
	}

	defer func() { _ = sync() }()
	logFatal := logFatalFunc(logger)

	updateCfg := overseer.Config{
		Program:       run,
		Debug:         *debug,
		RestartSignal: syscall.SIGTERM,
		// TODO: Eventually add a PreUpgrade func for signature check w/ x509 PKCS1v15
		// PreUpgrade: checkUpdateSignature(binaryPath string),
	}

	if !*noUpdate {
		topLevelCmd, _, _ := strings.Cut(cmd, " ")
		updateCfg.Fetcher = updater.Fetcher(topLevelCmd, usingTUI)
	}
	if version.BuildVersion == "dev" {
		updateCfg.Fetcher = nil
	}

	err := overseer.RunErr(updateCfg)
	if err != nil {
		logFatal(err, "trufflehog 更新器发生错误 🐷")
	}
}

// Function to check if the commit is valid
func isValidCommit(commit string) bool {
	cmd := exec.Command("git", "cat-file", "-t", commit)
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	return strings.TrimSpace(string(output)) == "commit"
}

func run(state overseer.State) {

	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)

	go func() {
		if err := cleantemp.CleanTempArtifacts(ctx); err != nil {
			ctx.Logger().Error(err, "错误清理临时工件")
		}
	}()

	logger := ctx.Logger()
	logFatal := logFatalFunc(logger)

	killSignal := make(chan os.Signal, 1)
	signal.Notify(killSignal, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		<-killSignal
		logger.Info("收到信号，正在关闭。")
		cancel(fmt.Errorf("由于信号取消上下文"))
	
		if err := cleantemp.CleanTempArtifacts(ctx); err != nil {
			logger.Error(err, "清理临时工件时出错")
		} else {
			logger.Info("已清理临时工件")
		}
		os.Exit(0)
	}()
	


	logger.V(2).Info(fmt.Sprintf("trufflehog %s", version.BuildVersion))

	if *githubScanToken != "" {
		// NOTE: this kludge is here to do an authenticated shallow commit
		// TODO: refactor to better pass credentials
		os.Setenv("GITHUB_TOKEN", *githubScanToken)
	}

	// When setting a base commit, chunks must be scanned in order.
	if *gitScanSinceCommit != "" {
		*concurrency = 1
		if !isValidCommit(*gitScanSinceCommit) {
			logger.Info("警告:提供的提交哈希似乎无效。")
		}
	}

	if *profile {
		runtime.SetBlockProfileRate(1)
		runtime.SetMutexProfileFraction(-1)
		go func() {
			router := http.NewServeMux()
			router.Handle("/debug/pprof/", http.DefaultServeMux)
			router.Handle("/debug/fgprof", fgprof.Handler())
			logger.Info("正在启动 pprof和fgprof 服务器在 :18066 /debug/pprof and /debug/fgprof")
			if err := http.ListenAndServe(":18066", router); err != nil {
				logger.Error(err, "错误提供pprof 和 fgprof")
			}
		}()
	}

	// Set feature configurations from CLI flags
	if *forceSkipBinaries {
		feature.ForceSkipBinaries.Store(true)
	}

	if *forceSkipArchives {
		feature.ForceSkipArchives.Store(true)
	}

	if *skipAdditionalRefs {
		feature.SkipAdditionalRefs.Store(true)
	}

	if *userAgentSuffix != "" {
		feature.UserAgentSuffix.Store(*userAgentSuffix)
	}

	// OSS Default APK handling on
	feature.EnableAPKHandler.Store(true)

	conf := &config.Config{}
	if *configFilename != "" {
		var err error
		conf, err = config.Read(*configFilename)
		if err != nil {
			logFatal(err, "解析提供的配置文件时出错")
		}
	}

	if *detectorTimeout != 0 {
		logger.Info("设置检测超时", "timeout", detectorTimeout.String())
		engine.SetDetectorTimeout(*detectorTimeout)
		detectors.OverrideDetectorTimeout(*detectorTimeout)
	}
	if *archiveMaxSize != 0 {
		handlers.SetArchiveMaxSize(int(*archiveMaxSize))
	}
	if *archiveMaxDepth != 0 {
		handlers.SetArchiveMaxDepth(*archiveMaxDepth)
	}
	if *archiveTimeout != 0 {
		handlers.SetArchiveMaxTimeout(*archiveTimeout)
	}

	// Set how the engine will print its results.
	var printer engine.Printer
	switch {
	case *jsonLegacy:
		printer = new(output.LegacyJSONPrinter)
	case *jsonOut:
		printer = new(output.JSONPrinter)
	case *gitHubActionsFormat:
		printer = new(output.GitHubActionsPrinter)
	default:
		printer = new(output.PlainPrinter)
	}

	if !*jsonLegacy && !*jsonOut {
		fmt.Fprintf(os.Stderr, "🐷🔑🐷 TruffleHog。挖掘你的秘密. 🐷🔑🐷\n\n")
	}

	// Parse --results flag.
	if *onlyVerified {
		r := "verified"
		results = &r
	}
	parsedResults, err := parseResults(results)
	if err != nil {
		logFatal(err, "配置结果标志失败")
	}

	verificationCacheMetrics := verificationcache.InMemoryMetrics{}

	engConf := engine.Config{
		Concurrency: *concurrency,
		// The engine must always be configured with the list of
		// default detectors, which can be further filtered by the
		// user. The filters are applied by the engine and are only
		// subtractive.
		Detectors:                append(defaults.DefaultDetectors(), conf.Detectors...),
		Verify:                   !*noVerification,
		IncludeDetectors:         *includeDetectors,
		ExcludeDetectors:         *excludeDetectors,
		CustomVerifiersOnly:      *customVerifiersOnly,
		VerifierEndpoints:        *verifiers,
		Dispatcher:               engine.NewPrinterDispatcher(printer),
		FilterUnverified:         *filterUnverified,
		FilterEntropy:            *filterEntropy,
		VerificationOverlap:      *allowVerificationOverlap,
		Results:                  parsedResults,
		PrintAvgDetectorTime:     *printAvgDetectorTime,
		ShouldScanEntireChunk:    *scanEntireChunk,
		VerificationCacheMetrics: &verificationCacheMetrics,
	}

	if !*noVerificationCache {
		engConf.VerificationResultCache = simple.NewCache[detectors.Result]()
	}

	if *compareDetectionStrategies {
		if err := compareScans(ctx, cmd, engConf); err != nil {
			logFatal(err, "错误比较检测策略")
		}
		return
	}

	metrics, err := runSingleScan(ctx, cmd, engConf)
	if err != nil {
		logFatal(err, "运行扫描时出错")
	}

	verificationCacheMetricsSnapshot := struct {
		Hits                    int32
		Misses                  int32
		HitsWasted              int32
		AttemptsSaved           int32
		VerificationTimeSpentMS int64
	}{
		Hits:                    verificationCacheMetrics.ResultCacheHits.Load(),
		Misses:                  verificationCacheMetrics.ResultCacheMisses.Load(),
		HitsWasted:              verificationCacheMetrics.ResultCacheHitsWasted.Load(),
		AttemptsSaved:           verificationCacheMetrics.CredentialVerificationsSaved.Load(),
		VerificationTimeSpentMS: verificationCacheMetrics.FromDataVerifyTimeSpentMS.Load(),
	}

	// Print results.
	logger.Info("finished scanning",
		"chunks", metrics.ChunksScanned,
		"bytes", metrics.BytesScanned,
		"verified_secrets", metrics.VerifiedSecretsFound,
		"unverified_secrets", metrics.UnverifiedSecretsFound,
		"scan_duration", metrics.ScanDuration.String(),
		"trufflehog_version", version.BuildVersion,
		"verification_caching", verificationCacheMetricsSnapshot,
	)

	if metrics.hasFoundResults && *fail {
		logger.V(2).Info("退出代码 183 因为已经存在文件")
		os.Exit(183)
	}
}

func compareScans(ctx context.Context, cmd string, cfg engine.Config) error {
	var (
		entireMetrics    metrics
		maxLengthMetrics metrics
		err              error
	)

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		// Run scan with entire chunk span calculator.
		cfg.ShouldScanEntireChunk = true
		entireMetrics, err = runSingleScan(ctx, cmd, cfg)
		if err != nil {
			ctx.Logger().Error(err, "错误运行扫描，使用整个块跨度计算器")
		}
	}()

	// Run scan with max-length span calculator.
	maxLengthMetrics, err = runSingleScan(ctx, cmd, cfg)
	if err != nil {
		return fmt.Errorf("error running scan with custom span calculator: %v", err)
	}

	wg.Wait()

	return compareMetrics(maxLengthMetrics.Metrics, entireMetrics.Metrics)
}

func compareMetrics(customMetrics, entireMetrics engine.Metrics) error {
	fmt.Printf("Comparison of scan results: \n")
	fmt.Printf("Custom span - Chunks: %d, Bytes: %d, Verified Secrets: %d, Unverified Secrets: %d, Duration: %s\n",
		customMetrics.ChunksScanned, customMetrics.BytesScanned, customMetrics.VerifiedSecretsFound, customMetrics.UnverifiedSecretsFound, customMetrics.ScanDuration.String())
	fmt.Printf("Entire chunk - Chunks: %d, Bytes: %d, Verified Secrets: %d, Unverified Secrets: %d, Duration: %s\n",
		entireMetrics.ChunksScanned, entireMetrics.BytesScanned, entireMetrics.VerifiedSecretsFound, entireMetrics.UnverifiedSecretsFound, entireMetrics.ScanDuration.String())

	// Check for differences in scan metrics.
	if customMetrics.ChunksScanned != entireMetrics.ChunksScanned ||
		customMetrics.BytesScanned != entireMetrics.BytesScanned ||
		customMetrics.VerifiedSecretsFound != entireMetrics.VerifiedSecretsFound {
		return fmt.Errorf("scan metrics do not match")
	}

	return nil
}

type metrics struct {
	engine.Metrics
	hasFoundResults bool
}

func runSingleScan(ctx context.Context, cmd string, cfg engine.Config) (metrics, error) {
	var scanMetrics metrics

	// Setup job report writer if provided
	var jobReportWriter io.WriteCloser
	if *jobReportFile != nil {
		jobReportWriter = *jobReportFile
	}

	handleFinishedMetrics := func(ctx context.Context, finishedMetrics <-chan sources.UnitMetrics, jobReportWriter io.WriteCloser) {
		go func() {
			defer func() {
				jobReportWriter.Close()
				if namer, ok := jobReportWriter.(interface{ Name() string }); ok {
					ctx.Logger().Info("report written", "path", namer.Name())
				} else {
					ctx.Logger().Info("report written")
				}
			}()

			for metrics := range finishedMetrics {
				metrics.Errors = common.ExportErrors(metrics.Errors...)
				details, err := json.Marshal(map[string]any{
					"version": 1,
					"data":    metrics,
				})
				if err != nil {
					ctx.Logger().Error(err, "error marshalling job details")
					continue
				}
				if _, err := jobReportWriter.Write(append(details, '\n')); err != nil {
					ctx.Logger().Error(err, "error writing to file")
				}
			}
		}()
	}

	const defaultOutputBufferSize = 64
	opts := []func(*sources.SourceManager){
		sources.WithConcurrentSources(cfg.Concurrency),
		sources.WithConcurrentUnits(cfg.Concurrency),
		sources.WithSourceUnits(),
		sources.WithBufferedOutput(defaultOutputBufferSize),
	}

	if jobReportWriter != nil {
		unitHook, finishedMetrics := sources.NewUnitHook(ctx)
		opts = append(opts, sources.WithReportHook(unitHook))
		handleFinishedMetrics(ctx, finishedMetrics, jobReportWriter)
	}

	cfg.SourceManager = sources.NewManager(opts...)

	eng, err := engine.NewEngine(ctx, &cfg)
	if err != nil {
		return scanMetrics, fmt.Errorf("error initializing engine: %v", err)
	}
	eng.Start(ctx)

	defer func() {
		// Clean up temporary artifacts.
		if err := cleantemp.CleanTempArtifacts(ctx); err != nil {
			ctx.Logger().Error(err, "error cleaning temp artifacts")
		}
	}()

	var ref sources.JobProgressRef
	switch cmd {
	case gitScan.FullCommand():
		gitCfg := sources.GitConfig{
			URI:              *gitScanURI,
			IncludePathsFile: *gitScanIncludePaths,
			ExcludePathsFile: *gitScanExcludePaths,
			HeadRef:          *gitScanBranch,
			BaseRef:          *gitScanSinceCommit,
			MaxDepth:         *gitScanMaxDepth,
			Bare:             *gitScanBare,
			ExcludeGlobs:     *gitScanExcludeGlobs,
		}
		if ref, err = eng.ScanGit(ctx, gitCfg); err != nil {
			return scanMetrics, fmt.Errorf("failed to scan Git: %v", err)
		}
	case githubScan.FullCommand():
		filter, err := common.FilterFromFiles(*githubScanIncludePaths, *githubScanExcludePaths)
		if err != nil {
			return scanMetrics, fmt.Errorf("could not create filter: %v", err)
		}
		if len(*githubScanOrgs) == 0 && len(*githubScanRepos) == 0 {
			return scanMetrics, fmt.Errorf("invalid config: you must specify at least one organization or repository")
		}

		cfg := sources.GithubConfig{
			Endpoint:                   *githubScanEndpoint,
			Token:                      *githubScanToken,
			IncludeForks:               *githubIncludeForks,
			IncludeMembers:             *githubIncludeMembers,
			IncludeWikis:               *githubIncludeWikis,
			Concurrency:                *concurrency,
			ExcludeRepos:               *githubExcludeRepos,
			IncludeRepos:               *githubIncludeRepos,
			Repos:                      *githubScanRepos,
			Orgs:                       *githubScanOrgs,
			IncludeIssueComments:       *githubScanIssueComments,
			IncludePullRequestComments: *githubScanPRComments,
			IncludeGistComments:        *githubScanGistComments,
			CommentsTimeframeDays:      *githubCommentsTimeframeDays,
			Filter:                     filter,
		}
		if ref, err = eng.ScanGitHub(ctx, cfg); err != nil {
			return scanMetrics, fmt.Errorf("failed to scan Github: %v", err)
		}
	case githubExperimentalScan.FullCommand():
		cfg := sources.GitHubExperimentalConfig{
			Token:              *githubExperimentalToken,
			Repository:         *githubExperimentalRepo,
			ObjectDiscovery:    *githubExperimentalObjectDiscovery,
			CollisionThreshold: *githubExperimentalCollisionThreshold,
			DeleteCachedData:   *githubExperimentalDeleteCache,
		}
		if ref, err = eng.ScanGitHubExperimental(ctx, cfg); err != nil {
			return scanMetrics, fmt.Errorf("failed to scan using Github Experimental: %v", err)
		}
	case gitlabScan.FullCommand():
		filter, err := common.FilterFromFiles(*gitlabScanIncludePaths, *gitlabScanExcludePaths)
		if err != nil {
			return scanMetrics, fmt.Errorf("could not create filter: %v", err)
		}

		cfg := sources.GitlabConfig{
			Endpoint:     *gitlabScanEndpoint,
			Token:        *gitlabScanToken,
			Repos:        *gitlabScanRepos,
			IncludeRepos: *gitlabScanIncludeRepos,
			ExcludeRepos: *gitlabScanExcludeRepos,
			Filter:       filter,
		}
		if ref, err = eng.ScanGitLab(ctx, cfg); err != nil {
			return scanMetrics, fmt.Errorf("failed to scan GitLab: %v", err)
		}
	case filesystemScan.FullCommand():
		if len(*filesystemDirectories) > 0 {
			ctx.Logger().Info("--directory flag is deprecated, please pass directories as arguments")
		}
		paths := make([]string, 0, len(*filesystemPaths)+len(*filesystemDirectories))
		paths = append(paths, *filesystemPaths...)
		paths = append(paths, *filesystemDirectories...)
		cfg := sources.FilesystemConfig{
			Paths:            paths,
			IncludePathsFile: *filesystemScanIncludePaths,
			ExcludePathsFile: *filesystemScanExcludePaths,
		}
		if ref, err = eng.ScanFileSystem(ctx, cfg); err != nil {
			return scanMetrics, fmt.Errorf("failed to scan filesystem: %v", err)
		}
	case s3Scan.FullCommand():
		cfg := sources.S3Config{
			Key:           *s3ScanKey,
			Secret:        *s3ScanSecret,
			SessionToken:  *s3ScanSessionToken,
			Buckets:       *s3ScanBuckets,
			IgnoreBuckets: *s3ScanIgnoreBuckets,
			Roles:         *s3ScanRoleArns,
			CloudCred:     *s3ScanCloudEnv,
			MaxObjectSize: int64(*s3ScanMaxObjectSize),
		}
		if ref, err = eng.ScanS3(ctx, cfg); err != nil {
			return scanMetrics, fmt.Errorf("failed to scan S3: %v", err)
		}
	case syslogScan.FullCommand():
		cfg := sources.SyslogConfig{
			Address:     *syslogAddress,
			Format:      *syslogFormat,
			Protocol:    *syslogProtocol,
			CertPath:    *syslogTLSCert,
			KeyPath:     *syslogTLSKey,
			Concurrency: *concurrency,
		}
		if ref, err = eng.ScanSyslog(ctx, cfg); err != nil {
			return scanMetrics, fmt.Errorf("failed to scan syslog: %v", err)
		}
	case circleCiScan.FullCommand():
		if ref, err = eng.ScanCircleCI(ctx, *circleCiScanToken); err != nil {
			return scanMetrics, fmt.Errorf("failed to scan CircleCI: %v", err)
		}
	case travisCiScan.FullCommand():
		if ref, err = eng.ScanTravisCI(ctx, *travisCiScanToken); err != nil {
			return scanMetrics, fmt.Errorf("failed to scan TravisCI: %v", err)
		}
	case gcsScan.FullCommand():
		cfg := sources.GCSConfig{
			ProjectID:      *gcsProjectID,
			CloudCred:      *gcsCloudEnv,
			ServiceAccount: *gcsServiceAccount,
			WithoutAuth:    *gcsWithoutAuth,
			ApiKey:         *gcsAPIKey,
			IncludeBuckets: commaSeparatedToSlice(*gcsIncludeBuckets),
			ExcludeBuckets: commaSeparatedToSlice(*gcsExcludeBuckets),
			IncludeObjects: commaSeparatedToSlice(*gcsIncludeObjects),
			ExcludeObjects: commaSeparatedToSlice(*gcsExcludeObjects),
			Concurrency:    *concurrency,
			MaxObjectSize:  int64(*gcsMaxObjectSize),
		}
		if ref, err = eng.ScanGCS(ctx, cfg); err != nil {
			return scanMetrics, fmt.Errorf("failed to scan GCS: %v", err)
		}
	case dockerScan.FullCommand():
		cfg := sources.DockerConfig{
			BearerToken:       *dockerScanToken,
			Images:            *dockerScanImages,
			UseDockerKeychain: *dockerScanToken == "",
		}
		if ref, err = eng.ScanDocker(ctx, cfg); err != nil {
			return scanMetrics, fmt.Errorf("failed to scan Docker: %v", err)
		}
	case postmanScan.FullCommand():
		// handle deprecated flag
		workspaceIDs := make([]string, 0, len(*postmanWorkspaceIDs)+len(*postmanWorkspaces))
		workspaceIDs = append(workspaceIDs, *postmanWorkspaceIDs...)
		workspaceIDs = append(workspaceIDs, *postmanWorkspaces...)

		// handle deprecated flag
		collectionIDs := make([]string, 0, len(*postmanCollectionIDs)+len(*postmanCollections))
		collectionIDs = append(collectionIDs, *postmanCollectionIDs...)
		collectionIDs = append(collectionIDs, *postmanCollections...)

		// handle deprecated flag
		includeCollectionIDs := make([]string, 0, len(*postmanIncludeCollectionIDs)+len(*postmanIncludeCollections))
		includeCollectionIDs = append(includeCollectionIDs, *postmanIncludeCollectionIDs...)
		includeCollectionIDs = append(includeCollectionIDs, *postmanIncludeCollections...)

		// handle deprecated flag
		excludeCollectionIDs := make([]string, 0, len(*postmanExcludeCollectionIDs)+len(*postmanExcludeCollections))
		excludeCollectionIDs = append(excludeCollectionIDs, *postmanExcludeCollectionIDs...)
		excludeCollectionIDs = append(excludeCollectionIDs, *postmanExcludeCollections...)

		cfg := sources.PostmanConfig{
			Token:               *postmanToken,
			Workspaces:          workspaceIDs,
			Collections:         collectionIDs,
			Environments:        *postmanEnvironments,
			IncludeCollections:  includeCollectionIDs,
			IncludeEnvironments: *postmanIncludeEnvironments,
			ExcludeCollections:  excludeCollectionIDs,
			ExcludeEnvironments: *postmanExcludeEnvironments,
			CollectionPaths:     *postmanCollectionPaths,
			WorkspacePaths:      *postmanWorkspacePaths,
			EnvironmentPaths:    *postmanEnvironmentPaths,
		}
		if ref, err = eng.ScanPostman(ctx, cfg); err != nil {
			return scanMetrics, fmt.Errorf("failed to scan Postman: %v", err)
		}
	case elasticsearchScan.FullCommand():
		cfg := sources.ElasticsearchConfig{
			Nodes:          *elasticsearchNodes,
			Username:       *elasticsearchUsername,
			Password:       *elasticsearchPassword,
			CloudID:        *elasticsearchCloudId,
			APIKey:         *elasticsearchAPIKey,
			ServiceToken:   *elasticsearchServiceToken,
			IndexPattern:   *elasticsearchIndexPattern,
			QueryJSON:      *elasticsearchQueryJSON,
			SinceTimestamp: *elasticsearchSinceTimestamp,
			BestEffortScan: *elasticsearchBestEffortScan,
		}
		if ref, err = eng.ScanElasticsearch(ctx, cfg); err != nil {
			return scanMetrics, fmt.Errorf("failed to scan Elasticsearch: %v", err)
		}
	case jenkinsScan.FullCommand():
		cfg := engine.JenkinsConfig{
			Endpoint:              *jenkinsURL,
			InsecureSkipVerifyTLS: *jenkinsInsecureSkipVerifyTLS,
			Username:              *jenkinsUsername,
			Password:              *jenkinsPassword,
		}
		if ref, err = eng.ScanJenkins(ctx, cfg); err != nil {
			return scanMetrics, fmt.Errorf("failed to scan Jenkins: %v", err)
		}
	case huggingfaceScan.FullCommand():
		if *huggingfaceEndpoint != "" {
			*huggingfaceEndpoint = strings.TrimRight(*huggingfaceEndpoint, "/")
		}

		if len(*huggingfaceModels) == 0 && len(*huggingfaceSpaces) == 0 && len(*huggingfaceDatasets) == 0 && len(*huggingfaceOrgs) == 0 && len(*huggingfaceUsers) == 0 {
			return scanMetrics, fmt.Errorf("invalid config: you must specify at least one organization, user, model, space or dataset")
		}

		cfg := engine.HuggingfaceConfig{
			Endpoint:           *huggingfaceEndpoint,
			Models:             *huggingfaceModels,
			Spaces:             *huggingfaceSpaces,
			Datasets:           *huggingfaceDatasets,
			Organizations:      *huggingfaceOrgs,
			Users:              *huggingfaceUsers,
			Token:              *huggingfaceToken,
			IncludeModels:      *huggingfaceIncludeModels,
			IncludeSpaces:      *huggingfaceIncludeSpaces,
			IncludeDatasets:    *huggingfaceIncludeDatasets,
			IgnoreModels:       *huggingfaceIgnoreModels,
			IgnoreSpaces:       *huggingfaceIgnoreSpaces,
			IgnoreDatasets:     *huggingfaceIgnoreDatasets,
			SkipAllModels:      *huggingfaceSkipAllModels,
			SkipAllSpaces:      *huggingfaceSkipAllSpaces,
			SkipAllDatasets:    *huggingfaceSkipAllDatasets,
			IncludeDiscussions: *huggingfaceIncludeDiscussions,
			IncludePrs:         *huggingfaceIncludePrs,
			Concurrency:        *concurrency,
		}
		if ref, err = eng.ScanHuggingface(ctx, cfg); err != nil {
			return scanMetrics, fmt.Errorf("failed to scan HuggingFace: %v", err)
		}
	default:
		return scanMetrics, fmt.Errorf("invalid command: %s", cmd)
	}

	// Wait for all workers to finish.
	if err = eng.Finish(ctx); err != nil {
		return scanMetrics, fmt.Errorf("engine failed to finish execution: %v", err)
	}

	// Print any errors reported during the scan.
	if errs := ref.Snapshot().Errors; len(errs) > 0 {
		errMsgs := make([]string, len(errs))
		for i := 0; i < len(errs); i++ {
			errMsgs[i] = errs[i].Error()
		}
		ctx.Logger().Error(nil, "encountered errors during scan", "errors", errMsgs)
	}

	if *printAvgDetectorTime {
		printAverageDetectorTime(eng)
	}

	return metrics{Metrics: eng.GetMetrics(), hasFoundResults: eng.HasFoundResults()}, nil
}

// parseResults ensures that users provide valid CSV input to `--results`.
//
// This is a work-around to kingpin not supporting CSVs.
// See: https://github.com/trufflesecurity/trufflehog/pull/2372#issuecomment-1983868917
func parseResults(input *string) (map[string]struct{}, error) {
	if *input == "" {
		return nil, nil
	}

	var (
		values  = strings.Split(strings.ToLower(*input), ",")
		results = make(map[string]struct{}, 3)
	)
	for _, value := range values {
		switch value {
		case "verified", "unknown", "unverified", "filtered_unverified":
			results[value] = struct{}{}
		default:
			return nil, fmt.Errorf("invalid value '%s', valid values are 'verified,unknown,unverified,filtered_unverified'", value)
		}
	}
	return results, nil
}

// logFatalFunc returns a log.Fatal style function. Calling the returned
// function will terminate the program without cleanup.
func logFatalFunc(logger logr.Logger) func(error, string, ...any) {
	return func(err error, message string, keyAndVals ...any) {
		logger.Error(err, message, keyAndVals...)
		if err != nil {
			os.Exit(1)
			return
		}
		os.Exit(0)
	}
}

func commaSeparatedToSlice(s []string) []string {
	var result []string
	for _, items := range s {
		for _, item := range strings.Split(items, ",") {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			result = append(result, item)
		}
	}
	return result
}

func printAverageDetectorTime(e *engine.Engine) {
	fmt.Fprintln(
		os.Stderr,
		"Average detector time is the measurement of average time spent on each detector when results are returned.",
	)
	for detectorName, duration := range e.GetDetectorsMetrics() {
		fmt.Fprintf(os.Stderr, "%s: %s\n", detectorName, duration)
	}
}
