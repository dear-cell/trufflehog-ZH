package elasticsearch

import (
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/textinputs"
)

type elasticSearchCmdModel struct {
	textinputs.Model
}

func GetNote() string {
	return "要连接到本地集群，请提供节点 IP 和（用户名 和 密码）或服务令牌。⭐\n⭐ 要连接到云集群，请提供云 ID 和 API 密钥。"
}

func GetFields() elasticSearchCmdModel {
	return elasticSearchCmdModel{textinputs.New([]textinputs.InputConfig{
		{
			Label:    "Elastic 节点",
			Key:      "nodes",
			Required: false,
			Help:     "Elastic 节点 IP - 用于扫描本地集群。如果有多个节点，请用空格分隔。",
		},
		{
			Label:    "用户名",
			Key:      "username",
			Required: false,
			Help:     "Elasticsearch 用户名。与密码配对，用于扫描本地集群。",
		},
		{
			Label:    "密码",
			Key:      "password",
			Required: false,
			Help:     "Elasticsearch 密码。与用户名配对，用于扫描本地集群。",
		},
		{
			Label:    "服务令牌",
			Key:      "serviceToken",
			Required: false,
			Help:     "Elastic 服务令牌，用于扫描本地集群。",
		},
		{
			Label:    "云 ID",
			Key:      "cloudId",
			Required: false,
			Help:     "Elastic 云 ID。与 API 密钥配对，用于扫描云集群。",
		},
		{
			Label:    "API 密钥",
			Key:      "apiKey",
			Required: false,
			Help:     "Elastic API 密钥。与云 ID 配对，用于扫描云集群。",
		}})}
}


func findFirstNonEmptyKey(inputs map[string]textinputs.Input, keys []string) string {
	for _, key := range keys {
		if val, ok := inputs[key]; ok && val.Value != "" {
			return key
		}
	}
	return ""
}

func getConnectionKeys(inputs map[string]textinputs.Input) []string {
	keys := []string{"username", "password", "serviceToken", "cloudId", "apiKey"}
	key := findFirstNonEmptyKey(inputs, keys)

	keyMap := map[string][]string{
		"username":     {"username", "password", "nodes"},
		"password":     {"username", "password", "nodes"},
		"serviceToken": {"serviceToken", "nodes"},
		"cloudId":      {"cloudId", "apiKey"},
		"apiKey":       {"cloudId", "apiKey"},
	}

	if val, ok := keyMap[key]; ok {
		return val
	}

	return nil
}

func (m elasticSearchCmdModel) Cmd() string {
	var command []string
	command = append(command, "trufflehog", "elasticsearch")
	inputs := m.GetInputs()

	for _, key := range getConnectionKeys(inputs) {
		val, ok := inputs[key]
		if !ok || val.Value == "" {
			continue
		}

		if key == "nodes" {
			nodes := strings.Fields(val.Value)
			for _, node := range nodes {
				command = append(command, "--nodes="+node)
			}
		} else {
			command = append(command, "--"+key+"="+val.Value)
		}
	}

	return strings.Join(command, " ")
}

func (m elasticSearchCmdModel) Summary() string {
	inputs := m.GetInputs()
	labels := m.GetLabels()

	summaryKeys := getConnectionKeys(inputs)
	return common.SummarizeSource(summaryKeys, inputs, labels)
}
