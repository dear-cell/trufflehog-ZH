package source_configure

import (
	"runtime"
	"strconv"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/textinputs"
)

type truffleCmdModel struct {
	textinputs.Model
}

func GetTrufflehogConfiguration() truffleCmdModel {
	verification := textinputs.InputConfig{
		Label:       "跳过验证",
		Key:         "no-verification",
		Required:    false,
		Help:        "检查疑似密钥是否真实",
		Placeholder: "false",
	}

	verifiedResults := textinputs.InputConfig{
		Label:       "仅验证结果",
		Key:         "only-verified",
		Required:    false,
		Help:        "仅返回验证过的结果",
		Placeholder: "false",
	}

	jsonOutput := textinputs.InputConfig{
		Label:       "JSON 输出",
		Key:         "json",
		Required:    false,
		Help:        "将结果输出为 JSON 格式",
		Placeholder: "false",
	}

	excludeDetectors := textinputs.InputConfig{
		Label:       "排除检测器",
		Key:         "exclude_detectors",
		Required:    false,
		Help:        "以逗号分隔的检测器类型列表，排除这些检测器。可以使用 protobuf 名称或 ID，支持范围。这里定义的 ID 优先于包含列表。",
		Placeholder: "",
	}

	concurrency := textinputs.InputConfig{
		Label:       "并发数",
		Key:         "concurrency",
		Required:    false,
		Help:        "并发工作线程数。",
		Placeholder: strconv.Itoa(runtime.NumCPU()),
	}

	return truffleCmdModel{textinputs.New([]textinputs.InputConfig{jsonOutput, verification, verifiedResults, excludeDetectors, concurrency}).SetSkip(true)}
}

func (m truffleCmdModel) Cmd() string {
	var command []string
	inputs := m.GetInputs()

	if isTrue(inputs["json"].Value) {
		command = append(command, "--json")
	}

	if isTrue(inputs["no-verification"].Value) {
		command = append(command, "--no-verification")
	}

	if isTrue(inputs["only-verified"].Value) {
		command = append(command, "--results=verified")
	}

	if inputs["exclude_detectors"].Value != "" {
		cmd := "--exclude-detectors=" + strings.ReplaceAll(inputs["exclude_detectors"].Value, " ", "")
		command = append(command, cmd)
	}

	if inputs["concurrency"].Value != "" {
		command = append(command, "--concurrency="+inputs["concurrency"].Value)
	}

	return strings.Join(command, " ")
}

func (m truffleCmdModel) Summary() string {
	summary := strings.Builder{}
	keys := []string{"no-verification", "only-verified", "json", "exclude_detectors", "concurrency"}

	inputs := m.GetInputs()
	labels := m.GetLabels()
	for _, key := range keys {
		if inputs[key].Value != "" {
			summary.WriteString("\t" + labels[key] + ": " + inputs[key].Value + "\n")
		}
	}

	if summary.Len() == 0 {
		summary.WriteString("\t使用默认设置运行\n")

	}

	summary.WriteString("\n")
	return summary.String()
}

func isTrue(val string) bool {
	value := strings.ToLower(val)
	isTrue, _ := strconv.ParseBool(value)

	if isTrue || value == "yes" || value == "y" {
		return true
	}
	return false
}
