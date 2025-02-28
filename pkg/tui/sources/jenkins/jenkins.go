package jenkins

import (
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/textinputs"
)

type jenkinsCmdModel struct {
	textinputs.Model
}

func GetNote() string {
	return "如果未提供用户名和密码，TruffleHog 将尝试进行未经认证的 Jenkins 扫描。"
}

func GetFields() jenkinsCmdModel {
	return jenkinsCmdModel{textinputs.New([]textinputs.InputConfig{
		{
			Label:       "端点 URL",
			Key:         "url",
			Required:    true,
			Help:        "Jenkins 服务器的 URL。",
			Placeholder: "https://jenkins.example.com",
		},
		{
			Label:    "用户名",
			Key:      "username",
			Required: false,
			Help:     "用于认证扫描 - 与密码配对使用。",
		},
		{
			Label:    "密码",
			Key:      "password",
			Required: false,
			Help:     "用于认证扫描 - 与用户名配对使用。",
		}})}
}


func checkIsAuthenticated(inputs map[string]textinputs.Input) bool {
	username := inputs["username"].Value
	password := inputs["password"].Value

	return username != "" && password != ""
}

func (m jenkinsCmdModel) Cmd() string {
	var command []string
	command = append(command, "trufflehog", "jenkins")
	inputs := m.GetInputs()

	keys := []string{"url"}
	if checkIsAuthenticated(inputs) {
		keys = append(keys, "username", "password")
	}

	for _, key := range keys {
		val, ok := inputs[key]
		if !ok || val.Value == "" {
			continue
		}
		command = append(command, "--"+key+"="+val.Value)
	}

	return strings.Join(command, " ")
}

func (m jenkinsCmdModel) Summary() string {
	inputs := m.GetInputs()
	labels := m.GetLabels()

	summaryKeys := []string{"url"}
	if checkIsAuthenticated(inputs) {
		summaryKeys = append(summaryKeys, "username", "password")
	}

	return common.SummarizeSource(summaryKeys, inputs, labels)
}
