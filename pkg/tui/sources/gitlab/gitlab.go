package gitlab

import (
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/textinputs"
)

type gitlabCmdModel struct {
	textinputs.Model
}

func GetFields() gitlabCmdModel {
	token := textinputs.InputConfig{
		Label:       "GitLab 令牌",
		Key:         "token",
		Required:    true,
		Help:        "具有读取权限的个人访问令牌",
		Placeholder: "glpat-",
	}

	return gitlabCmdModel{textinputs.New([]textinputs.InputConfig{token})}
}

func (m gitlabCmdModel) Cmd() string {
	var command []string
	command = append(command, "trufflehog", "gitlab")

	inputs := m.GetInputs()

	command = append(command, "--token="+inputs["token"].Value)

	return strings.Join(command, " ")
}

func (m gitlabCmdModel) Summary() string {
	inputs := m.GetInputs()
	labels := m.GetLabels()

	keys := []string{"token"}
	return common.SummarizeSource(keys, inputs, labels)
}
