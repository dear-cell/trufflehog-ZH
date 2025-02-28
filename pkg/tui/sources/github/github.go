package github

import (
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/textinputs"
)

type githubCmdModel struct {
	textinputs.Model
}

func GetNote() string {
	return "请输入组织或仓库."
}

func GetFields() githubCmdModel {
	org := textinputs.InputConfig{
		Label:       "组织",
		Key:         "org",
		Required:    true,
		Help:        "要扫描的 GitHub 组织。",
		Placeholder: "trufflesecurity",
	}

	repo := textinputs.InputConfig{
		Label:       "仓库",
		Key:         "repo",
		Required:    true,
		Help:        "要扫描的 GitHub 仓库。",
		Placeholder: "https://github.com/trufflesecurity/test_keys",
	}

	return githubCmdModel{textinputs.New([]textinputs.InputConfig{org, repo})}
}

// Handle default values since GitHub flags are OR operations
func (m githubCmdModel) GetSpecialInputs() map[string]textinputs.Input {
	inputs := m.GetInputs()
	if inputs["org"].IsDefault != inputs["repo"].IsDefault {
		if inputs["org"].IsDefault {
			delete(inputs, "org")
		}
		if inputs["repo"].IsDefault {
			delete(inputs, "repo")
		}
	}

	return inputs
}

func (m githubCmdModel) Cmd() string {
	var command []string
	command = append(command, "trufflehog", "github")
	inputs := m.GetSpecialInputs()

	if inputs["org"].Value != "" {
		command = append(command, "--org="+inputs["org"].Value)
	}

	if inputs["repo"].Value != "" {
		command = append(command, "--repo="+inputs["repo"].Value)
	}

	return strings.Join(command, " ")
}

func (m githubCmdModel) Summary() string {
	inputs := m.GetSpecialInputs()
	labels := m.GetLabels()

	keys := []string{"org", "repo"}
	return common.SummarizeSource(keys, inputs, labels)
}
