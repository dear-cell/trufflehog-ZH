package filesystem

import (
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/textinputs"
)

type fsModel struct {
	textinputs.Model
}


func GetFields() fsModel {
	path := textinputs.InputConfig{
		Label:       "路径",
		Key:         "path",
		Required:    true,
		Help:        "要扫描的文件和目录。如果有多个，用空格分隔。",
		Placeholder: "path/to/file.txt path/to/another/dir",
	}

	return fsModel{textinputs.New([]textinputs.InputConfig{path})}
}

func (m fsModel) Cmd() string {
	var command []string
	command = append(command, "trufflehog", "filesystem")

	inputs := m.GetInputs()
	command = append(command, inputs["path"].Value)

	return strings.Join(command, " ")
}

func (m fsModel) Summary() string {
	inputs := m.GetInputs()
	labels := m.GetLabels()

	keys := []string{"path"}
	return common.SummarizeSource(keys, inputs, labels)
}
