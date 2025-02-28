package s3

import (
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/textinputs"
)

type s3CmdModel struct {
	textinputs.Model
}
func GetFields() s3CmdModel {
	bucket := textinputs.InputConfig{
		Label:       "S3 桶名称",
		Key:         "buckets",
		Required:    true,
		Placeholder: "truffletestbucket",
		Help:        "要扫描的桶。如果有多个，用空格分隔。",
	}

	return s3CmdModel{textinputs.New([]textinputs.InputConfig{bucket})}
}

func (m s3CmdModel) Cmd() string {
	var command []string
	command = append(command, "trufflehog", "s3")

	inputs := m.GetInputs()
	vals := inputs["buckets"].Value
	if vals != "" {
		buckets := strings.Fields(vals)
		for _, bucket := range buckets {
			command = append(command, "--bucket="+bucket)
		}
	}

	return strings.Join(command, " ")
}

func (m s3CmdModel) Summary() string {
	inputs := m.GetInputs()
	labels := m.GetLabels()

	keys := []string{"buckets"}
	return common.SummarizeSource(keys, inputs, labels)
}
