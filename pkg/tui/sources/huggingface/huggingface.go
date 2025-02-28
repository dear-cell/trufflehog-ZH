package huggingface

import (
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/textinputs"
)

type huggingFaceCmdModel struct {
	textinputs.Model
}

func GetNote() string {
	return "请输入你希望扫描的组织、用户、模型、空间或数据集。"
}

func GetFields() huggingFaceCmdModel {
	org := textinputs.InputConfig{
		Label:    "组织",
		Key:      "org",
		Required: false,
		Help:     "Hugging Face 组织名称。将扫描属于该组织的所有模型、数据集和空间。",
	}
	user := textinputs.InputConfig{
		Label:    "用户名",
		Key:      "user",
		Required: false,
		Help:     "Hugging Face 用户名。将扫描属于该用户的所有模型、数据集和空间。",
	}
	model := textinputs.InputConfig{
		Label:    "模型",
		Key:      "model",
		Required: false,
		Help:     "Hugging Face 模型。例如：org/model_name 或 user/model_name",
	}
	space := textinputs.InputConfig{
		Label:    "空间",
		Key:      "space",
		Required: false,
		Help:     "Hugging Face 空间。例如：org/space_name 或 user/space_name。",
	}
	dataset := textinputs.InputConfig{
		Label:    "数据集",
		Key:      "dataset",
		Required: false,
		Help:     "Hugging Face 数据集。例如：org/dataset_name 或 user/dataset_name。",
	}

	return huggingFaceCmdModel{textinputs.New([]textinputs.InputConfig{org, user, model, space, dataset})}
}

func (m huggingFaceCmdModel) Cmd() string {
	var command []string
	command = append(command, "trufflehog", "huggingface")

	inputs := m.GetInputs()
	keys := []string{"org", "user", "model", "space", "dataset"}

	for _, key := range keys {
		val, ok := inputs[key]
		if !ok || val.Value == "" {
			continue
		}

		command = append(command, "--"+key+"="+val.Value)
	}

	return strings.Join(command, " ")
}

func (m huggingFaceCmdModel) Summary() string {
	inputs := m.GetInputs()
	labels := m.GetLabels()
	keys := []string{"org", "user", "model", "space", "dataset"}
	return common.SummarizeSource(keys, inputs, labels)
}
