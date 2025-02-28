package source_select

import (
	"time"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/selector"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/styles"
)

// TODO: Review light theme styling
var (
	titleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFDF5")).
			Background(lipgloss.Color(styles.Colors["bronze"])).
			Padding(0, 1)

	// FIXME: Hon pls help
	errorStatusMessageStyle = lipgloss.NewStyle().
				Foreground(lipgloss.AdaptiveColor{Dark: "#ff0000"}).
				Render

	selectedSourceItemStyle = lipgloss.NewStyle().
				Border(lipgloss.NormalBorder(), false, false, false, true).
				BorderForeground(lipgloss.AdaptiveColor{Dark: styles.Colors["sprout"], Light: styles.Colors["bronze"]}).
				Foreground(lipgloss.AdaptiveColor{Dark: styles.Colors["sprout"], Light: styles.Colors["fern"]}).
				Padding(0, 0, 0, 1)

	selectedDescription = selectedSourceItemStyle.Copy().
				Foreground(lipgloss.AdaptiveColor{Dark: styles.Colors["sprout"], Light: styles.Colors["sprout"]})
)

type listKeyMap struct {
	toggleHelpMenu key.Binding
}

type (
	SourceSelect struct {
		common.Common
		sourcesList  list.Model
		keys         *listKeyMap
		delegateKeys *delegateKeyMap
		selector     *selector.Selector
	}
)

func New(c common.Common) *SourceSelect {
	var (
		delegateKeys = newDelegateKeyMap()
		listKeys     = &listKeyMap{
			toggleHelpMenu: key.NewBinding(
				key.WithKeys("H"),
				key.WithHelp("H", "toggle help"),
			),
		}
	)

	// Make list of SourceItems.
	SourceItems := []list.Item{
		// 开源资源
OssItem("Git", "扫描 Git 仓库。"),
OssItem("GitHub", "扫描 GitHub 仓库和/或组织。"),
OssItem("Filesystem", "通过选择要扫描的目录来扫描您的文件系统。"),
OssItem("Hugging Face", "扫描 Hugging Face，一个 AI/ML 社区。"),
OssItem("Jenkins", "扫描 Jenkins，一个 CI/CD 平台。（最近从企业版开源！）"),
OssItem("Elasticsearch", "扫描您的 Elasticsearch 集群或 Elastic Cloud 实例。"),
OssItem("Postman", "扫描 Postman 的集合、工作区或环境，Postman 是一个 API 平台。"),
OssItem("GitLab", "扫描 GitLab 仓库。"),
OssItem("AWS S3", "扫描 Amazon S3 存储桶。"),
OssItem("CircleCI", "扫描 CircleCI，一个 CI/CD 平台。"),
OssItem("Syslog", "扫描 syslog，事件数据日志。"),
OssItem("Docker", "扫描 Docker 实例，一个容器化应用程序。"),
OssItem("GCS (Google Cloud Storage)", "扫描 Google Cloud Storage 实例。"),
// 企业资源
EnterpriseItem("Artifactory", "扫描 JFrog Artifactory 包。"),
EnterpriseItem("Azure Repos", "扫描 Microsoft Azure 仓库。"),
EnterpriseItem("BitBucket", "扫描 Atlassian 的 Git 基于的源代码托管服务。"),
EnterpriseItem("Buildkite", "扫描 Buildkite，一个 CI/CD 平台。"),
EnterpriseItem("Confluence", "扫描 Atlassian 的基于 Web 的 wiki 和知识库。"),
EnterpriseItem("Gerrit", "扫描 Gerrit，一个代码协作工具。"),
EnterpriseItem("Jira", "扫描 Atlassian 的问题和项目跟踪软件。"),
EnterpriseItem("Slack", "扫描 Slack，一个消息和通讯平台。"),
EnterpriseItem("Microsoft Teams", "扫描 Microsoft Teams，一个消息和通讯平台。"),
EnterpriseItem("Microsoft Sharepoint", "扫描 Microsoft Sharepoint，一个协作和文档管理平台。"),
EnterpriseItem("Google Drive", "扫描 Google Drive，一个基于云的存储和文件同步服务。"),
	}

	// Setup list
	delegate := newSourceItemDelegate(delegateKeys)
	delegate.Styles.SelectedTitle = selectedSourceItemStyle
	delegate.Styles.SelectedDesc = selectedDescription

	sourcesList := list.New(SourceItems, delegate, 0, 0)
	sourcesList.Title = "Sources"
	sourcesList.Styles.Title = titleStyle
	sourcesList.StatusMessageLifetime = 10 * time.Second

	sourcesList.AdditionalFullHelpKeys = func() []key.Binding {
		return []key.Binding{
			listKeys.toggleHelpMenu,
		}
	}

	sourcesList.SetShowStatusBar(false)
	sel := selector.New(c, []selector.IdentifiableItem{}, delegate)

	return &SourceSelect{
		Common:       c,
		sourcesList:  sourcesList,
		keys:         listKeys,
		delegateKeys: delegateKeys,
		selector:     sel,
	}
}

func (m *SourceSelect) Init() tea.Cmd {
	return nil
}

func (m *SourceSelect) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		h, v := styles.AppStyle.GetFrameSize()
		m.sourcesList.SetSize(msg.Width-h, msg.Height-v)

	case tea.KeyMsg:
		// Don't match any of the keys below if we're actively filtering.
		if m.sourcesList.FilterState() == list.Filtering {
			break
		}

		switch {
		case key.Matches(msg, m.keys.toggleHelpMenu):
			m.sourcesList.SetShowHelp(!m.sourcesList.ShowHelp())
			return m, nil
		}
	}

	// This will also call our delegate's update function.
	newListModel, cmd := m.sourcesList.Update(msg)
	m.sourcesList = newListModel
	cmds = append(cmds, cmd)

	if m.selector != nil {
		sel, cmd := m.selector.Update(msg)
		m.selector = sel.(*selector.Selector)
		cmds = append(cmds, cmd)
	}

	return m, tea.Batch(cmds...)
}

func (m *SourceSelect) View() string {
	return styles.AppStyle.Render(m.sourcesList.View())
}

func (m *SourceSelect) ShortHelp() []key.Binding {
	// TODO: actually return something
	return nil
}

func (m *SourceSelect) FullHelp() [][]key.Binding {
	// TODO: actually return something
	return nil
}

func newSourceItemDelegate(keys *delegateKeyMap) list.DefaultDelegate {
	d := list.NewDefaultDelegate()

	d.UpdateFunc = func(msg tea.Msg, m *list.Model) tea.Cmd {
		selectedSourceItem, ok := m.SelectedItem().(SourceItem)
		if !ok {
			return nil
		}

		if msg, ok := msg.(tea.KeyMsg); ok && key.Matches(msg, keys.choose) {
			if selectedSourceItem.enterprise {
				return m.NewStatusMessage(errorStatusMessageStyle(
					"这是一个仅限企业的来源。欲了解更多，请访问 trufflesecurity.com",
				))
			}

			return func() tea.Msg {
				return selector.SelectMsg{IdentifiableItem: selectedSourceItem}
			}
		}
		return nil
	}

	help := []key.Binding{keys.choose}
	d.ShortHelpFunc = func() []key.Binding { return help }
	d.FullHelpFunc = func() [][]key.Binding { return [][]key.Binding{help} }

	return d
}

type delegateKeyMap struct {
	choose key.Binding
}

// Additional short help entries. This satisfies the help.KeyMap interface and
// is entirely optional.
func (d delegateKeyMap) ShortHelp() []key.Binding {
	return []key.Binding{d.choose}
}

// Additional full help entries. This satisfies the help.KeyMap interface and
// is entirely optional.
func (d delegateKeyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{{d.choose}}
}

func newDelegateKeyMap() *delegateKeyMap {
	return &delegateKeyMap{
		choose: key.NewBinding(
			key.WithKeys("enter"),
			key.WithHelp("enter", "choose"),
		),
	}
}
