package resources

import (
	"testing"
	"time"

	"github.com/go-openapi/strfmt"
	"github.com/grafana/grafana-openapi-client-go/models"
	cmdconfig "github.com/grafana/grafanactl/cmd/grafanactl/config"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateProvisionedAlertRule(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(rule *models.ProvisionedAlertRule)
		wantError string
	}{
		{
			name:      "valid",
			mutate:    func(_ *models.ProvisionedAlertRule) {},
			wantError: "",
		},
		{
			name: "missing state values",
			mutate: func(rule *models.ProvisionedAlertRule) {
				rule.ExecErrState = nil
				rule.NoDataState = nil
			},
			wantError: "",
		},
		{
			name: "keep last state values",
			mutate: func(rule *models.ProvisionedAlertRule) {
				*rule.ExecErrState = "KeepLast"
				*rule.NoDataState = "keep_last_state"
			},
			wantError: "",
		},
		{
			name: "empty condition",
			mutate: func(rule *models.ProvisionedAlertRule) {
				*rule.Condition = "   "
			},
			wantError: "condition must not be empty",
		},
		{
			name: "empty folder uid",
			mutate: func(rule *models.ProvisionedAlertRule) {
				*rule.FolderUID = "   "
			},
			wantError: "folderUID must not be empty",
		},
		{
			name: "empty title",
			mutate: func(rule *models.ProvisionedAlertRule) {
				*rule.Title = " "
			},
			wantError: "title must not be empty",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rule := validProvisionedAlertRule()
			test.mutate(rule)

			err := validateProvisionedAlertRule(rule)
			if test.wantError == "" {
				require.NoError(t, err)
				return
			}

			require.Error(t, err)
			assert.ErrorContains(t, err, test.wantError)
		})
	}
}

func TestValidateAlertRuleGroupManifest(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(group *models.AlertRuleGroup)
		wantError string
	}{
		{
			name:      "valid",
			mutate:    func(_ *models.AlertRuleGroup) {},
			wantError: "",
		},
		{
			name: "missing folder uid",
			mutate: func(group *models.AlertRuleGroup) {
				group.FolderUID = " "
			},
			wantError: "folderUid must not be empty",
		},
		{
			name: "missing title",
			mutate: func(group *models.AlertRuleGroup) {
				group.Title = ""
			},
			wantError: "title must not be empty",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			group := validAlertRuleGroup()
			test.mutate(group)

			err := validateAlertRuleGroupManifest(group)
			if test.wantError == "" {
				require.NoError(t, err)
				return
			}

			require.Error(t, err)
			assert.ErrorContains(t, err, test.wantError)
		})
	}
}

func TestAlertingCommandsIncludeValidate(t *testing.T) {
	t.Run("rules", func(t *testing.T) {
		cmd := alertingRulesCmd(&cmdconfig.Options{})
		assert.True(t, hasSubcommand(cmd, "validate"))
	})

	t.Run("groups", func(t *testing.T) {
		cmd := alertingGroupsCmd(&cmdconfig.Options{})
		assert.True(t, hasSubcommand(cmd, "validate"))
	})
}

func validAlertRuleGroup() *models.AlertRuleGroup {
	return &models.AlertRuleGroup{
		FolderUID: "folder-a",
		Title:     "group-a",
		Rules: []*models.ProvisionedAlertRule{
			validProvisionedAlertRule(),
		},
	}
}

func validProvisionedAlertRule() *models.ProvisionedAlertRule {
	condition := "A"
	execErrState := models.ProvisionedAlertRuleExecErrStateOK
	folderUID := "folder-a"
	forDuration := strfmt.Duration(time.Minute)
	noDataState := models.ProvisionedAlertRuleNoDataStateNoData
	orgID := int64(1)
	ruleGroup := "group-a"
	title := "High CPU"

	return &models.ProvisionedAlertRule{
		UID:          "rule-a",
		Condition:    &condition,
		Data:         []*models.AlertQuery{{RefID: "A"}},
		ExecErrState: &execErrState,
		FolderUID:    &folderUID,
		For:          &forDuration,
		NoDataState:  &noDataState,
		OrgID:        &orgID,
		RuleGroup:    &ruleGroup,
		Title:        &title,
	}
}

func hasSubcommand(cmd *cobra.Command, name string) bool {
	for _, child := range cmd.Commands() {
		if child.Name() == name {
			return true
		}
	}

	return false
}
