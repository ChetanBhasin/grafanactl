package resources

import (
	"testing"

	"github.com/grafana/grafana-openapi-client-go/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseAlertRuleGroupRef(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		want      alertRuleGroupRef
		wantError bool
	}{
		{
			name:  "valid",
			input: "folder-a/cpu-high",
			want: alertRuleGroupRef{
				FolderUID: "folder-a",
				Group:     "cpu-high",
			},
			wantError: false,
		},
		{
			name:      "missing slash",
			input:     "folder-a",
			wantError: true,
		},
		{
			name:      "missing folder",
			input:     "/cpu-high",
			wantError: true,
		},
		{
			name:      "missing group",
			input:     "folder-a/",
			wantError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseAlertRuleGroupRef(test.input)
			if test.wantError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, test.want, got)
		})
	}
}

func TestBuildAlertRuleGroupSummaries(t *testing.T) {
	rules := models.ProvisionedAlertRules{
		&models.ProvisionedAlertRule{
			UID:       "r1",
			FolderUID: toStringPtr("folder-a"),
			RuleGroup: toStringPtr("group-1"),
		},
		&models.ProvisionedAlertRule{
			UID:       "r2",
			FolderUID: toStringPtr("folder-a"),
			RuleGroup: toStringPtr("group-1"),
		},
		&models.ProvisionedAlertRule{
			UID:       "r3",
			FolderUID: toStringPtr("folder-b"),
			RuleGroup: toStringPtr("group-2"),
		},
		&models.ProvisionedAlertRule{
			UID:       "missing-group",
			FolderUID: toStringPtr("folder-c"),
		},
		&models.ProvisionedAlertRule{
			UID:       "missing-folder",
			RuleGroup: toStringPtr("group-3"),
		},
	}

	assert.Equal(t, []alertRuleGroupSummary{
		{
			FolderUID: "folder-a",
			Group:     "group-1",
			RuleCount: 2,
		},
		{
			FolderUID: "folder-b",
			Group:     "group-2",
			RuleCount: 1,
		},
	}, buildAlertRuleGroupSummaries(rules))
}

func toStringPtr(value string) *string {
	return &value
}
