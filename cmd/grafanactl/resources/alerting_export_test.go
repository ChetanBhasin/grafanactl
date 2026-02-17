package resources

import (
	"testing"

	"github.com/grafana/grafana-openapi-client-go/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeAlertingFileExportPayload(t *testing.T) {
	t.Run("ignores non-object payloads", func(t *testing.T) {
		file, ok, err := decodeAlertingFileExportPayload([]any{"not", "an", "object"})
		require.NoError(t, err)
		assert.False(t, ok)
		assert.Nil(t, file)
	})

	t.Run("detects alerting export with groups", func(t *testing.T) {
		file, ok, err := decodeAlertingFileExportPayload(map[string]any{
			"apiVersion": float64(1),
			"groups": []any{
				map[string]any{
					"name": "group-a",
				},
			},
		})

		require.NoError(t, err)
		require.True(t, ok)
		require.NotNil(t, file)
		assert.Len(t, file.Groups, 1)
		assert.Equal(t, int64(1), file.APIVersion)
	})
}

func TestHydrateExportFolderNames(t *testing.T) {
	t.Run("fills missing folder names", func(t *testing.T) {
		alertingFile := &models.AlertingFileExport{
			Groups: []*models.AlertRuleGroupExport{
				{
					Name: "group-a",
				},
			},
		}

		hydrateExportFolderNames(alertingFile, "alerts-folder", map[string]string{"alerts-folder": "Alerts"})
		assert.Equal(t, "Alerts", alertingFile.Groups[0].Folder)
	})

	t.Run("does not override existing folder names", func(t *testing.T) {
		alertingFile := &models.AlertingFileExport{
			Groups: []*models.AlertRuleGroupExport{
				{
					Name:   "group-a",
					Folder: "Existing",
				},
			},
		}

		hydrateExportFolderNames(alertingFile, "alerts-folder", map[string]string{"alerts-folder": "Alerts"})
		assert.Equal(t, "Existing", alertingFile.Groups[0].Folder)
	})
}

func TestNormalizeAlertingFileIntegralNumbers(t *testing.T) {
	alertingFile := &models.AlertingFileExport{
		Groups: []*models.AlertRuleGroupExport{
			{
				Rules: []*models.AlertRuleExport{
					{
						Data: []*models.AlertQueryExport{
							{
								Model: map[string]any{
									"intervalMs": float64(1000),
									"thresholds": []any{
										float64(5),
										float64(0.25),
									},
								},
							},
						},
					},
				},
			},
		},
	}

	normalizeAlertingFileIntegralNumbers(alertingFile)

	model := alertingFile.Groups[0].Rules[0].Data[0].Model.(map[string]any)
	assert.IsType(t, int64(0), model["intervalMs"])

	thresholds := model["thresholds"].([]any)
	assert.IsType(t, int64(0), thresholds[0])
	assert.IsType(t, float64(0), thresholds[1])
}
