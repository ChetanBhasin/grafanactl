package grafana

import (
	"testing"

	"github.com/grafana/grafanactl/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTransportConfigFromContext(t *testing.T) {
	tests := []struct {
		name            string
		context         *config.Context
		wantAPIKey      string
		wantBasicUser   string
		wantBasicPass   string
		wantOrgID       int64
		wantBasePath    string
		wantErrContains string
	}{
		{
			name:            "nil context",
			context:         nil,
			wantErrContains: "no context provided",
		},
		{
			name:            "missing grafana config",
			context:         &config.Context{},
			wantErrContains: "grafana not configured",
		},
		{
			name: "api token takes precedence over basic auth and org header",
			context: &config.Context{Grafana: &config.GrafanaConfig{
				Server:   "https://example.grafana.net",
				APIToken: "token-123",
				User:     "user",
				Password: "pass",
				OrgID:    42,
			}},
			wantAPIKey:    "token-123",
			wantBasicUser: "",
			wantBasicPass: "",
			wantOrgID:     0,
			wantBasePath:  "api",
		},
		{
			name: "basic auth with org id",
			context: &config.Context{Grafana: &config.GrafanaConfig{
				Server:   "https://example.grafana.net/grafana",
				User:     "admin",
				Password: "admin-pass",
				OrgID:    7,
			}},
			wantAPIKey:    "",
			wantBasicUser: "admin",
			wantBasicPass: "admin-pass",
			wantOrgID:     7,
			wantBasePath:  "grafana/api",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg, err := transportConfigFromContext(test.context)
			if test.wantErrContains != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), test.wantErrContains)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, cfg)

			assert.Equal(t, test.wantAPIKey, cfg.APIKey)
			assert.Equal(t, test.wantOrgID, cfg.OrgID)
			assert.Equal(t, test.wantBasePath, cfg.BasePath)

			if test.wantBasicUser == "" {
				assert.Nil(t, cfg.BasicAuth)
				return
			}

			require.NotNil(t, cfg.BasicAuth)
			assert.Equal(t, test.wantBasicUser, cfg.BasicAuth.Username())
			password, hasPassword := cfg.BasicAuth.Password()
			assert.True(t, hasPassword)
			assert.Equal(t, test.wantBasicPass, password)
		})
	}
}
