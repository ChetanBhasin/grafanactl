package grafana

import (
	"errors"
	"net/url"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/go-openapi/strfmt"
	goapi "github.com/grafana/grafana-openapi-client-go/client"
	"github.com/grafana/grafanactl/internal/config"
)

func ClientFromContext(ctx *config.Context) (*goapi.GrafanaHTTPAPI, error) {
	cfg, err := transportConfigFromContext(ctx)
	if err != nil {
		return nil, err
	}

	return goapi.NewHTTPClientWithConfig(strfmt.Default, cfg), nil
}

func GetVersion(ctx *config.Context) (*semver.Version, error) {
	gClient, err := ClientFromContext(ctx)
	if err != nil {
		return nil, err
	}

	healthResponse, err := gClient.Health.GetHealth()
	if err != nil {
		return nil, err
	}

	return semver.NewVersion(healthResponse.Payload.Version)
}

func transportConfigFromContext(ctx *config.Context) (*goapi.TransportConfig, error) {
	if ctx == nil {
		return nil, errors.New("no context provided")
	}
	if ctx.Grafana == nil {
		return nil, errors.New("grafana not configured")
	}

	grafanaURL, err := url.Parse(ctx.Grafana.Server)
	if err != nil {
		return nil, err
	}

	cfg := &goapi.TransportConfig{
		Host:     grafanaURL.Host,
		BasePath: strings.TrimLeft(grafanaURL.Path+"/api", "/"),
		Schemes:  []string{grafanaURL.Scheme},
	}

	if ctx.Grafana.TLS != nil {
		cfg.TLSConfig = ctx.Grafana.TLS.ToStdTLSConfig()
	}

	// API token takes precedence over basic auth.
	if ctx.Grafana.APIToken != "" {
		cfg.APIKey = ctx.Grafana.APIToken
		return cfg, nil
	}

	if ctx.Grafana.User != "" && ctx.Grafana.Password != "" {
		cfg.BasicAuth = url.UserPassword(ctx.Grafana.User, ctx.Grafana.Password)
		if ctx.Grafana.OrgID != 0 {
			cfg.OrgID = ctx.Grafana.OrgID
		}
	}

	return cfg, nil
}
