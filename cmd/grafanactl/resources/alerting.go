package resources

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"

	goruntime "github.com/go-openapi/runtime"
	"github.com/grafana/grafana-openapi-client-go/client/provisioning"
	"github.com/grafana/grafana-openapi-client-go/models"
	cmdconfig "github.com/grafana/grafanactl/cmd/grafanactl/config"
	cmdio "github.com/grafana/grafanactl/cmd/grafanactl/io"
	"github.com/grafana/grafanactl/internal/format"
	"github.com/grafana/grafanactl/internal/grafana"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

const (
	defaultAlertingRulesPath  = "./resources/alerting/rules"
	defaultAlertingGroupsPath = "./resources/alerting/groups"
)

type alertRuleGroupRef struct {
	FolderUID string
	Group     string
}

type alertRuleGroupSummary struct {
	FolderUID string `json:"folderUid" yaml:"folderUid"`
	Group     string `json:"group" yaml:"group"`
	RuleCount int    `json:"ruleCount" yaml:"ruleCount"`
}

type alertRuleGroupSummaryList struct {
	Items []alertRuleGroupSummary `json:"items" yaml:"items"`
}

type alertRuleList struct {
	Items models.ProvisionedAlertRules `json:"items" yaml:"items"`
}

type alertingListOpts struct {
	IO cmdio.Options
}

type alertingGetOpts struct {
	IO cmdio.Options
}

type alertingPullOpts struct {
	IO          cmdio.Options
	Path        string
	StopOnError bool
}

type alertingRulesPushOpts struct {
	Paths             []string
	StopOnError       bool
	DisableProvenance bool
}

type alertingGroupsPushOpts struct {
	Paths             []string
	StopOnError       bool
	DisableProvenance bool
}

type alertingRulesDeleteOpts struct {
	StopOnError       bool
	DisableProvenance bool
}

type alertingGroupsDeleteOpts struct {
	StopOnError bool
}

type alertingTextCodec struct{}

func (opts *alertingListOpts) setup(flags *pflag.FlagSet) {
	opts.IO.RegisterCustomCodec("text", &alertingTextCodec{})
	opts.IO.DefaultFormat("text")
	opts.IO.BindFlags(flags)
}

func (opts *alertingListOpts) Validate() error {
	if err := opts.IO.Validate(); err != nil {
		return err
	}

	return nil
}

func (opts *alertingGetOpts) setup(flags *pflag.FlagSet) {
	opts.IO.DefaultFormat("yaml")
	opts.IO.BindFlags(flags)
}

func (opts *alertingGetOpts) Validate() error {
	if err := opts.IO.Validate(); err != nil {
		return err
	}

	return nil
}

func (opts *alertingPullOpts) setup(flags *pflag.FlagSet, defaultPath string) {
	opts.IO.DefaultFormat("yaml")
	opts.IO.BindFlags(flags)
	flags.StringVarP(&opts.Path, "path", "p", defaultPath, "Path on disk in which the resources will be written")
	flags.BoolVar(&opts.StopOnError, "stop-on-error", opts.StopOnError, "Stop pulling resources when an error occurs")
}

func (opts *alertingPullOpts) Validate() error {
	if err := opts.IO.Validate(); err != nil {
		return err
	}

	if opts.Path == "" {
		return errors.New("--path is required")
	}

	return nil
}

func (opts *alertingRulesPushOpts) setup(flags *pflag.FlagSet, defaultPath string) {
	flags.StringSliceVarP(&opts.Paths, "path", "p", []string{defaultPath}, "Paths on disk from which to read alert rule manifests")
	flags.BoolVar(&opts.StopOnError, "stop-on-error", opts.StopOnError, "Stop pushing rules when an error occurs")
	flags.BoolVar(
		&opts.DisableProvenance,
		"disable-provenance",
		opts.DisableProvenance,
		"Set X-Disable-Provenance=true on write requests",
	)
}

func (opts *alertingRulesPushOpts) Validate() error {
	if len(opts.Paths) == 0 {
		return errors.New("at least one path is required")
	}

	return nil
}

func (opts *alertingGroupsPushOpts) setup(flags *pflag.FlagSet, defaultPath string) {
	flags.StringSliceVarP(&opts.Paths, "path", "p", []string{defaultPath}, "Paths on disk from which to read alert rule group manifests")
	flags.BoolVar(&opts.StopOnError, "stop-on-error", opts.StopOnError, "Stop pushing groups when an error occurs")
	flags.BoolVar(
		&opts.DisableProvenance,
		"disable-provenance",
		opts.DisableProvenance,
		"Set X-Disable-Provenance=true on write requests",
	)
}

func (opts *alertingGroupsPushOpts) Validate() error {
	if len(opts.Paths) == 0 {
		return errors.New("at least one path is required")
	}

	return nil
}

func (opts *alertingRulesDeleteOpts) setup(flags *pflag.FlagSet) {
	flags.BoolVar(&opts.StopOnError, "stop-on-error", opts.StopOnError, "Stop deleting rules when an error occurs")
	flags.BoolVar(
		&opts.DisableProvenance,
		"disable-provenance",
		opts.DisableProvenance,
		"Set X-Disable-Provenance=true on delete requests",
	)
}

func (opts *alertingGroupsDeleteOpts) setup(flags *pflag.FlagSet) {
	flags.BoolVar(&opts.StopOnError, "stop-on-error", opts.StopOnError, "Stop deleting groups when an error occurs")
}

func (codec *alertingTextCodec) Format() format.Format {
	return "text"
}

func (codec *alertingTextCodec) Encode(io.Writer, any) error {
	return errors.New("text codec does not support encoding")
}

func (codec *alertingTextCodec) Decode(io.Reader, any) error {
	return errors.New("text codec does not support decoding")
}

func alertingCmd(configOpts *cmdconfig.Options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "alerting",
		Short: "Manage Grafana alerting provisioning resources",
		Long:  "Manage Grafana alerting provisioning resources (alert rules and rule groups).",
	}

	cmd.AddCommand(alertingRulesCmd(configOpts))
	cmd.AddCommand(alertingGroupsCmd(configOpts))

	return cmd
}

func alertingRulesCmd(configOpts *cmdconfig.Options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rules",
		Short: "Manage alert rules",
		Long:  "Manage Grafana alert rules through the provisioning API.",
	}

	cmd.AddCommand(alertingRulesListCmd(configOpts))
	cmd.AddCommand(alertingRulesGetCmd(configOpts))
	cmd.AddCommand(alertingRulesPullCmd(configOpts))
	cmd.AddCommand(alertingRulesPushCmd(configOpts))
	cmd.AddCommand(alertingRulesDeleteCmd(configOpts))

	return cmd
}

func alertingRulesListCmd(configOpts *cmdconfig.Options) *cobra.Command {
	opts := &alertingListOpts{}

	cmd := &cobra.Command{
		Use:   "list",
		Args:  cobra.NoArgs,
		Short: "List alert rules",
		Long:  "List Grafana alert rules from the provisioning API.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()

			if err := opts.Validate(); err != nil {
				return err
			}

			client, err := loadProvisioningClient(ctx, configOpts)
			if err != nil {
				return err
			}

			rules, err := listAlertRules(ctx, client)
			if err != nil {
				return err
			}
			sortAlertRules(rules)

			if opts.IO.OutputFormat == "text" {
				return printAlertRulesTable(cmd.OutOrStdout(), rules)
			}

			codec, err := opts.IO.Codec()
			if err != nil {
				return err
			}

			return codec.Encode(cmd.OutOrStdout(), alertRuleList{Items: rules})
		},
	}

	opts.setup(cmd.Flags())

	return cmd
}

func alertingRulesGetCmd(configOpts *cmdconfig.Options) *cobra.Command {
	opts := &alertingGetOpts{}

	cmd := &cobra.Command{
		Use:   "get UID",
		Args:  cobra.ExactArgs(1),
		Short: "Get an alert rule",
		Long:  "Get a single alert rule by UID.",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			if err := opts.Validate(); err != nil {
				return err
			}

			client, err := loadProvisioningClient(ctx, configOpts)
			if err != nil {
				return err
			}

			rule, err := getAlertRule(ctx, client, args[0])
			if err != nil {
				return err
			}

			codec, err := opts.IO.Codec()
			if err != nil {
				return err
			}

			return codec.Encode(cmd.OutOrStdout(), rule)
		},
	}

	opts.setup(cmd.Flags())

	return cmd
}

func alertingRulesPullCmd(configOpts *cmdconfig.Options) *cobra.Command {
	opts := &alertingPullOpts{}

	cmd := &cobra.Command{
		Use:   "pull [UID]...",
		Args:  cobra.ArbitraryArgs,
		Short: "Pull alert rules",
		Long:  "Pull alert rules from Grafana and write them to local files.",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			if err := opts.Validate(); err != nil {
				return err
			}

			client, err := loadProvisioningClient(ctx, configOpts)
			if err != nil {
				return err
			}

			var (
				rules    models.ProvisionedAlertRules
				failures int
			)

			if len(args) == 0 {
				rules, err = listAlertRules(ctx, client)
				if err != nil {
					return err
				}
			} else {
				rules = make(models.ProvisionedAlertRules, 0, len(args))
				for _, uid := range args {
					rule, getErr := getAlertRule(ctx, client, uid)
					if getErr != nil {
						failures++
						if opts.StopOnError {
							return getErr
						}
						continue
					}

					rules = append(rules, rule)
				}
			}

			codec, err := opts.IO.Codec()
			if err != nil {
				return err
			}

			if err := ensureDirectoryExists(opts.Path); err != nil {
				return err
			}

			usedNames := make(map[string]int)
			written := 0
			for i, rule := range rules {
				fileBase := rule.UID
				if fileBase == "" {
					fileBase = fmt.Sprintf("rule-%d", i+1)
				}

				fileBase = nextUniqueBaseName(usedNames, sanitizeFileNamePart(fileBase))
				fileName := fileBase + "." + opts.IO.OutputFormat
				fullPath := filepath.Join(opts.Path, fileName)

				if writeErr := writeManifestFile(fullPath, codec, rule); writeErr != nil {
					failures++
					if opts.StopOnError {
						return writeErr
					}
					continue
				}

				written++
			}

			printer := cmdio.Success
			if failures != 0 {
				printer = cmdio.Warning
				if written == 0 {
					printer = cmdio.Error
				}
			}

			printer(cmd.OutOrStdout(), "%d alert rules pulled, %d errors", written, failures)

			return nil
		},
	}

	opts.setup(cmd.Flags(), defaultAlertingRulesPath)

	return cmd
}

func alertingRulesPushCmd(configOpts *cmdconfig.Options) *cobra.Command {
	opts := &alertingRulesPushOpts{}

	cmd := &cobra.Command{
		Use:   "push",
		Args:  cobra.NoArgs,
		Short: "Push alert rules",
		Long:  "Push alert rule manifests from local files to Grafana.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()

			if err := opts.Validate(); err != nil {
				return err
			}

			client, err := loadProvisioningClient(ctx, configOpts)
			if err != nil {
				return err
			}

			files, err := collectManifestFiles(opts.Paths)
			if err != nil {
				return err
			}

			succeeded := 0
			failed := 0

			for _, file := range files {
				rules, readErr := readAlertRulesFromFile(file)
				if readErr != nil {
					failed++
					if opts.StopOnError {
						return readErr
					}
					continue
				}

				for _, rule := range rules {
					if rule == nil {
						continue
					}

					if pushErr := upsertAlertRule(ctx, client, rule, opts.DisableProvenance); pushErr != nil {
						failed++
						if opts.StopOnError {
							return pushErr
						}
						continue
					}

					succeeded++
				}
			}

			printer := cmdio.Success
			if failed != 0 {
				printer = cmdio.Warning
				if succeeded == 0 {
					printer = cmdio.Error
				}
			}

			printer(cmd.OutOrStdout(), "%d alert rules pushed, %d errors", succeeded, failed)

			return nil
		},
	}

	opts.setup(cmd.Flags(), defaultAlertingRulesPath)

	return cmd
}

func alertingRulesDeleteCmd(configOpts *cmdconfig.Options) *cobra.Command {
	opts := &alertingRulesDeleteOpts{}

	cmd := &cobra.Command{
		Use:   "delete UID...",
		Args:  cobra.MinimumNArgs(1),
		Short: "Delete alert rules",
		Long:  "Delete one or more alert rules by UID.",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			client, err := loadProvisioningClient(ctx, configOpts)
			if err != nil {
				return err
			}

			succeeded := 0
			failed := 0

			for _, uid := range args {
				delErr := deleteAlertRule(ctx, client, uid, opts.DisableProvenance)
				if delErr != nil {
					failed++
					if opts.StopOnError {
						return delErr
					}
					continue
				}

				succeeded++
			}

			printer := cmdio.Success
			if failed != 0 {
				printer = cmdio.Warning
				if succeeded == 0 {
					printer = cmdio.Error
				}
			}

			printer(cmd.OutOrStdout(), "%d alert rules deleted, %d errors", succeeded, failed)

			return nil
		},
	}

	opts.setup(cmd.Flags())

	return cmd
}

func alertingGroupsCmd(configOpts *cmdconfig.Options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "groups",
		Short: "Manage alert rule groups",
		Long:  "Manage Grafana alert rule groups through the provisioning API.",
	}

	cmd.AddCommand(alertingGroupsListCmd(configOpts))
	cmd.AddCommand(alertingGroupsGetCmd(configOpts))
	cmd.AddCommand(alertingGroupsPullCmd(configOpts))
	cmd.AddCommand(alertingGroupsPushCmd(configOpts))
	cmd.AddCommand(alertingGroupsDeleteCmd(configOpts))

	return cmd
}

func alertingGroupsListCmd(configOpts *cmdconfig.Options) *cobra.Command {
	opts := &alertingListOpts{}

	cmd := &cobra.Command{
		Use:   "list",
		Args:  cobra.NoArgs,
		Short: "List alert rule groups",
		Long:  "List alert rule groups derived from alert rules.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()

			if err := opts.Validate(); err != nil {
				return err
			}

			client, err := loadProvisioningClient(ctx, configOpts)
			if err != nil {
				return err
			}

			groups, err := listAlertRuleGroups(ctx, client)
			if err != nil {
				return err
			}

			if opts.IO.OutputFormat == "text" {
				return printAlertRuleGroupsTable(cmd.OutOrStdout(), groups)
			}

			codec, err := opts.IO.Codec()
			if err != nil {
				return err
			}

			return codec.Encode(cmd.OutOrStdout(), alertRuleGroupSummaryList{Items: groups})
		},
	}

	opts.setup(cmd.Flags())

	return cmd
}

func alertingGroupsGetCmd(configOpts *cmdconfig.Options) *cobra.Command {
	opts := &alertingGetOpts{}

	cmd := &cobra.Command{
		Use:   "get FOLDER_UID/GROUP",
		Args:  cobra.ExactArgs(1),
		Short: "Get an alert rule group",
		Long:  "Get a single alert rule group by folder UID and group name.",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			if err := opts.Validate(); err != nil {
				return err
			}

			ref, err := parseAlertRuleGroupRef(args[0])
			if err != nil {
				return err
			}

			client, err := loadProvisioningClient(ctx, configOpts)
			if err != nil {
				return err
			}

			group, err := getAlertRuleGroup(ctx, client, ref)
			if err != nil {
				return err
			}

			codec, err := opts.IO.Codec()
			if err != nil {
				return err
			}

			return codec.Encode(cmd.OutOrStdout(), group)
		},
	}

	opts.setup(cmd.Flags())

	return cmd
}

func alertingGroupsPullCmd(configOpts *cmdconfig.Options) *cobra.Command {
	opts := &alertingPullOpts{}

	cmd := &cobra.Command{
		Use:   "pull [FOLDER_UID/GROUP]...",
		Args:  cobra.ArbitraryArgs,
		Short: "Pull alert rule groups",
		Long:  "Pull alert rule groups from Grafana and write them to local files.",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			if err := opts.Validate(); err != nil {
				return err
			}

			client, err := loadProvisioningClient(ctx, configOpts)
			if err != nil {
				return err
			}

			var refs []alertRuleGroupRef
			if len(args) == 0 {
				summaries, listErr := listAlertRuleGroups(ctx, client)
				if listErr != nil {
					return listErr
				}
				refs = make([]alertRuleGroupRef, 0, len(summaries))
				for _, summary := range summaries {
					refs = append(refs, alertRuleGroupRef{
						FolderUID: summary.FolderUID,
						Group:     summary.Group,
					})
				}
			} else {
				refs = make([]alertRuleGroupRef, 0, len(args))
				for _, arg := range args {
					ref, parseErr := parseAlertRuleGroupRef(arg)
					if parseErr != nil {
						return parseErr
					}
					refs = append(refs, ref)
				}
			}

			codec, err := opts.IO.Codec()
			if err != nil {
				return err
			}

			if err := ensureDirectoryExists(opts.Path); err != nil {
				return err
			}

			usedNames := make(map[string]int)
			written := 0
			failed := 0

			for _, ref := range refs {
				group, getErr := getAlertRuleGroup(ctx, client, ref)
				if getErr != nil {
					failed++
					if opts.StopOnError {
						return getErr
					}
					continue
				}

				baseName := sanitizeFileNamePart(ref.FolderUID) + "__" + sanitizeFileNamePart(ref.Group)
				baseName = nextUniqueBaseName(usedNames, baseName)
				fileName := baseName + "." + opts.IO.OutputFormat
				fullPath := filepath.Join(opts.Path, fileName)

				if writeErr := writeManifestFile(fullPath, codec, group); writeErr != nil {
					failed++
					if opts.StopOnError {
						return writeErr
					}
					continue
				}

				written++
			}

			printer := cmdio.Success
			if failed != 0 {
				printer = cmdio.Warning
				if written == 0 {
					printer = cmdio.Error
				}
			}

			printer(cmd.OutOrStdout(), "%d alert rule groups pulled, %d errors", written, failed)

			return nil
		},
	}

	opts.setup(cmd.Flags(), defaultAlertingGroupsPath)

	return cmd
}

func alertingGroupsPushCmd(configOpts *cmdconfig.Options) *cobra.Command {
	opts := &alertingGroupsPushOpts{}

	cmd := &cobra.Command{
		Use:   "push",
		Args:  cobra.NoArgs,
		Short: "Push alert rule groups",
		Long:  "Push alert rule group manifests from local files to Grafana.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()

			if err := opts.Validate(); err != nil {
				return err
			}

			client, err := loadProvisioningClient(ctx, configOpts)
			if err != nil {
				return err
			}

			files, err := collectManifestFiles(opts.Paths)
			if err != nil {
				return err
			}

			succeeded := 0
			failed := 0

			for _, file := range files {
				groups, readErr := readAlertRuleGroupsFromFile(file)
				if readErr != nil {
					failed++
					if opts.StopOnError {
						return readErr
					}
					continue
				}

				for _, group := range groups {
					if group == nil {
						continue
					}

					if strings.TrimSpace(group.FolderUID) == "" || strings.TrimSpace(group.Title) == "" {
						err = fmt.Errorf("group in '%s' must have non-empty folderUid and title", file)
						failed++
						if opts.StopOnError {
							return err
						}
						continue
					}

					putErr := upsertAlertRuleGroup(ctx, client, alertRuleGroupRef{
						FolderUID: group.FolderUID,
						Group:     group.Title,
					}, group, opts.DisableProvenance)
					if putErr != nil {
						failed++
						if opts.StopOnError {
							return putErr
						}
						continue
					}

					succeeded++
				}
			}

			printer := cmdio.Success
			if failed != 0 {
				printer = cmdio.Warning
				if succeeded == 0 {
					printer = cmdio.Error
				}
			}

			printer(cmd.OutOrStdout(), "%d alert rule groups pushed, %d errors", succeeded, failed)

			return nil
		},
	}

	opts.setup(cmd.Flags(), defaultAlertingGroupsPath)

	return cmd
}

func alertingGroupsDeleteCmd(configOpts *cmdconfig.Options) *cobra.Command {
	opts := &alertingGroupsDeleteOpts{}

	cmd := &cobra.Command{
		Use:   "delete FOLDER_UID/GROUP...",
		Args:  cobra.MinimumNArgs(1),
		Short: "Delete alert rule groups",
		Long:  "Delete one or more alert rule groups.",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			client, err := loadProvisioningClient(ctx, configOpts)
			if err != nil {
				return err
			}

			succeeded := 0
			failed := 0

			for _, arg := range args {
				ref, parseErr := parseAlertRuleGroupRef(arg)
				if parseErr != nil {
					failed++
					if opts.StopOnError {
						return parseErr
					}
					continue
				}

				delErr := deleteAlertRuleGroup(ctx, client, ref)
				if delErr != nil {
					failed++
					if opts.StopOnError {
						return delErr
					}
					continue
				}

				succeeded++
			}

			printer := cmdio.Success
			if failed != 0 {
				printer = cmdio.Warning
				if succeeded == 0 {
					printer = cmdio.Error
				}
			}

			printer(cmd.OutOrStdout(), "%d alert rule groups deleted, %d errors", succeeded, failed)

			return nil
		},
	}

	opts.setup(cmd.Flags())

	return cmd
}

func loadProvisioningClient(ctx context.Context, configOpts *cmdconfig.Options) (provisioning.ClientService, error) {
	cfg, err := configOpts.LoadConfig(ctx)
	if err != nil {
		return nil, err
	}

	client, err := grafana.ClientFromContext(cfg.GetCurrentContext())
	if err != nil {
		return nil, err
	}

	return client.Provisioning, nil
}

func listAlertRules(ctx context.Context, client provisioning.ClientService) (models.ProvisionedAlertRules, error) {
	resp, err := client.GetAlertRulesWithParams(provisioning.NewGetAlertRulesParamsWithContext(ctx))
	if err != nil {
		return nil, err
	}

	return resp.Payload, nil
}

func getAlertRule(ctx context.Context, client provisioning.ClientService, uid string) (*models.ProvisionedAlertRule, error) {
	resp, err := client.GetAlertRuleWithParams(
		provisioning.NewGetAlertRuleParamsWithContext(ctx).WithUID(uid),
	)
	if err != nil {
		return nil, err
	}

	return resp.Payload, nil
}

func upsertAlertRule(
	ctx context.Context,
	client provisioning.ClientService,
	rule *models.ProvisionedAlertRule,
	disableProvenance bool,
) error {
	header := disableProvenanceHeader(disableProvenance)

	if strings.TrimSpace(rule.UID) != "" {
		params := provisioning.NewPutAlertRuleParamsWithContext(ctx).WithUID(rule.UID).WithBody(rule)
		if header != nil {
			params.WithXDisableProvenance(header)
		}

		if _, err := client.PutAlertRule(params); err == nil {
			return nil
		} else if !isNotFoundError(err) {
			return err
		}
	}

	params := provisioning.NewPostAlertRuleParamsWithContext(ctx).WithBody(rule)
	if header != nil {
		params.WithXDisableProvenance(header)
	}

	_, err := client.PostAlertRule(params)
	return err
}

func deleteAlertRule(
	ctx context.Context,
	client provisioning.ClientService,
	uid string,
	disableProvenance bool,
) error {
	params := provisioning.NewDeleteAlertRuleParamsWithContext(ctx).WithUID(uid)
	header := disableProvenanceHeader(disableProvenance)
	if header != nil {
		params.WithXDisableProvenance(header)
	}

	_, err := client.DeleteAlertRule(params)
	return err
}

func listAlertRuleGroups(ctx context.Context, client provisioning.ClientService) ([]alertRuleGroupSummary, error) {
	rules, err := listAlertRules(ctx, client)
	if err != nil {
		return nil, err
	}

	return buildAlertRuleGroupSummaries(rules), nil
}

func getAlertRuleGroup(
	ctx context.Context,
	client provisioning.ClientService,
	ref alertRuleGroupRef,
) (*models.AlertRuleGroup, error) {
	resp, err := client.GetAlertRuleGroupWithParams(
		provisioning.NewGetAlertRuleGroupParamsWithContext(ctx).
			WithFolderUID(ref.FolderUID).
			WithGroup(ref.Group),
	)
	if err != nil {
		return nil, err
	}

	return resp.Payload, nil
}

func upsertAlertRuleGroup(
	ctx context.Context,
	client provisioning.ClientService,
	ref alertRuleGroupRef,
	group *models.AlertRuleGroup,
	disableProvenance bool,
) error {
	params := provisioning.NewPutAlertRuleGroupParamsWithContext(ctx).
		WithFolderUID(ref.FolderUID).
		WithGroup(ref.Group).
		WithBody(group)

	header := disableProvenanceHeader(disableProvenance)
	if header != nil {
		params.WithXDisableProvenance(header)
	}

	_, err := client.PutAlertRuleGroup(params)
	return err
}

func deleteAlertRuleGroup(ctx context.Context, client provisioning.ClientService, ref alertRuleGroupRef) error {
	_, err := client.DeleteAlertRuleGroupWithParams(
		provisioning.NewDeleteAlertRuleGroupParamsWithContext(ctx).
			WithFolderUID(ref.FolderUID).
			WithGroup(ref.Group),
	)

	return err
}

func buildAlertRuleGroupSummaries(rules models.ProvisionedAlertRules) []alertRuleGroupSummary {
	groupByRef := make(map[string]alertRuleGroupSummary)
	for _, rule := range rules {
		if rule == nil {
			continue
		}

		folderUID := strings.TrimSpace(stringValue(rule.FolderUID))
		group := strings.TrimSpace(stringValue(rule.RuleGroup))
		if folderUID == "" || group == "" {
			continue
		}

		key := folderUID + "\x00" + group
		summary, ok := groupByRef[key]
		if !ok {
			summary = alertRuleGroupSummary{
				FolderUID: folderUID,
				Group:     group,
			}
		}
		summary.RuleCount++
		groupByRef[key] = summary
	}

	summaries := make([]alertRuleGroupSummary, 0, len(groupByRef))
	for _, summary := range groupByRef {
		summaries = append(summaries, summary)
	}

	sort.Slice(summaries, func(i, j int) bool {
		if summaries[i].FolderUID != summaries[j].FolderUID {
			return summaries[i].FolderUID < summaries[j].FolderUID
		}

		return summaries[i].Group < summaries[j].Group
	})

	return summaries
}

func printAlertRulesTable(dst io.Writer, rules models.ProvisionedAlertRules) error {
	tab := tabwriter.NewWriter(dst, 0, 4, 2, ' ', tabwriter.TabIndent|tabwriter.DiscardEmptyColumns)

	if _, err := fmt.Fprintln(tab, "UID\tFOLDER\tGROUP\tTITLE\tPAUSED"); err != nil {
		return err
	}

	for _, rule := range rules {
		if rule == nil {
			continue
		}

		if _, err := fmt.Fprintf(
			tab,
			"%s\t%s\t%s\t%s\t%t\n",
			rule.UID,
			stringValue(rule.FolderUID),
			stringValue(rule.RuleGroup),
			stringValue(rule.Title),
			rule.IsPaused,
		); err != nil {
			return err
		}
	}

	return tab.Flush()
}

func printAlertRuleGroupsTable(dst io.Writer, groups []alertRuleGroupSummary) error {
	tab := tabwriter.NewWriter(dst, 0, 4, 2, ' ', tabwriter.TabIndent|tabwriter.DiscardEmptyColumns)

	if _, err := fmt.Fprintln(tab, "FOLDER\tGROUP\tRULES"); err != nil {
		return err
	}

	for _, group := range groups {
		if _, err := fmt.Fprintf(tab, "%s\t%s\t%d\n", group.FolderUID, group.Group, group.RuleCount); err != nil {
			return err
		}
	}

	return tab.Flush()
}

func parseAlertRuleGroupRef(input string) (alertRuleGroupRef, error) {
	folderUID, group, ok := strings.Cut(input, "/")
	if !ok || strings.TrimSpace(folderUID) == "" || strings.TrimSpace(group) == "" {
		return alertRuleGroupRef{}, fmt.Errorf("invalid group reference '%s' (expected FOLDER_UID/GROUP)", input)
	}

	return alertRuleGroupRef{
		FolderUID: folderUID,
		Group:     group,
	}, nil
}

func readAlertRulesFromFile(path string) (models.ProvisionedAlertRules, error) {
	payload, err := readManifestPayload(path)
	if err != nil {
		return nil, err
	}

	return decodeAlertRulesPayload(payload)
}

func readAlertRuleGroupsFromFile(path string) ([]*models.AlertRuleGroup, error) {
	payload, err := readManifestPayload(path)
	if err != nil {
		return nil, err
	}

	return decodeAlertRuleGroupsPayload(payload)
}

func readManifestPayload(path string) (any, error) {
	codec, err := codecFromFilePath(path)
	if err != nil {
		return nil, err
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var payload any
	if err := codec.Decode(file, &payload); err != nil {
		return nil, fmt.Errorf("failed to parse '%s': %w", path, err)
	}

	return payload, nil
}

func decodeAlertRulesPayload(payload any) (models.ProvisionedAlertRules, error) {
	switch typed := payload.(type) {
	case map[string]any:
		if items, ok := typed["items"]; ok {
			return decodeAlertRulesPayload(items)
		}

		var rule models.ProvisionedAlertRule
		if err := decodePayload(typed, &rule); err != nil {
			return nil, err
		}

		return models.ProvisionedAlertRules{&rule}, nil
	case []any:
		var rules models.ProvisionedAlertRules
		if err := decodePayload(typed, &rules); err != nil {
			return nil, err
		}

		return rules, nil
	default:
		var rule models.ProvisionedAlertRule
		if err := decodePayload(payload, &rule); err != nil {
			return nil, fmt.Errorf("invalid alert rule payload: %w", err)
		}

		return models.ProvisionedAlertRules{&rule}, nil
	}
}

func decodeAlertRuleGroupsPayload(payload any) ([]*models.AlertRuleGroup, error) {
	switch typed := payload.(type) {
	case map[string]any:
		if items, ok := typed["items"]; ok {
			return decodeAlertRuleGroupsPayload(items)
		}

		var group models.AlertRuleGroup
		if err := decodePayload(typed, &group); err != nil {
			return nil, err
		}

		return []*models.AlertRuleGroup{&group}, nil
	case []any:
		groups := make([]*models.AlertRuleGroup, 0, len(typed))
		if err := decodePayload(typed, &groups); err != nil {
			return nil, err
		}

		return groups, nil
	default:
		var group models.AlertRuleGroup
		if err := decodePayload(payload, &group); err != nil {
			return nil, fmt.Errorf("invalid alert rule group payload: %w", err)
		}

		return []*models.AlertRuleGroup{&group}, nil
	}
}

func collectManifestFiles(paths []string) ([]string, error) {
	files := make([]string, 0)
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}

		if !info.IsDir() {
			if !isSupportedManifestFile(path) {
				return nil, fmt.Errorf("unsupported file extension for '%s' (expected .json, .yaml, or .yml)", path)
			}
			files = append(files, path)
			continue
		}

		if err := filepath.WalkDir(path, func(filePath string, dirEntry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if dirEntry.IsDir() {
				return nil
			}
			if !isSupportedManifestFile(filePath) {
				return nil
			}

			files = append(files, filePath)
			return nil
		}); err != nil {
			return nil, err
		}
	}

	sort.Strings(files)
	if len(files) == 0 {
		return nil, errors.New("no manifest files found")
	}

	return files, nil
}

func codecFromFilePath(path string) (format.Codec, error) {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		return format.NewJSONCodec(), nil
	case ".yaml", ".yml":
		return format.NewYAMLCodec(), nil
	default:
		return nil, fmt.Errorf("unsupported file extension for '%s'", path)
	}
}

func decodePayload(payload any, dst any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	if err := json.Unmarshal(raw, dst); err != nil {
		return err
	}

	return nil
}

func writeManifestFile(path string, codec format.Codec, obj any) error {
	if err := ensureDirectoryExists(filepath.Dir(path)); err != nil {
		return err
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	if err := codec.Encode(file, obj); err != nil {
		return err
	}

	return nil
}

func ensureDirectoryExists(path string) error {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return os.MkdirAll(path, 0755)
	}
	if err != nil {
		return err
	}

	if !info.IsDir() {
		return &os.PathError{Op: "mkdir", Path: path, Err: os.ErrInvalid}
	}

	return nil
}

func sortAlertRules(rules models.ProvisionedAlertRules) {
	sort.Slice(rules, func(i, j int) bool {
		left := rules[i]
		right := rules[j]
		if left == nil || right == nil {
			return left != nil
		}

		leftFolder := stringValue(left.FolderUID)
		rightFolder := stringValue(right.FolderUID)
		if leftFolder != rightFolder {
			return leftFolder < rightFolder
		}

		leftGroup := stringValue(left.RuleGroup)
		rightGroup := stringValue(right.RuleGroup)
		if leftGroup != rightGroup {
			return leftGroup < rightGroup
		}

		return left.UID < right.UID
	})
}

func stringValue(input *string) string {
	if input == nil {
		return ""
	}

	return *input
}

func disableProvenanceHeader(enabled bool) *string {
	if !enabled {
		return nil
	}

	value := "true"
	return &value
}

func isNotFoundError(err error) bool {
	apiErr := &goruntime.APIError{}
	if !errors.As(err, &apiErr) {
		return false
	}

	return apiErr.Code == 404
}

func sanitizeFileNamePart(input string) string {
	if input == "" {
		return "unnamed"
	}

	var builder strings.Builder
	for _, r := range input {
		switch {
		case r >= 'a' && r <= 'z':
			builder.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			builder.WriteRune(r)
		case r >= '0' && r <= '9':
			builder.WriteRune(r)
		case r == '-', r == '_', r == '.':
			builder.WriteRune(r)
		default:
			builder.WriteRune('_')
		}
	}

	clean := strings.Trim(builder.String(), "_")
	if clean == "" {
		return "unnamed"
	}

	return clean
}

func nextUniqueBaseName(used map[string]int, base string) string {
	count := used[base]
	if count == 0 {
		used[base] = 1
		return base
	}

	next := fmt.Sprintf("%s-%d", base, count+1)
	used[base] = count + 1
	return next
}

func isSupportedManifestFile(path string) bool {
	extension := strings.ToLower(filepath.Ext(path))
	return extension == ".json" || extension == ".yaml" || extension == ".yml"
}
