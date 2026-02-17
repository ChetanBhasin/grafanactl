package resources

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/go-openapi/strfmt"
	"github.com/grafana/grafana-openapi-client-go/models"
	cmdconfig "github.com/grafana/grafanactl/cmd/grafanactl/config"
	cmdio "github.com/grafana/grafanactl/cmd/grafanactl/io"
	"github.com/grafana/grafanactl/internal/format"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

type alertingValidateOpts struct {
	IO cmdio.Options

	Paths       []string
	StopOnError bool
}

type alertingValidationFailure struct {
	File  string `json:"file" yaml:"file"`
	Error string `json:"error" yaml:"error"`
}

type alertingValidationSummary struct {
	Failures []alertingValidationFailure `json:"failures" yaml:"failures"`
}

type alertingResolverLoader func() (alertingFolderResolver, error)

type alertingValidationTextCodec struct{}

func alertingRulesValidateCmd(configOpts *cmdconfig.Options) *cobra.Command {
	opts := &alertingValidateOpts{}

	cmd := &cobra.Command{
		Use:   "validate",
		Args:  cobra.NoArgs,
		Short: "Validate alert rule manifests",
		Long:  "Validate alert rule manifests from local files.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runAlertingRulesValidate(cmd, configOpts, opts)
		},
	}

	opts.setup(cmd.Flags(), defaultAlertingRulesPath, "Paths on disk from which to read alert rule manifests")

	return cmd
}

func alertingGroupsValidateCmd(configOpts *cmdconfig.Options) *cobra.Command {
	opts := &alertingValidateOpts{}

	cmd := &cobra.Command{
		Use:   "validate",
		Args:  cobra.NoArgs,
		Short: "Validate alert rule group manifests",
		Long:  "Validate alert rule group manifests from local files.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runAlertingGroupsValidate(cmd, configOpts, opts)
		},
	}

	opts.setup(cmd.Flags(), defaultAlertingGroupsPath, "Paths on disk from which to read alert rule group manifests")

	return cmd
}

func (opts *alertingValidateOpts) setup(flags *pflag.FlagSet, defaultPath string, pathDescription string) {
	opts.IO.RegisterCustomCodec("text", &alertingValidationTextCodec{})
	opts.IO.DefaultFormat("text")
	opts.IO.BindFlags(flags)

	flags.StringSliceVarP(&opts.Paths, "path", "p", []string{defaultPath}, pathDescription)
	flags.BoolVar(&opts.StopOnError, "stop-on-error", opts.StopOnError, "Stop validating resources when an error occurs")
}

func (opts *alertingValidateOpts) Validate() error {
	if err := opts.IO.Validate(); err != nil {
		return err
	}

	if len(opts.Paths) == 0 {
		return errors.New("at least one path is required")
	}

	return nil
}

func (codec *alertingValidationTextCodec) Format() format.Format {
	return "text"
}

func (codec *alertingValidationTextCodec) Encode(output io.Writer, input any) error {
	//nolint:forcetypeassert
	summary := input.(*alertingValidationSummary)

	tab := tabwriter.NewWriter(output, 0, 4, 2, ' ', tabwriter.TabIndent|tabwriter.DiscardEmptyColumns)

	if _, err := fmt.Fprintln(tab, "FILE\tERROR"); err != nil {
		return err
	}

	for _, failure := range summary.Failures {
		if _, err := fmt.Fprintf(tab, "%s\t%s\n", failure.File, failure.Error); err != nil {
			return err
		}
	}

	return tab.Flush()
}

func (codec *alertingValidationTextCodec) Decode(io.Reader, any) error {
	return errors.New("codec does not support decoding")
}

func runAlertingRulesValidate(
	cmd *cobra.Command,
	configOpts *cmdconfig.Options,
	opts *alertingValidateOpts,
) error {
	if err := opts.Validate(); err != nil {
		return err
	}

	files, err := collectManifestFiles(opts.Paths)
	if err != nil {
		return err
	}

	summary, err := validateAlertingRulesFiles(files, newAlertingResolverLoader(cmd.Context(), configOpts), opts.StopOnError)
	if err != nil {
		return err
	}

	return writeAlertingValidationSummary(cmd, opts, &summary)
}

func runAlertingGroupsValidate(
	cmd *cobra.Command,
	configOpts *cmdconfig.Options,
	opts *alertingValidateOpts,
) error {
	if err := opts.Validate(); err != nil {
		return err
	}

	files, err := collectManifestFiles(opts.Paths)
	if err != nil {
		return err
	}

	summary, err := validateAlertingGroupsFiles(files, newAlertingResolverLoader(cmd.Context(), configOpts), opts.StopOnError)
	if err != nil {
		return err
	}

	return writeAlertingValidationSummary(cmd, opts, &summary)
}

func validateAlertingRulesFiles(
	files []string,
	resolverLoader alertingResolverLoader,
	stopOnError bool,
) (alertingValidationSummary, error) {
	summary := alertingValidationSummary{
		Failures: make([]alertingValidationFailure, 0),
	}

	for _, file := range files {
		failures, err := validateAlertingRulesFile(file, resolverLoader, stopOnError)
		if err != nil {
			return alertingValidationSummary{}, err
		}

		if len(failures) == 0 {
			continue
		}

		summary.Failures = append(summary.Failures, failures...)
		if stopOnError {
			break
		}
	}

	return summary, nil
}

func validateAlertingGroupsFiles(
	files []string,
	resolverLoader alertingResolverLoader,
	stopOnError bool,
) (alertingValidationSummary, error) {
	summary := alertingValidationSummary{
		Failures: make([]alertingValidationFailure, 0),
	}

	for _, file := range files {
		failures, err := validateAlertingGroupsFile(file, resolverLoader, stopOnError)
		if err != nil {
			return alertingValidationSummary{}, err
		}

		if len(failures) == 0 {
			continue
		}

		summary.Failures = append(summary.Failures, failures...)
		if stopOnError {
			break
		}
	}

	return summary, nil
}

func writeAlertingValidationSummary(cmd *cobra.Command, opts *alertingValidateOpts, summary *alertingValidationSummary) error {
	if len(summary.Failures) == 0 && opts.IO.OutputFormat == "text" {
		cmdio.Success(cmd.OutOrStdout(), "No errors found.")
		return nil
	}

	codec, err := opts.IO.Codec()
	if err != nil {
		return err
	}

	return codec.Encode(cmd.OutOrStdout(), summary)
}

func newAlertingResolverLoader(ctx context.Context, configOpts *cmdconfig.Options) alertingResolverLoader {
	resolverLoaded := false
	var resolver alertingFolderResolver

	return func() (alertingFolderResolver, error) {
		if resolverLoaded {
			return resolver, nil
		}

		client, err := loadGrafanaClient(ctx, configOpts)
		if err != nil {
			return alertingFolderResolver{}, err
		}

		resolver, err = buildAlertingFolderResolver(ctx, client)
		if err != nil {
			return alertingFolderResolver{}, err
		}

		resolverLoaded = true
		return resolver, nil
	}
}

func validateAlertingRulesFile(
	file string,
	resolverLoader alertingResolverLoader,
	stopOnError bool,
) ([]alertingValidationFailure, error) {
	payload, err := readManifestPayload(file)
	if err != nil {
		return []alertingValidationFailure{newAlertingValidationFailure(file, err)}, nil
	}

	alertingFile, isAlertingExport, err := decodeAlertingFileExportPayload(payload)
	if err != nil {
		return []alertingValidationFailure{
			newAlertingValidationFailure(file, fmt.Errorf("failed to decode alerting export payload: %w", err)),
		}, nil
	}

	if isAlertingExport {
		return validateAlertingExportRules(file, alertingFile, resolverLoader, stopOnError)
	}

	rules, err := decodeAlertRulesPayload(payload)
	if err != nil {
		return []alertingValidationFailure{
			newAlertingValidationFailure(file, fmt.Errorf("failed to decode alert rules payload: %w", err)),
		}, nil
	}

	failures := make([]alertingValidationFailure, 0)
	for i, rule := range rules {
		if rule == nil {
			continue
		}

		if validateErr := validateProvisionedAlertRule(rule); validateErr != nil {
			failures = append(failures, newAlertingValidationFailure(
				file,
				fmt.Errorf("invalid rule %s: %w", alertRuleDescriptor(rule, i), validateErr),
			))
			if stopOnError {
				return failures, nil
			}
		}
	}

	return failures, nil
}

func validateAlertingGroupsFile(
	file string,
	resolverLoader alertingResolverLoader,
	stopOnError bool,
) ([]alertingValidationFailure, error) {
	payload, err := readManifestPayload(file)
	if err != nil {
		return []alertingValidationFailure{newAlertingValidationFailure(file, err)}, nil
	}

	alertingFile, isAlertingExport, err := decodeAlertingFileExportPayload(payload)
	if err != nil {
		return []alertingValidationFailure{
			newAlertingValidationFailure(file, fmt.Errorf("failed to decode alerting export payload: %w", err)),
		}, nil
	}

	if isAlertingExport {
		return validateAlertingExportGroups(file, alertingFile, resolverLoader, stopOnError)
	}

	groups, err := decodeAlertRuleGroupsPayload(payload)
	if err != nil {
		return []alertingValidationFailure{
			newAlertingValidationFailure(file, fmt.Errorf("failed to decode alert rule groups payload: %w", err)),
		}, nil
	}

	failures := make([]alertingValidationFailure, 0)
	for i, group := range groups {
		if group == nil {
			continue
		}

		if validateErr := validateAlertRuleGroupManifest(group); validateErr != nil {
			failures = append(failures, newAlertingValidationFailure(
				file,
				fmt.Errorf("invalid group %s: %w", alertRuleGroupDescriptor(group, i), validateErr),
			))
			if stopOnError {
				return failures, nil
			}
		}
	}

	return failures, nil
}

func validateAlertingExportRules(
	file string,
	alertingFile *models.AlertingFileExport,
	resolverLoader alertingResolverLoader,
	stopOnError bool,
) ([]alertingValidationFailure, error) {
	resolver, err := resolverLoader()
	if err != nil {
		return nil, err
	}

	convertedGroups, err := convertAlertingFileToRuleGroups(alertingFile, resolver)
	if err != nil {
		return []alertingValidationFailure{newAlertingValidationFailure(file, err)}, nil
	}

	failures := make([]alertingValidationFailure, 0)
	for _, convertedGroup := range convertedGroups {
		if convertedGroup.Group == nil {
			continue
		}

		for i, rule := range convertedGroup.Group.Rules {
			if rule == nil {
				continue
			}

			if validateErr := validateProvisionedAlertRule(rule); validateErr != nil {
				failures = append(failures, newAlertingValidationFailure(
					file,
					fmt.Errorf(
						"invalid rule in group '%s/%s' at index %d: %w",
						convertedGroup.Ref.FolderUID,
						convertedGroup.Ref.Group,
						i,
						validateErr,
					),
				))
				if stopOnError {
					return failures, nil
				}
			}
		}
	}

	return failures, nil
}

func validateAlertingExportGroups(
	file string,
	alertingFile *models.AlertingFileExport,
	resolverLoader alertingResolverLoader,
	stopOnError bool,
) ([]alertingValidationFailure, error) {
	resolver, err := resolverLoader()
	if err != nil {
		return nil, err
	}

	convertedGroups, err := convertAlertingFileToRuleGroups(alertingFile, resolver)
	if err != nil {
		return []alertingValidationFailure{newAlertingValidationFailure(file, err)}, nil
	}

	failures := make([]alertingValidationFailure, 0)
	for _, convertedGroup := range convertedGroups {
		if convertedGroup.Group == nil {
			continue
		}

		if validateErr := validateAlertRuleGroupManifest(convertedGroup.Group); validateErr != nil {
			failures = append(failures, newAlertingValidationFailure(
				file,
				fmt.Errorf("invalid group '%s/%s': %w", convertedGroup.Ref.FolderUID, convertedGroup.Ref.Group, validateErr),
			))
			if stopOnError {
				return failures, nil
			}
		}
	}

	return failures, nil
}

func validateProvisionedAlertRule(rule *models.ProvisionedAlertRule) error {
	sanitizedRule := *rule
	sanitizedRule.ExecErrState = stringPointer(normalizeExecErrStateValue(stringValue(rule.ExecErrState)))
	sanitizedRule.NoDataState = stringPointer(normalizeNoDataStateValue(stringValue(rule.NoDataState)))

	if err := sanitizedRule.Validate(strfmt.Default); err != nil {
		return err
	}

	if strings.TrimSpace(stringValue(rule.Condition)) == "" {
		return errors.New("condition must not be empty")
	}

	if strings.TrimSpace(stringValue(rule.FolderUID)) == "" {
		return errors.New("folderUID must not be empty")
	}

	if strings.TrimSpace(stringValue(rule.RuleGroup)) == "" {
		return errors.New("ruleGroup must not be empty")
	}

	if strings.TrimSpace(stringValue(rule.Title)) == "" {
		return errors.New("title must not be empty")
	}

	return nil
}

func validateAlertRuleGroupManifest(group *models.AlertRuleGroup) error {
	if strings.TrimSpace(group.FolderUID) == "" {
		return errors.New("folderUid must not be empty")
	}

	if strings.TrimSpace(group.Title) == "" {
		return errors.New("title must not be empty")
	}

	for i, rule := range group.Rules {
		if rule == nil {
			continue
		}

		if err := validateProvisionedAlertRule(rule); err != nil {
			return fmt.Errorf("rules[%d]: %w", i, err)
		}
	}

	return nil
}

func alertRuleDescriptor(rule *models.ProvisionedAlertRule, index int) string {
	if uid := strings.TrimSpace(rule.UID); uid != "" {
		return fmt.Sprintf("uid '%s'", uid)
	}

	title := strings.TrimSpace(stringValue(rule.Title))
	if title != "" {
		return fmt.Sprintf("title '%s'", title)
	}

	return fmt.Sprintf("at index %d", index)
}

func alertRuleGroupDescriptor(group *models.AlertRuleGroup, index int) string {
	folderUID := strings.TrimSpace(group.FolderUID)
	title := strings.TrimSpace(group.Title)

	if folderUID != "" && title != "" {
		return fmt.Sprintf("'%s/%s'", folderUID, title)
	}

	if title != "" {
		return fmt.Sprintf("title '%s'", title)
	}

	return fmt.Sprintf("at index %d", index)
}

func newAlertingValidationFailure(file string, err error) alertingValidationFailure {
	return alertingValidationFailure{
		File:  file,
		Error: err.Error(),
	}
}

func stringPointer(value string) *string {
	return &value
}

func normalizeExecErrStateValue(input string) string {
	switch normalizeAlertStateToken(input) {
	case "ok":
		return models.ProvisionedAlertRuleExecErrStateOK
	case "alerting":
		return models.ProvisionedAlertRuleExecErrStateAlerting
	case "error":
		return models.ProvisionedAlertRuleExecErrStateError
	case "keeplast", "keeplaststate":
		return models.ProvisionedAlertRuleExecErrStateError
	default:
		return models.ProvisionedAlertRuleExecErrStateError
	}
}

func normalizeNoDataStateValue(input string) string {
	switch normalizeAlertStateToken(input) {
	case "ok":
		return models.ProvisionedAlertRuleNoDataStateOK
	case "alerting":
		return models.ProvisionedAlertRuleNoDataStateAlerting
	case "nodata":
		return models.ProvisionedAlertRuleNoDataStateNoData
	case "keeplast", "keeplaststate":
		return models.ProvisionedAlertRuleNoDataStateNoData
	default:
		return models.ProvisionedAlertRuleNoDataStateNoData
	}
}

func normalizeAlertStateToken(input string) string {
	normalized := strings.TrimSpace(strings.ToLower(input))
	normalized = strings.ReplaceAll(normalized, "_", "")
	normalized = strings.ReplaceAll(normalized, "-", "")
	normalized = strings.ReplaceAll(normalized, " ", "")

	return normalized
}
