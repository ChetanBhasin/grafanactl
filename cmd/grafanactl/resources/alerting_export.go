package resources

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/go-openapi/strfmt"
	goapi "github.com/grafana/grafana-openapi-client-go/client"
	"github.com/grafana/grafana-openapi-client-go/client/folders"
	"github.com/grafana/grafana-openapi-client-go/client/provisioning"
	"github.com/grafana/grafana-openapi-client-go/models"
)

type alertingFolderResolver struct {
	defaultOrgID int64
	groupToUIDs  map[string][]string
	titleToUIDs  map[string][]string
	uidSet       map[string]struct{}
	uidToTitle   map[string]string
}

type convertedAlertRuleGroup struct {
	Group      *models.AlertRuleGroup
	Ref        alertRuleGroupRef
	RulesCount int
}

func buildAlertingFolderResolver(ctx context.Context, client *goapi.GrafanaHTTPAPI) (alertingFolderResolver, error) {
	resolver := alertingFolderResolver{
		groupToUIDs: make(map[string][]string),
		titleToUIDs: make(map[string][]string),
		uidSet:      make(map[string]struct{}),
		uidToTitle:  make(map[string]string),
	}

	rules, err := listAlertRules(ctx, client.Provisioning)
	if err != nil {
		return alertingFolderResolver{}, err
	}

	for _, rule := range rules {
		if rule == nil {
			continue
		}

		if resolver.defaultOrgID == 0 && rule.OrgID != nil {
			resolver.defaultOrgID = *rule.OrgID
		}

		groupName := strings.TrimSpace(stringValue(rule.RuleGroup))
		folderUID := strings.TrimSpace(stringValue(rule.FolderUID))
		if groupName == "" || folderUID == "" {
			continue
		}

		resolver.groupToUIDs[groupName] = appendUniqueString(resolver.groupToUIDs[groupName], folderUID)
	}

	const maxPageSize int64 = 1000
	for page := int64(1); ; page++ {
		pageRef := page
		pageSize := maxPageSize
		params := folders.NewGetFoldersParamsWithContext(ctx).
			WithPage(&pageRef).
			WithLimit(&pageSize)

		response, getErr := client.Folders.GetFolders(params)
		if getErr != nil {
			return alertingFolderResolver{}, getErr
		}

		for _, folder := range response.Payload {
			if folder == nil {
				continue
			}

			title := strings.TrimSpace(folder.Title)
			uid := strings.TrimSpace(folder.UID)
			if title == "" || uid == "" {
				continue
			}

			resolver.uidSet[uid] = struct{}{}
			resolver.uidToTitle[uid] = title
			resolver.titleToUIDs[title] = appendUniqueString(resolver.titleToUIDs[title], uid)
		}

		if int64(len(response.Payload)) < maxPageSize {
			break
		}
	}

	return resolver, nil
}

func decodeAlertingFileExportPayload(payload any) (*models.AlertingFileExport, bool, error) {
	if _, ok := payload.(map[string]any); !ok {
		return nil, false, nil
	}

	var file models.AlertingFileExport
	if err := decodePayload(payload, &file); err != nil {
		return nil, false, err
	}

	if len(file.Groups) == 0 {
		return nil, false, nil
	}

	return &file, true, nil
}

func exportAlertRuleByUID(
	ctx context.Context,
	client provisioning.ClientService,
	uid string,
	outputFormat string,
) (*models.AlertingFileExport, error) {
	_ = outputFormat
	format := "json"
	params := provisioning.NewGetAlertRulesExportParamsWithContext(ctx).
		WithFormat(&format).
		WithRuleUID(&uid)

	response, err := client.GetAlertRulesExport(params)
	if err != nil {
		return nil, err
	}

	return response.Payload, nil
}

func exportAlertRuleGroupByRef(
	ctx context.Context,
	client provisioning.ClientService,
	ref alertRuleGroupRef,
	outputFormat string,
) (*models.AlertingFileExport, error) {
	_ = outputFormat
	format := "json"
	params := provisioning.NewGetAlertRuleGroupExportParamsWithContext(ctx).
		WithFolderUID(ref.FolderUID).
		WithGroup(ref.Group).
		WithFormat(&format)

	response, err := client.GetAlertRuleGroupExport(params)
	if err != nil {
		return nil, err
	}

	return response.Payload, nil
}

func convertAlertingFileToRuleGroups(
	alertingFile *models.AlertingFileExport,
	resolver alertingFolderResolver,
) ([]convertedAlertRuleGroup, error) {
	if alertingFile == nil {
		return nil, errors.New("alerting file is nil")
	}

	groups := make([]convertedAlertRuleGroup, 0, len(alertingFile.Groups))
	for _, exportGroup := range alertingFile.Groups {
		if exportGroup == nil {
			continue
		}

		folderUID, err := resolver.resolveFolderUID(exportGroup.Folder, exportGroup.Name)
		if err != nil {
			return nil, err
		}

		ruleGroup, ruleCount, err := convertAlertRuleGroupExport(exportGroup, folderUID, resolver.defaultOrgID)
		if err != nil {
			return nil, err
		}

		groups = append(groups, convertedAlertRuleGroup{
			Group: ruleGroup,
			Ref: alertRuleGroupRef{
				FolderUID: folderUID,
				Group:     exportGroup.Name,
			},
			RulesCount: ruleCount,
		})
	}

	sort.Slice(groups, func(i, j int) bool {
		if groups[i].Ref.FolderUID != groups[j].Ref.FolderUID {
			return groups[i].Ref.FolderUID < groups[j].Ref.FolderUID
		}

		return groups[i].Ref.Group < groups[j].Ref.Group
	})

	return groups, nil
}

func convertAlertRuleGroupExport(
	exportGroup *models.AlertRuleGroupExport,
	folderUID string,
	defaultOrgID int64,
) (*models.AlertRuleGroup, int, error) {
	if exportGroup == nil {
		return nil, 0, errors.New("alert rule group export is nil")
	}

	groupName := strings.TrimSpace(exportGroup.Name)
	if groupName == "" {
		return nil, 0, errors.New("alert rule group export has empty name")
	}

	interval, err := parseGroupInterval(exportGroup.Interval)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid interval for group '%s': %w", groupName, err)
	}

	orgID := exportGroup.OrgID
	if orgID == 0 {
		orgID = defaultOrgID
	}
	if orgID == 0 {
		return nil, 0, fmt.Errorf("missing orgId in group '%s'", groupName)
	}

	rules := make([]*models.ProvisionedAlertRule, 0, len(exportGroup.Rules))
	for _, exportRule := range exportGroup.Rules {
		if exportRule == nil {
			continue
		}

		rule, convertErr := convertAlertRuleExport(exportRule, folderUID, groupName, orgID)
		if convertErr != nil {
			return nil, 0, fmt.Errorf("could not convert rule in group '%s': %w", groupName, convertErr)
		}

		rules = append(rules, rule)
	}

	return &models.AlertRuleGroup{
		FolderUID: folderUID,
		Title:     groupName,
		Interval:  interval,
		Rules:     rules,
	}, len(rules), nil
}

func convertAlertRuleExport(
	exportRule *models.AlertRuleExport,
	folderUID string,
	groupName string,
	orgID int64,
) (*models.ProvisionedAlertRule, error) {
	if exportRule == nil {
		return nil, errors.New("alert rule export is nil")
	}

	title := strings.TrimSpace(exportRule.Title)
	if title == "" {
		return nil, errors.New("title is required")
	}

	condition := strings.TrimSpace(exportRule.Condition)
	if condition == "" {
		return nil, fmt.Errorf("rule '%s': condition is required", title)
	}

	forDuration, err := parseDuration(exportRule.For)
	if err != nil {
		return nil, fmt.Errorf("rule '%s': invalid for duration: %w", title, err)
	}

	keepFiringDuration, err := parseOptionalDuration(exportRule.KeepFiringFor)
	if err != nil {
		return nil, fmt.Errorf("rule '%s': invalid keepFiringFor duration: %w", title, err)
	}

	execErrState := strings.TrimSpace(exportRule.ExecErrState)
	if execErrState == "" {
		return nil, fmt.Errorf("rule '%s': execErrState is required", title)
	}

	noDataState := strings.TrimSpace(exportRule.NoDataState)
	if noDataState == "" {
		return nil, fmt.Errorf("rule '%s': noDataState is required", title)
	}

	ruleGroup := groupName
	folder := folderUID

	queries := make([]*models.AlertQuery, 0, len(exportRule.Data))
	for _, exportQuery := range exportRule.Data {
		query, convertErr := convertAlertQueryExport(exportQuery)
		if convertErr != nil {
			return nil, fmt.Errorf("rule '%s': invalid query: %w", title, convertErr)
		}

		queries = append(queries, query)
	}

	notificationSettings := convertNotificationSettingsExport(exportRule.NotificationSettings)
	record := convertRecordExport(exportRule.Record)

	return &models.ProvisionedAlertRule{
		UID:                         exportRule.UID,
		Title:                       &title,
		Condition:                   &condition,
		Data:                        queries,
		ExecErrState:                &execErrState,
		FolderUID:                   &folder,
		For:                         &forDuration,
		KeepFiringFor:               keepFiringDuration,
		Labels:                      exportRule.Labels,
		MissingSeriesEvalsToResolve: exportRule.MissingSeriesEvalsToResolve,
		NoDataState:                 &noDataState,
		NotificationSettings:        notificationSettings,
		OrgID:                       &orgID,
		Record:                      record,
		RuleGroup:                   &ruleGroup,
		Annotations:                 exportRule.Annotations,
		IsPaused:                    exportRule.IsPaused,
	}, nil
}

func convertAlertQueryExport(exportQuery *models.AlertQueryExport) (*models.AlertQuery, error) {
	if exportQuery == nil {
		return nil, errors.New("query is nil")
	}

	query := &models.AlertQuery{
		DatasourceUID: exportQuery.DatasourceUID,
		Model:         exportQuery.Model,
		QueryType:     exportQuery.QueryType,
		RefID:         exportQuery.RefID,
	}

	if exportQuery.RelativeTimeRange != nil {
		query.RelativeTimeRange = &models.RelativeTimeRange{
			From: models.Duration(exportQuery.RelativeTimeRange.From),
			To:   models.Duration(exportQuery.RelativeTimeRange.To),
		}
	}

	return query, nil
}

func convertNotificationSettingsExport(
	exportSettings *models.AlertRuleNotificationSettingsExport,
) *models.AlertRuleNotificationSettings {
	if exportSettings == nil {
		return nil
	}

	settings := &models.AlertRuleNotificationSettings{
		ActiveTimeIntervals: exportSettings.ActiveTimeIntervals,
		GroupBy:             exportSettings.GroupBy,
		GroupInterval:       exportSettings.GroupInterval,
		GroupWait:           exportSettings.GroupWait,
		MuteTimeIntervals:   exportSettings.MuteTimeIntervals,
		RepeatInterval:      exportSettings.RepeatInterval,
	}

	receiver := strings.TrimSpace(exportSettings.Receiver)
	if receiver != "" {
		settings.Receiver = &receiver
	}

	return settings
}

func convertRecordExport(exportRecord *models.AlertRuleRecordExport) *models.Record {
	if exportRecord == nil {
		return nil
	}

	record := &models.Record{
		TargetDatasourceUID: exportRecord.TargetDatasourceUID,
	}

	from := strings.TrimSpace(exportRecord.From)
	if from != "" {
		record.From = &from
	}

	metric := strings.TrimSpace(exportRecord.Metric)
	if metric != "" {
		record.Metric = &metric
	}

	return record
}

func parseDuration(value string) (strfmt.Duration, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return strfmt.Duration(0), errors.New("duration is required")
	}

	duration, err := time.ParseDuration(trimmed)
	if err != nil {
		return strfmt.Duration(0), err
	}

	return strfmt.Duration(duration), nil
}

func parseOptionalDuration(value string) (strfmt.Duration, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return strfmt.Duration(0), nil
	}

	duration, err := time.ParseDuration(trimmed)
	if err != nil {
		return strfmt.Duration(0), err
	}

	return strfmt.Duration(duration), nil
}

func parseGroupInterval(value string) (int64, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return 0, errors.New("interval is required")
	}

	duration, err := time.ParseDuration(trimmed)
	if err != nil {
		return 0, err
	}

	seconds := int64(duration / time.Second)
	if seconds <= 0 {
		return 0, fmt.Errorf("interval '%s' must be at least 1 second", value)
	}

	return seconds, nil
}

func listAlertingFolderTitlesByUID(ctx context.Context, client *goapi.GrafanaHTTPAPI) (map[string]string, error) {
	titles := make(map[string]string)

	const maxPageSize int64 = 1000
	for page := int64(1); ; page++ {
		pageRef := page
		pageSize := maxPageSize
		params := folders.NewGetFoldersParamsWithContext(ctx).
			WithPage(&pageRef).
			WithLimit(&pageSize)

		response, err := client.Folders.GetFolders(params)
		if err != nil {
			return nil, err
		}

		for _, folder := range response.Payload {
			if folder == nil {
				continue
			}

			uid := strings.TrimSpace(folder.UID)
			title := strings.TrimSpace(folder.Title)
			if uid == "" || title == "" {
				continue
			}

			titles[uid] = title
		}

		if int64(len(response.Payload)) < maxPageSize {
			break
		}
	}

	return titles, nil
}

func hydrateExportFolderNames(
	alertingFile *models.AlertingFileExport,
	fallbackFolderUID string,
	folderTitlesByUID map[string]string,
) {
	if alertingFile == nil {
		return
	}

	fallbackFolderUID = strings.TrimSpace(fallbackFolderUID)
	fallbackFolder := ""
	if fallbackFolderUID != "" {
		fallbackFolder = strings.TrimSpace(folderTitlesByUID[fallbackFolderUID])
		if fallbackFolder == "" {
			fallbackFolder = fallbackFolderUID
		}
	}

	if fallbackFolder == "" {
		return
	}

	for _, group := range alertingFile.Groups {
		if group == nil {
			continue
		}

		if strings.TrimSpace(group.Folder) == "" {
			group.Folder = fallbackFolder
		}
	}
}

func normalizeAlertingFileIntegralNumbers(alertingFile *models.AlertingFileExport) {
	if alertingFile == nil {
		return
	}

	for _, group := range alertingFile.Groups {
		if group == nil {
			continue
		}

		for _, rule := range group.Rules {
			if rule == nil {
				continue
			}

			for _, query := range rule.Data {
				if query == nil {
					continue
				}

				query.Model = normalizeIntegralNumbers(query.Model)
			}
		}
	}
}

func normalizeIntegralNumbers(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		for key, nested := range typed {
			typed[key] = normalizeIntegralNumbers(nested)
		}
		return typed
	case []any:
		for index, nested := range typed {
			typed[index] = normalizeIntegralNumbers(nested)
		}
		return typed
	case float64:
		if math.IsNaN(typed) || math.IsInf(typed, 0) {
			return typed
		}
		if typed == math.Trunc(typed) && typed >= float64(math.MinInt64) && typed <= float64(math.MaxInt64) {
			return int64(typed)
		}
		return typed
	default:
		return value
	}
}

func appendUniqueString(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}

	return append(values, value)
}

func (resolver alertingFolderResolver) resolveFolderUID(folderReference string, groupName string) (string, error) {
	folderReference = strings.TrimSpace(folderReference)
	groupName = strings.TrimSpace(groupName)

	if folderReference != "" {
		if _, ok := resolver.uidSet[folderReference]; ok {
			return folderReference, nil
		}

		if exactMatches, ok := resolver.titleToUIDs[folderReference]; ok {
			if len(exactMatches) == 1 {
				return exactMatches[0], nil
			}
			if len(exactMatches) > 1 {
				return "", fmt.Errorf("folder '%s' is ambiguous", folderReference)
			}
		}

		var caseInsensitiveMatches []string
		for title, uids := range resolver.titleToUIDs {
			if strings.EqualFold(title, folderReference) {
				for _, uid := range uids {
					caseInsensitiveMatches = appendUniqueString(caseInsensitiveMatches, uid)
				}
			}
		}

		if len(caseInsensitiveMatches) == 1 {
			return caseInsensitiveMatches[0], nil
		}
		if len(caseInsensitiveMatches) > 1 {
			return "", fmt.Errorf("folder '%s' is ambiguous", folderReference)
		}
	}

	if groupName != "" {
		groupMatches := resolver.groupToUIDs[groupName]
		if len(groupMatches) == 1 {
			return groupMatches[0], nil
		}
		if len(groupMatches) > 1 {
			return "", fmt.Errorf("group '%s' exists in multiple folders; set folder explicitly", groupName)
		}
	}

	if folderReference == "" {
		return "", fmt.Errorf("missing folder for group '%s'", groupName)
	}

	return "", fmt.Errorf("folder '%s' was not found", folderReference)
}
