package handlers

import (
	"net/http"
	"sort"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/shorebird-server/internal/db"
)

const (
	activeHoursLookbackDays  = 30
	activeHoursMinDays       = 7
	activeHoursWindowLength  = 2
	metricsDefaultWindowDays = 30
	versionActiveWindowDays  = 30
	millisecondsTimestampMin = int64(1000000000000)
)

// MetricsHandler handles app metrics endpoints.
type MetricsHandler struct {
	DB db.Store
}

type activeHourEntry struct {
	HourUTC              int     `json:"hour_utc"`
	AverageActiveDevices float64 `json:"average_active_devices"`
}

type activeHoursResponse struct {
	Hourly                       []activeHourEntry `json:"hourly"`
	RecommendedWindowStartUTC    *int              `json:"recommended_window_start_utc"`
	RecommendedWindowLengthHours int               `json:"recommended_window_length_hours"`
	BusiestHourUTC               *int              `json:"busiest_hour_utc"`
	LookbackDays                 int               `json:"lookback_days"`
	AsOf                         time.Time         `json:"as_of"`
}

type metricsRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

type uniqueUsersTimeSeriesEntry struct {
	Period      time.Time `json:"period"`
	UniqueUsers int       `json:"unique_users"`
}

type uniqueUsersBreakdownEntry struct {
	GroupBy     string                       `json:"group_by"`
	GroupValue  string                       `json:"group_value"`
	UniqueUsers int                          `json:"unique_users"`
	TimeSeries  []uniqueUsersTimeSeriesEntry `json:"time_series,omitempty"`
}

type uniqueUsersWindow struct {
	UniqueUsers int                          `json:"unique_users"`
	Range       metricsRange                 `json:"range"`
	TimeSeries  []uniqueUsersTimeSeriesEntry `json:"time_series,omitempty"`
}

type uniqueUsersCurrentWindow struct {
	UniqueUsers int                          `json:"unique_users"`
	Range       metricsRange                 `json:"range"`
	TimeSeries  []uniqueUsersTimeSeriesEntry `json:"time_series,omitempty"`
	Breakdown   []uniqueUsersBreakdownEntry  `json:"breakdown,omitempty"`
}

type uniqueUsersResponse struct {
	AsOf        time.Time                `json:"as_of"`
	Granularity *string                  `json:"granularity"`
	Current     uniqueUsersCurrentWindow `json:"current"`
	Previous    *uniqueUsersWindow       `json:"previous"`
}

type versionDistributionEntry struct {
	ReleaseVersion *string `json:"release_version"`
	DeviceCount    int     `json:"device_count"`
	Percentage     float64 `json:"percentage"`
}

type versionDistributionResponse struct {
	Entries          []versionDistributionEntry `json:"entries"`
	TotalDevices     int                        `json:"total_devices"`
	ActiveWindowDays int                        `json:"active_window_days"`
	AsOf             time.Time                  `json:"as_of"`
}

type patchAdoptionPoint struct {
	Period      *time.Time `json:"period"`
	Devices     int        `json:"devices"`
	Target      int        `json:"target"`
	AdoptionPct float64    `json:"adoption_pct"`
}

type patchAdoptionEntry struct {
	PatchNumber     int                  `json:"patch_number"`
	TargetPlatforms []string             `json:"target_platforms"`
	IsRolledBack    bool                 `json:"is_rolled_back"`
	Series          []patchAdoptionPoint `json:"series"`
}

type patchAdoptionResponse struct {
	ReleaseVersion string               `json:"release_version"`
	IsLatest       bool                 `json:"is_latest"`
	Granularity    *string              `json:"granularity"`
	Range          metricsRange         `json:"range"`
	AsOf           time.Time            `json:"as_of"`
	Patches        []patchAdoptionEntry `json:"patches"`
}

// GetActiveHours handles GET /api/v1/apps/{appId}/metrics/active-hours.
func (h *MetricsHandler) GetActiveHours(w http.ResponseWriter, r *http.Request) {
	appID, err := uuid.Parse(chi.URLParam(r, "appId"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid app ID", nil)
		return
	}
	if _, ok := requireAppAccess(w, r, h.DB, appID, false); !ok {
		return
	}

	now := time.Now().UTC()
	since := now.AddDate(0, 0, -activeHoursLookbackDays)
	events, err := h.DB.ListPatchEventActivity(
		r.Context(),
		appID,
		since.Unix(),
		since.UnixMilli(),
	)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to load active hours", nil)
		return
	}

	type hourDayKey struct {
		hour int
		day  string
	}
	hourDayClients := make(map[hourDayKey]map[string]struct{})
	daysSeen := make(map[string]struct{})
	for _, event := range events {
		t := eventTime(event.Timestamp)
		if t.Before(since) || t.After(now) {
			continue
		}
		day := t.Format("2006-01-02")
		daysSeen[day] = struct{}{}
		key := hourDayKey{hour: t.Hour(), day: day}
		if _, ok := hourDayClients[key]; !ok {
			hourDayClients[key] = make(map[string]struct{})
		}
		hourDayClients[key][event.ClientID] = struct{}{}
	}

	averages := make([]float64, 24)
	for hour := 0; hour < 24; hour++ {
		var total int
		for day := 0; day < activeHoursLookbackDays; day++ {
			key := hourDayKey{
				hour: hour,
				day:  now.AddDate(0, 0, -day).Format("2006-01-02"),
			}
			total += len(hourDayClients[key])
		}
		averages[hour] = float64(total) / float64(activeHoursLookbackDays)
	}

	hourly := make([]activeHourEntry, 24)
	for hour := 0; hour < 24; hour++ {
		hourly[hour] = activeHourEntry{
			HourUTC:              hour,
			AverageActiveDevices: averages[hour],
		}
	}

	var recommendedStart *int
	var busiestHour *int
	if len(daysSeen) >= activeHoursMinDays {
		start := lowestActivityWindowStart(averages, activeHoursWindowLength)
		busiest := busiestHourUTC(averages)
		recommendedStart = &start
		busiestHour = &busiest
	}

	respondJSON(w, http.StatusOK, activeHoursResponse{
		Hourly:                       hourly,
		RecommendedWindowStartUTC:    recommendedStart,
		RecommendedWindowLengthHours: activeHoursWindowLength,
		BusiestHourUTC:               busiestHour,
		LookbackDays:                 activeHoursLookbackDays,
		AsOf:                         now,
	})
}

// GetUniqueUsers handles GET /api/v1/apps/{appId}/metrics/unique-users.
func (h *MetricsHandler) GetUniqueUsers(w http.ResponseWriter, r *http.Request) {
	appID, ok := h.authorizeMetricsRequest(w, r)
	if !ok {
		return
	}
	now := time.Now().UTC()
	currentRange := metricRangeFromQuery(r, now)
	window := currentRange.End.Sub(currentRange.Start)
	previousRange := metricsRange{
		Start: currentRange.Start.Add(-window),
		End:   currentRange.Start,
	}
	granularity := validGranularity(r.URL.Query().Get("granularity"))
	groupBy := r.URL.Query().Get("group_by")

	events, err := h.DB.ListPatchEventActivity(r.Context(), appID, previousRange.Start.Unix(), previousRange.Start.UnixMilli())
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to load unique users", nil)
		return
	}

	current := uniqueUsersCurrentWindow{
		UniqueUsers: countUniqueDevices(eventsInRange(events, currentRange)),
		Range:       currentRange,
	}
	previous := &uniqueUsersWindow{
		UniqueUsers: countUniqueDevices(eventsInRange(events, previousRange)),
		Range:       previousRange,
	}
	if granularity != nil {
		current.TimeSeries = uniqueUsersSeries(events, currentRange, *granularity)
		previous.TimeSeries = uniqueUsersSeries(events, previousRange, *granularity)
	}
	if groupBy == "platform" {
		current.Breakdown = uniqueUsersPlatformBreakdown(eventsInRange(events, currentRange), currentRange, granularity)
	}

	respondJSON(w, http.StatusOK, uniqueUsersResponse{
		AsOf:        now,
		Granularity: granularity,
		Current:     current,
		Previous:    previous,
	})
}

// GetVersionDistribution handles GET /api/v1/apps/{appId}/metrics/version-distribution.
func (h *MetricsHandler) GetVersionDistribution(w http.ResponseWriter, r *http.Request) {
	appID, ok := h.authorizeMetricsRequest(w, r)
	if !ok {
		return
	}
	now := time.Now().UTC()
	since := now.AddDate(0, 0, -versionActiveWindowDays)
	events, err := h.DB.ListPatchEventActivity(r.Context(), appID, since.Unix(), since.UnixMilli())
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to load version distribution", nil)
		return
	}

	latestByDevice := map[string]db.PatchEventActivityRow{}
	for _, event := range events {
		t := eventTime(event.Timestamp)
		if t.Before(since) || t.After(now) {
			continue
		}
		current, ok := latestByDevice[event.ClientID]
		if !ok || eventTime(current.Timestamp).Before(t) {
			latestByDevice[event.ClientID] = event
		}
	}
	counts := map[string]int{}
	for _, event := range latestByDevice {
		counts[event.ReleaseVersion]++
	}
	total := len(latestByDevice)
	entries := make([]versionDistributionEntry, 0, len(counts))
	for version, count := range counts {
		var pct float64
		if total > 0 {
			pct = float64(count) / float64(total)
		}
		versionCopy := version
		var versionPtr *string
		if versionCopy != "" {
			versionPtr = &versionCopy
		}
		entries = append(entries, versionDistributionEntry{
			ReleaseVersion: versionPtr,
			DeviceCount:    count,
			Percentage:     pct,
		})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].DeviceCount == entries[j].DeviceCount {
			if entries[i].ReleaseVersion == nil {
				return false
			}
			if entries[j].ReleaseVersion == nil {
				return true
			}
			return *entries[i].ReleaseVersion < *entries[j].ReleaseVersion
		}
		return entries[i].DeviceCount > entries[j].DeviceCount
	})

	respondJSON(w, http.StatusOK, versionDistributionResponse{
		Entries:          entries,
		TotalDevices:     total,
		ActiveWindowDays: versionActiveWindowDays,
		AsOf:             now,
	})
}

// GetPatchAdoption handles GET /api/v1/apps/{appId}/metrics/patch-adoption.
func (h *MetricsHandler) GetPatchAdoption(w http.ResponseWriter, r *http.Request) {
	appID, ok := h.authorizeMetricsRequest(w, r)
	if !ok {
		return
	}
	now := time.Now().UTC()
	metricsRange := metricRangeFromQuery(r, now)
	granularity := validGranularity(r.URL.Query().Get("granularity"))
	releaseVersion := r.URL.Query().Get("release_version")
	isLatest := releaseVersion == ""

	if releaseVersion == "" {
		releases, err := h.DB.GetReleasesByAppID(r.Context(), appID, false)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "Failed to load releases", nil)
			return
		}
		if len(releases) > 0 {
			releaseVersion = releases[0].Version
		}
	}

	events, err := h.DB.ListPatchEventActivity(r.Context(), appID, metricsRange.Start.Unix(), metricsRange.Start.UnixMilli())
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to load patch adoption", nil)
		return
	}
	events = eventsInRange(events, metricsRange)
	if releaseVersion != "" {
		filtered := events[:0]
		for _, event := range events {
			if event.ReleaseVersion == releaseVersion {
				filtered = append(filtered, event)
			}
		}
		events = filtered
	}

	patchPlatforms := map[int]map[string]struct{}{}
	for _, event := range events {
		if event.PatchNumber <= 0 {
			continue
		}
		if _, ok := patchPlatforms[event.PatchNumber]; !ok {
			patchPlatforms[event.PatchNumber] = map[string]struct{}{}
		}
		if event.Platform != "" {
			patchPlatforms[event.PatchNumber][event.Platform] = struct{}{}
		}
	}
	patchNumbers := make([]int, 0, len(patchPlatforms))
	for patchNumber := range patchPlatforms {
		patchNumbers = append(patchNumbers, patchNumber)
	}
	sort.Ints(patchNumbers)

	entries := make([]patchAdoptionEntry, 0, len(patchNumbers))
	for _, patchNumber := range patchNumbers {
		platforms := sortedKeys(patchPlatforms[patchNumber])
		if len(platforms) == 0 {
			platforms = []string{"android", "ios", "linux", "macos", "windows"}
		}
		entries = append(entries, patchAdoptionEntry{
			PatchNumber:     patchNumber,
			TargetPlatforms: platforms,
			IsRolledBack:    false,
			Series:          patchAdoptionSeries(events, metricsRange, granularity, patchNumber, patchPlatforms[patchNumber]),
		})
	}

	respondJSON(w, http.StatusOK, patchAdoptionResponse{
		ReleaseVersion: releaseVersion,
		IsLatest:       isLatest,
		Granularity:    granularity,
		Range:          metricsRange,
		AsOf:           now,
		Patches:        entries,
	})
}

func (h *MetricsHandler) authorizeMetricsRequest(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	appID, err := uuid.Parse(chi.URLParam(r, "appId"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid app ID", nil)
		return uuid.Nil, false
	}
	if _, ok := requireAppAccess(w, r, h.DB, appID, false); !ok {
		return uuid.Nil, false
	}
	return appID, true
}

func eventTime(timestamp int64) time.Time {
	if timestamp >= millisecondsTimestampMin {
		return time.UnixMilli(timestamp).UTC()
	}
	return time.Unix(timestamp, 0).UTC()
}

func metricRangeFromQuery(r *http.Request, now time.Time) metricsRange {
	end := parseMetricTime(r.URL.Query().Get("end"), now)
	start := parseMetricTime(r.URL.Query().Get("start"), end.AddDate(0, 0, -metricsDefaultWindowDays))
	if !start.Before(end) {
		start = end.AddDate(0, 0, -metricsDefaultWindowDays)
	}
	return metricsRange{Start: start.UTC(), End: end.UTC()}
}

func parseMetricTime(value string, fallback time.Time) time.Time {
	if value == "" {
		return fallback.UTC()
	}
	if t, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return t.UTC()
	}
	if t, err := time.Parse("2006-01-02", value); err == nil {
		return t.UTC()
	}
	return fallback.UTC()
}

func validGranularity(value string) *string {
	switch value {
	case "hour", "day", "week":
		return &value
	default:
		return nil
	}
}

func eventsInRange(events []db.PatchEventActivityRow, metricRange metricsRange) []db.PatchEventActivityRow {
	result := make([]db.PatchEventActivityRow, 0, len(events))
	for _, event := range events {
		t := eventTime(event.Timestamp)
		if !t.Before(metricRange.Start) && t.Before(metricRange.End) {
			result = append(result, event)
		}
	}
	return result
}

func countUniqueDevices(events []db.PatchEventActivityRow) int {
	devices := map[string]struct{}{}
	for _, event := range events {
		devices[event.ClientID] = struct{}{}
	}
	return len(devices)
}

func uniqueUsersSeries(events []db.PatchEventActivityRow, metricRange metricsRange, granularity string) []uniqueUsersTimeSeriesEntry {
	buckets := map[time.Time]map[string]struct{}{}
	for _, event := range eventsInRange(events, metricRange) {
		period := bucketStart(eventTime(event.Timestamp), granularity)
		if _, ok := buckets[period]; !ok {
			buckets[period] = map[string]struct{}{}
		}
		buckets[period][event.ClientID] = struct{}{}
	}
	periods := make([]time.Time, 0, len(buckets))
	for period := range buckets {
		periods = append(periods, period)
	}
	sort.Slice(periods, func(i, j int) bool { return periods[i].Before(periods[j]) })
	series := make([]uniqueUsersTimeSeriesEntry, 0, len(periods))
	for _, period := range periods {
		series = append(series, uniqueUsersTimeSeriesEntry{Period: period, UniqueUsers: len(buckets[period])})
	}
	return series
}

func uniqueUsersPlatformBreakdown(events []db.PatchEventActivityRow, metricRange metricsRange, granularity *string) []uniqueUsersBreakdownEntry {
	byPlatform := map[string][]db.PatchEventActivityRow{}
	for _, event := range events {
		platform := event.Platform
		if platform == "" {
			platform = "unknown"
		}
		byPlatform[platform] = append(byPlatform[platform], event)
	}
	platforms := make([]string, 0, len(byPlatform))
	for platform := range byPlatform {
		platforms = append(platforms, platform)
	}
	sort.Strings(platforms)
	breakdown := make([]uniqueUsersBreakdownEntry, 0, len(platforms))
	for _, platform := range platforms {
		entry := uniqueUsersBreakdownEntry{
			GroupBy:     "platform",
			GroupValue:  platform,
			UniqueUsers: countUniqueDevices(byPlatform[platform]),
		}
		if granularity != nil {
			entry.TimeSeries = uniqueUsersSeries(byPlatform[platform], metricRange, *granularity)
		}
		breakdown = append(breakdown, entry)
	}
	return breakdown
}

func patchAdoptionSeries(events []db.PatchEventActivityRow, metricRange metricsRange, granularity *string, patchNumber int, platforms map[string]struct{}) []patchAdoptionPoint {
	if granularity == nil {
		devices, target := patchAdoptionCounts(events, patchNumber, platforms)
		return []patchAdoptionPoint{{Devices: devices, Target: target, AdoptionPct: adoptionPct(devices, target)}}
	}
	buckets := map[time.Time][]db.PatchEventActivityRow{}
	for _, event := range events {
		period := bucketStart(eventTime(event.Timestamp), *granularity)
		buckets[period] = append(buckets[period], event)
	}
	periods := make([]time.Time, 0, len(buckets))
	for period := range buckets {
		periods = append(periods, period)
	}
	sort.Slice(periods, func(i, j int) bool { return periods[i].Before(periods[j]) })
	series := make([]patchAdoptionPoint, 0, len(periods))
	for _, period := range periods {
		devices, target := patchAdoptionCounts(eventsInRange(buckets[period], metricRange), patchNumber, platforms)
		periodCopy := period
		series = append(series, patchAdoptionPoint{
			Period:      &periodCopy,
			Devices:     devices,
			Target:      target,
			AdoptionPct: adoptionPct(devices, target),
		})
	}
	return series
}

func patchAdoptionCounts(events []db.PatchEventActivityRow, patchNumber int, platforms map[string]struct{}) (int, int) {
	targetDevices := map[string]struct{}{}
	adoptedDevices := map[string]struct{}{}
	for _, event := range events {
		if len(platforms) > 0 {
			if _, ok := platforms[event.Platform]; !ok {
				continue
			}
		}
		targetDevices[event.ClientID] = struct{}{}
		if event.PatchNumber >= patchNumber {
			adoptedDevices[event.ClientID] = struct{}{}
		}
	}
	return len(adoptedDevices), len(targetDevices)
}

func adoptionPct(devices, target int) float64 {
	if target == 0 {
		return 0
	}
	return float64(devices) / float64(target)
}

func bucketStart(t time.Time, granularity string) time.Time {
	t = t.UTC()
	switch granularity {
	case "hour":
		return time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), 0, 0, 0, time.UTC)
	case "week":
		weekday := int(t.Weekday())
		if weekday == 0 {
			weekday = 7
		}
		day := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
		return day.AddDate(0, 0, -(weekday - 1))
	default:
		return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
	}
}

func sortedKeys(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for value := range values {
		keys = append(keys, value)
	}
	sort.Strings(keys)
	return keys
}

func lowestActivityWindowStart(averages []float64, length int) int {
	bestStart := 0
	bestTotal := windowTotal(averages, 0, length)
	for start := 1; start < len(averages); start++ {
		total := windowTotal(averages, start, length)
		if total < bestTotal {
			bestStart = start
			bestTotal = total
		}
	}
	return bestStart
}

func busiestHourUTC(averages []float64) int {
	busiest := 0
	for hour := 1; hour < len(averages); hour++ {
		if averages[hour] > averages[busiest] {
			busiest = hour
		}
	}
	return busiest
}

func windowTotal(averages []float64, start, length int) float64 {
	var total float64
	for offset := 0; offset < length; offset++ {
		total += averages[(start+offset)%len(averages)]
	}
	return total
}
