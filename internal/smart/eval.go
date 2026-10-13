package smart

import "fmt"

// Thresholds are user-configurable alert levels.
type Thresholds struct {
	TempWarnC       int   `json:"temp_warn_c"`
	TempCritC       int   `json:"temp_crit_c"`
	TripMarginC     int   `json:"trip_margin_c"`
	ReallocatedWarn int64 `json:"reallocated_warn"`
	ReallocatedCrit int64 `json:"reallocated_crit"`
	PendingWarn     int64 `json:"pending_warn"`
	PendingCrit     int64 `json:"pending_crit"`
	UncorrWarn      int64 `json:"uncorrectable_warn"`
	CRCWarn         int64 `json:"crc_warn"`
	ErrorLogWarn    int64 `json:"error_log_warn"`
	NVMeUsedWarn    int   `json:"nvme_used_warn"`
	NVMeUsedCrit    int   `json:"nvme_used_crit"`
}

func DefaultThresholds() Thresholds {
	return Thresholds{
		TempWarnC: 50, TempCritC: 60, TripMarginC: 5,
		ReallocatedWarn: 1, ReallocatedCrit: 100,
		PendingWarn: 1, PendingCrit: 10,
		UncorrWarn: 1, CRCWarn: 1, ErrorLogWarn: 1,
		NVMeUsedWarn: 80, NVMeUsedCrit: 95,
	}
}

const (
	StatusOK      = "ok"
	StatusWarn    = "warn"
	StatusCrit    = "crit"
	StatusUnknown = "unknown"
)

type Finding struct {
	Level string `json:"level"`
	Text  string `json:"text"`
}

type Assessment struct {
	Status   string    `json:"status"`
	Findings []Finding `json:"findings,omitempty"`
}

func rank(s string) int {
	switch s {
	case StatusCrit:
		return 3
	case StatusWarn:
		return 2
	case StatusOK:
		return 1
	}
	return 0
}

// Worse returns the more severe of two statuses.
func Worse(a, b string) string {
	if rank(b) > rank(a) {
		return b
	}
	return a
}

// Evaluate checks a report against thresholds.
func Evaluate(r *Report, t Thresholds) Assessment {
	a := Assessment{Status: StatusOK}
	add := func(level, format string, args ...any) {
		a.Findings = append(a.Findings, Finding{Level: level, Text: fmt.Sprintf(format, args...)})
		a.Status = Worse(a.Status, level)
	}
	if r == nil {
		return Assessment{Status: StatusUnknown}
	}
	if !r.SmartAvailable {
		return Assessment{Status: StatusUnknown, Findings: []Finding{{StatusUnknown, "SMART not available"}}}
	}
	if r.Passed != nil && !*r.Passed {
		add(StatusCrit, "SMART overall health self-assessment: FAILED")
	}
	if r.ExitStatus&8 != 0 {
		add(StatusCrit, "smartctl reports the disk is failing (exit bit 3)")
	}
	if r.ExitStatus&16 != 0 {
		add(StatusWarn, "a prefail attribute is at or below its threshold (exit bit 4)")
	}
	for _, at := range r.Attributes {
		if at.WhenFailed == "now" {
			add(StatusCrit, "attribute %d %s failing now (value %d ≤ threshold %d)", at.ID, at.Name, at.Value, at.Thresh)
		}
	}

	if r.TemperatureC != nil {
		c := *r.TemperatureC
		switch {
		case r.TempTripC != nil && *r.TempTripC > 0 && c >= *r.TempTripC:
			add(StatusCrit, "temperature %d°C has reached the drive trip point %d°C", c, *r.TempTripC)
		case c >= t.TempCritC:
			add(StatusCrit, "temperature %d°C ≥ %d°C", c, t.TempCritC)
		case c >= t.TempWarnC:
			add(StatusWarn, "temperature %d°C ≥ %d°C", c, t.TempWarnC)
		case r.TempTripC != nil && *r.TempTripC > 0 && t.TripMarginC > 0 && c >= *r.TempTripC-t.TripMarginC:
			add(StatusWarn, "temperature %d°C is within %d°C of the drive trip point %d°C", c, *r.TempTripC-c, *r.TempTripC)
		}
	}

	level := func(v *int64, warn, crit int64, what string) {
		if v == nil || *v <= 0 {
			return
		}
		switch {
		case crit > 0 && *v >= crit:
			add(StatusCrit, "%s: %d", what, *v)
		case warn > 0 && *v >= warn:
			add(StatusWarn, "%s: %d", what, *v)
		}
	}
	level(r.Reallocated, t.ReallocatedWarn, t.ReallocatedCrit, "reallocated sectors")
	level(r.Pending, t.PendingWarn, t.PendingCrit, "pending sectors")
	level(r.OfflineUncorr, t.UncorrWarn, 0, "offline uncorrectable sectors")
	level(r.ReportedUncorr, t.UncorrWarn, 0, "reported uncorrectable errors")
	level(r.GrownDefects, t.ReallocatedWarn, t.ReallocatedCrit, "grown defect list entries")
	level(r.Uncorrected, t.UncorrWarn, 0, "uncorrected read/write errors")
	if r.CRCErrors != nil && t.CRCWarn > 0 && *r.CRCErrors >= t.CRCWarn {
		add(StatusWarn, "interface CRC errors: %d (check cable/backplane)", *r.CRCErrors)
	}

	if r.ATAErrorCount != nil && t.ErrorLogWarn > 0 && *r.ATAErrorCount >= t.ErrorLogWarn {
		msg := fmt.Sprintf("ATA error log: %d errors", *r.ATAErrorCount)
		if r.ATALastError != "" {
			msg += ", latest"
			if r.ATALastErrorHours != nil {
				msg += fmt.Sprintf(" at %d h", *r.ATALastErrorHours)
			}
			msg += ": " + r.ATALastError
		}
		add(StatusWarn, "%s", msg)
	}
	if r.NVMeCriticalWarning != nil && *r.NVMeCriticalWarning != 0 {
		add(StatusCrit, "NVMe critical warning flags: 0x%02x", *r.NVMeCriticalWarning)
	}
	if r.NVMePercentUsed != nil {
		switch u := *r.NVMePercentUsed; {
		case u >= t.NVMeUsedCrit:
			add(StatusCrit, "NVMe endurance used: %d%%", u)
		case u >= t.NVMeUsedWarn:
			add(StatusWarn, "NVMe endurance used: %d%%", u)
		}
	}
	if r.NVMeSpare != nil && r.NVMeSpareThreshold != nil && *r.NVMeSpare < *r.NVMeSpareThreshold {
		add(StatusCrit, "NVMe available spare %d%% below threshold %d%%", *r.NVMeSpare, *r.NVMeSpareThreshold)
	}
	if r.NVMeMediaErrors != nil && *r.NVMeMediaErrors > 0 {
		add(StatusWarn, "NVMe media errors: %d", *r.NVMeMediaErrors)
	}

	// The most recent finished (not aborted/running) self-test decides.
	for _, st := range r.SelfTests {
		if st.Outcome == "aborted" || st.Outcome == "running" || st.Outcome == "unknown" {
			continue
		}
		if st.Outcome == "failed" {
			msg := fmt.Sprintf("last self-test failed: %s", st.Status)
			if st.Detail != "" {
				msg += " (" + st.Detail + ")"
			}
			if st.LifetimeHours != nil {
				msg += fmt.Sprintf(" at %d h", *st.LifetimeHours)
			}
			add(StatusCrit, "%s", msg)
		}
		break
	}
	return a
}
