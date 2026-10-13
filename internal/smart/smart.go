// Package smart normalizes `smartctl -j -a` output for ATA, SCSI and NVMe
// devices and evaluates it against alert thresholds.
package smart

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

type Attribute struct {
	ID         int    `json:"id"`
	Name       string `json:"name"`
	Value      int    `json:"value"`
	Worst      int    `json:"worst"`
	Thresh     int    `json:"thresh"`
	Raw        int64  `json:"raw"`
	RawString  string `json:"raw_string"`
	WhenFailed string `json:"when_failed,omitempty"`
	Prefailure bool   `json:"prefailure"`
}

type SelfTest struct {
	Type          string `json:"type"`
	Status        string `json:"status"`
	Outcome       string `json:"outcome"` // passed | failed | aborted | running | unknown
	LifetimeHours *int64 `json:"lifetime_hours,omitempty"`
	LBA           *int64 `json:"lba,omitempty"`
	Detail        string `json:"detail,omitempty"`
}

type Running struct {
	Description      string `json:"description"`
	RemainingPercent *int   `json:"remaining_percent,omitempty"`
}

type Report struct {
	Device        string `json:"device"`
	DevType       string `json:"devtype"`
	Protocol      string `json:"protocol"` // ATA | SCSI | NVMe
	Model         string `json:"model"`
	Family        string `json:"family,omitempty"`
	Serial        string `json:"serial"`
	Firmware      string `json:"firmware,omitempty"`
	CapacityBytes int64  `json:"capacity_bytes"`
	RotationRate  int    `json:"rotation_rate"`

	SmartAvailable bool  `json:"smart_available"`
	SmartEnabled   bool  `json:"smart_enabled"`
	Passed         *bool `json:"passed,omitempty"`
	Standby        bool  `json:"standby"`

	TemperatureC   *int   `json:"temperature_c,omitempty"`
	TempTripC      *int   `json:"temp_trip_c,omitempty"`
	PowerOnHours   *int64 `json:"power_on_hours,omitempty"`
	PowerCycles    *int64 `json:"power_cycles,omitempty"`
	Reallocated    *int64 `json:"reallocated,omitempty"`
	Pending        *int64 `json:"pending,omitempty"`
	OfflineUncorr  *int64 `json:"offline_uncorrectable,omitempty"`
	ReportedUncorr *int64 `json:"reported_uncorrectable,omitempty"`
	CRCErrors      *int64 `json:"crc_errors,omitempty"`
	GrownDefects   *int64 `json:"grown_defects,omitempty"`
	Uncorrected    *int64 `json:"uncorrected_errors,omitempty"`

	NVMeCriticalWarning *int     `json:"nvme_critical_warning,omitempty"`
	NVMePercentUsed     *int     `json:"nvme_percent_used,omitempty"`
	NVMeSpare           *int     `json:"nvme_available_spare,omitempty"`
	NVMeSpareThreshold  *int     `json:"nvme_spare_threshold,omitempty"`
	NVMeMediaErrors     *int64   `json:"nvme_media_errors,omitempty"`
	NVMeUnsafeShutdowns *int64   `json:"nvme_unsafe_shutdowns,omitempty"`
	NVMeDataWrittenTB   *float64 `json:"nvme_data_written_tb,omitempty"`

	Attributes   []Attribute `json:"attributes,omitempty"`
	SelfTests    []SelfTest  `json:"self_tests,omitempty"`
	Running      *Running    `json:"self_test_running,omitempty"`
	ShortMinutes int         `json:"short_test_minutes,omitempty"`
	LongMinutes  int         `json:"long_test_minutes,omitempty"`

	ExitStatus int      `json:"exit_status"`
	Messages   []string `json:"messages,omitempty"`
	Notes      []string `json:"notes,omitempty"`
}

// raw mirrors the parts of smartctl's JSON we use.
type raw struct {
	Smartctl struct {
		ExitStatus int `json:"exit_status"`
		Messages   []struct {
			String   string `json:"string"`
			Severity string `json:"severity"`
		} `json:"messages"`
	} `json:"smartctl"`
	Device struct {
		Name     string `json:"name"`
		Type     string `json:"type"`
		Protocol string `json:"protocol"`
	} `json:"device"`
	ModelFamily  string `json:"model_family"`
	ModelName    string `json:"model_name"`
	ScsiVendor   string `json:"scsi_vendor"`
	ScsiProduct  string `json:"scsi_product"`
	Serial       string `json:"serial_number"`
	Firmware     string `json:"firmware_version"`
	ScsiRevision string `json:"scsi_revision"`
	UserCapacity struct {
		Bytes int64 `json:"bytes"`
	} `json:"user_capacity"`
	RotationRate int `json:"rotation_rate"`
	SmartSupport struct {
		Available bool `json:"available"`
		Enabled   bool `json:"enabled"`
	} `json:"smart_support"`
	SmartStatus *struct {
		Passed *bool `json:"passed"`
	} `json:"smart_status"`
	Temperature *struct {
		Current   *int `json:"current"`
		DriveTrip *int `json:"drive_trip"`
		OpLimit   *int `json:"op_limit_max"`
	} `json:"temperature"`
	PowerOnTime *struct {
		Hours *int64 `json:"hours"`
	} `json:"power_on_time"`
	PowerCycleCount *int64 `json:"power_cycle_count"`

	ATAData *struct {
		SelfTest *struct {
			Status *struct {
				Value            int    `json:"value"`
				String           string `json:"string"`
				RemainingPercent *int   `json:"remaining_percent"`
			} `json:"status"`
			PollingMinutes *struct {
				Short    int `json:"short"`
				Extended int `json:"extended"`
			} `json:"polling_minutes"`
		} `json:"self_test"`
	} `json:"ata_smart_data"`
	ATAAttributes *struct {
		Table []struct {
			ID         int    `json:"id"`
			Name       string `json:"name"`
			Value      int    `json:"value"`
			Worst      int    `json:"worst"`
			Thresh     int    `json:"thresh"`
			WhenFailed string `json:"when_failed"`
			Flags      struct {
				Prefailure bool `json:"prefailure"`
			} `json:"flags"`
			Raw struct {
				Value  int64  `json:"value"`
				String string `json:"string"`
			} `json:"raw"`
		} `json:"table"`
	} `json:"ata_smart_attributes"`
	ATASelfTestLog *struct {
		Standard *struct {
			Table []struct {
				Type struct {
					String string `json:"string"`
				} `json:"type"`
				Status struct {
					Value  int    `json:"value"`
					String string `json:"string"`
					Passed *bool  `json:"passed"`
				} `json:"status"`
				LifetimeHours *int64 `json:"lifetime_hours"`
				LBA           *int64 `json:"lba"`
			} `json:"table"`
		} `json:"standard"`
	} `json:"ata_smart_self_test_log"`

	ScsiGrownDefects *int64 `json:"scsi_grown_defect_list"`
	ScsiErrorLog     map[string]struct {
		TotalUncorrected *int64 `json:"total_uncorrected_errors"`
	} `json:"scsi_error_counter_log"`
	ScsiStartStop *struct {
		Accumulated *int64 `json:"accumulated_start_stop_cycles"`
	} `json:"scsi_start_stop_cycle_counter"`
	ScsiExtendedSeconds int `json:"scsi_extended_self_test_seconds"`

	NVMeHealth *struct {
		CriticalWarning  *int   `json:"critical_warning"`
		AvailableSpare   *int   `json:"available_spare"`
		SpareThreshold   *int   `json:"available_spare_threshold"`
		PercentageUsed   *int   `json:"percentage_used"`
		DataUnitsWritten *int64 `json:"data_units_written"`
		PowerCycles      *int64 `json:"power_cycles"`
		PowerOnHours     *int64 `json:"power_on_hours"`
		UnsafeShutdowns  *int64 `json:"unsafe_shutdowns"`
		MediaErrors      *int64 `json:"media_errors"`
	} `json:"nvme_smart_health_information_log"`
	NVMeSelfTestLog *struct {
		Current *struct {
			Value  int    `json:"value"`
			String string `json:"string"`
		} `json:"current_self_test_operation"`
		CompletionPercent *int `json:"current_self_test_completion_percent"`
		Table             []struct {
			Code struct {
				String string `json:"string"`
			} `json:"self_test_code"`
			Result struct {
				Value  int    `json:"value"`
				String string `json:"string"`
			} `json:"self_test_result"`
			PowerOnHours *int64 `json:"power_on_hours"`
			LBA          *int64 `json:"lba"`
		} `json:"table"`
	} `json:"nvme_self_test_log"`
}

type scsiSelfTest struct {
	Code struct {
		String string `json:"string"`
	} `json:"code"`
	Result struct {
		Value  int    `json:"value"`
		String string `json:"string"`
	} `json:"result"`
	PowerOnTime struct {
		Hours *int64 `json:"hours"`
	} `json:"power_on_time"`
	LBA *struct {
		Value *json.Number `json:"value"`
	} `json:"lba_first_failure"`
	SenseKey *struct {
		String string `json:"string"`
	} `json:"sense_key"`
}

func ip[T any](v T) *T { return &v }

// Parse normalizes smartctl JSON. devtype is the -d type that was used
// ("" for smartctl's default).
func Parse(data []byte, devtype string) (*Report, error) {
	var r raw
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("parse smartctl json: %w", err)
	}
	rep := &Report{
		Device:         r.Device.Name,
		DevType:        devtype,
		Protocol:       r.Device.Protocol,
		Model:          strings.Join(strings.Fields(r.ModelName), " "),
		Family:         r.ModelFamily,
		Serial:         r.Serial,
		Firmware:       r.Firmware,
		CapacityBytes:  r.UserCapacity.Bytes,
		RotationRate:   r.RotationRate,
		SmartAvailable: r.SmartSupport.Available,
		SmartEnabled:   r.SmartSupport.Enabled,
		ExitStatus:     r.Smartctl.ExitStatus,
		PowerCycles:    r.PowerCycleCount,
	}
	if rep.Firmware == "" {
		rep.Firmware = r.ScsiRevision
	}
	if devtype == "" {
		rep.DevType = r.Device.Type
	}
	for _, m := range r.Smartctl.Messages {
		rep.Messages = append(rep.Messages, m.String)
		u := strings.ToUpper(m.String)
		if strings.Contains(u, "STANDBY MODE") || strings.Contains(u, "SLEEP MODE") {
			rep.Standby = true
		}
	}
	if r.SmartStatus != nil {
		rep.Passed = r.SmartStatus.Passed
	}
	if r.Temperature != nil {
		rep.TemperatureC = r.Temperature.Current
		rep.TempTripC = r.Temperature.DriveTrip
		if rep.TempTripC == nil {
			rep.TempTripC = r.Temperature.OpLimit
		}
	}
	if r.PowerOnTime != nil {
		rep.PowerOnHours = r.PowerOnTime.Hours
	}

	switch strings.ToUpper(rep.Protocol) {
	case "ATA":
		rep.Protocol = "ATA"
		parseATA(&r, rep)
	case "NVME":
		rep.Protocol = "NVMe"
		parseNVMe(&r, rep)
	case "SCSI":
		rep.Protocol = "SCSI"
		parseSCSI(data, &r, rep)
	}
	return rep, nil
}

func parseATA(r *raw, rep *Report) {
	if r.ATAAttributes != nil {
		for _, a := range r.ATAAttributes.Table {
			attr := Attribute{ID: a.ID, Name: a.Name, Value: a.Value, Worst: a.Worst, Thresh: a.Thresh,
				Raw: a.Raw.Value, RawString: a.Raw.String, WhenFailed: a.WhenFailed, Prefailure: a.Flags.Prefailure}
			rep.Attributes = append(rep.Attributes, attr)
			v := a.Raw.Value
			switch a.ID {
			case 5:
				rep.Reallocated = ip(v)
			case 197:
				rep.Pending = ip(v)
			case 198:
				rep.OfflineUncorr = ip(v)
			case 187:
				rep.ReportedUncorr = ip(v)
			case 199:
				rep.CRCErrors = ip(v)
			case 9:
				if rep.PowerOnHours == nil {
					rep.PowerOnHours = ip(v)
				}
			case 12:
				if rep.PowerCycles == nil {
					rep.PowerCycles = ip(v)
				}
			case 194, 190:
				if rep.TemperatureC == nil {
					t := int(v & 0xff)
					rep.TemperatureC = &t
				}
			}
		}
	}
	if r.ATAData != nil && r.ATAData.SelfTest != nil {
		st := r.ATAData.SelfTest
		if st.Status != nil && st.Status.Value>>4 == 0xf {
			rep.Running = &Running{Description: st.Status.String, RemainingPercent: st.Status.RemainingPercent}
		}
		if st.PollingMinutes != nil {
			rep.ShortMinutes = st.PollingMinutes.Short
			rep.LongMinutes = st.PollingMinutes.Extended
		}
	}
	if r.ATASelfTestLog != nil && r.ATASelfTestLog.Standard != nil {
		for _, e := range r.ATASelfTestLog.Standard.Table {
			t := SelfTest{Type: e.Type.String, Status: e.Status.String, LifetimeHours: e.LifetimeHours, LBA: e.LBA}
			switch hi := e.Status.Value >> 4; {
			case hi == 0xf:
				t.Outcome = "running"
			case hi == 1 || hi == 2:
				t.Outcome = "aborted"
			case e.Status.Passed != nil && *e.Status.Passed:
				t.Outcome = "passed"
			case e.Status.Passed != nil && !*e.Status.Passed:
				t.Outcome = "failed"
			case hi == 0:
				t.Outcome = "passed"
			default:
				t.Outcome = "failed"
			}
			rep.SelfTests = append(rep.SelfTests, t)
		}
	}
}

func parseNVMe(r *raw, rep *Report) {
	if h := r.NVMeHealth; h != nil {
		rep.NVMeCriticalWarning = h.CriticalWarning
		rep.NVMePercentUsed = h.PercentageUsed
		rep.NVMeSpare = h.AvailableSpare
		rep.NVMeSpareThreshold = h.SpareThreshold
		rep.NVMeMediaErrors = h.MediaErrors
		rep.NVMeUnsafeShutdowns = h.UnsafeShutdowns
		if rep.PowerOnHours == nil {
			rep.PowerOnHours = h.PowerOnHours
		}
		if rep.PowerCycles == nil {
			rep.PowerCycles = h.PowerCycles
		}
		if h.DataUnitsWritten != nil {
			// One data unit is 1000 512-byte blocks.
			tb := float64(*h.DataUnitsWritten) * 512000 / 1e12
			rep.NVMeDataWrittenTB = &tb
		}
	}
	if l := r.NVMeSelfTestLog; l != nil {
		if l.Current != nil && l.Current.Value != 0 {
			rep.Running = &Running{Description: l.Current.String}
			if l.CompletionPercent != nil {
				rem := 100 - *l.CompletionPercent
				rep.Running.RemainingPercent = &rem
			}
		}
		for _, e := range l.Table {
			t := SelfTest{Type: e.Code.String, Status: e.Result.String, LifetimeHours: e.PowerOnHours, LBA: e.LBA}
			switch v := e.Result.Value; {
			case v == 0:
				t.Outcome = "passed"
			case v >= 1 && v <= 3:
				t.Outcome = "aborted"
			case v == 0xf:
				t.Outcome = "unknown"
			default:
				t.Outcome = "failed"
			}
			rep.SelfTests = append(rep.SelfTests, t)
		}
	}
	rep.ShortMinutes = 2
}

func parseSCSI(data []byte, r *raw, rep *Report) {
	if rep.Model == "" {
		rep.Model = strings.Join(strings.Fields(r.ScsiVendor+" "+r.ScsiProduct), " ")
	}
	rep.GrownDefects = r.ScsiGrownDefects
	var unc int64
	have := false
	for _, k := range []string{"read", "write", "verify"} {
		if e, ok := r.ScsiErrorLog[k]; ok && e.TotalUncorrected != nil {
			unc += *e.TotalUncorrected
			have = true
		}
	}
	if have {
		rep.Uncorrected = &unc
	}
	if r.ScsiStartStop != nil && rep.PowerCycles == nil {
		rep.PowerCycles = r.ScsiStartStop.Accumulated
	}
	if r.ScsiExtendedSeconds > 0 {
		rep.LongMinutes = (r.ScsiExtendedSeconds + 59) / 60
	}
	rep.ShortMinutes = 2

	// Self-test entries are top-level keys scsi_self_test_0..N, newest first.
	var all map[string]json.RawMessage
	_ = json.Unmarshal(data, &all)
	var keys []int
	for k := range all {
		if n, ok := strings.CutPrefix(k, "scsi_self_test_"); ok {
			if i, err := strconv.Atoi(n); err == nil {
				keys = append(keys, i)
			}
		}
	}
	sort.Ints(keys)
	var maxHours int64
	for _, i := range keys {
		var e scsiSelfTest
		if json.Unmarshal(all[fmt.Sprintf("scsi_self_test_%d", i)], &e) != nil {
			continue
		}
		t := SelfTest{Type: e.Code.String, Status: e.Result.String, LifetimeHours: e.PowerOnTime.Hours}
		if e.PowerOnTime.Hours != nil && *e.PowerOnTime.Hours > maxHours {
			maxHours = *e.PowerOnTime.Hours
		}
		switch v := e.Result.Value; {
		case v == 0:
			t.Outcome = "passed"
		case v == 1 || v == 2:
			t.Outcome = "aborted"
		case v == 15:
			t.Outcome = "running"
			rep.Running = &Running{Description: e.Result.String}
		default:
			t.Outcome = "failed"
		}
		if t.Outcome == "failed" {
			if e.SenseKey != nil {
				t.Detail = e.SenseKey.String
			}
			if e.LBA != nil && e.LBA.Value != nil {
				if n, err := e.LBA.Value.Int64(); err == nil {
					t.LBA = &n
				}
			}
		}
		rep.SelfTests = append(rep.SelfTests, t)
	}
	// SATA disks behind some SAS bridges report 0 power-on hours through
	// the SCSI log pages; the self-test log still carries real hours.
	if rep.PowerOnHours != nil && *rep.PowerOnHours == 0 && maxHours > 0 {
		rep.PowerOnHours = nil
		rep.Notes = append(rep.Notes, fmt.Sprintf(
			"Power-on hours are not reported through this SCSI bridge (last self-test logged at %d h). Try ATA pass-through (-d sat) for full SMART data.", maxHours))
	}
}

// LooksLikeBridgedATA reports whether a SCSI report is probably a SATA disk
// behind a SAS/USB bridge, where -d sat would give much better data.
func (r *Report) LooksLikeBridgedATA() bool {
	return r.Protocol == "SCSI" && len(r.Attributes) == 0
}
