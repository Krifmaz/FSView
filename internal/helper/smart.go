package helper

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/krifmaz/fsview/internal/proto"
	"github.com/krifmaz/fsview/internal/smart"
)

// smartChoice remembers which -d type works for a disk and the serial the
// disk reported natively, so pass-through answers can be verified.
type smartChoice struct {
	devtype string // "" = smartctl default
	serial  string // serial from the native (non pass-through) query
}

func (s *Server) cachedSmartType(dev string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.smartTypes[dev].devtype
}

func (s *Server) smartctl(ctx context.Context, dev, devtype string, wake bool, info bool) (*proto.SmartGetResult, *smart.Report, error) {
	args := []string{"-j"}
	if info {
		args = append(args, "-i")
	} else {
		args = append(args, "-a")
	}
	if !wake {
		args = append(args, "-n", "standby")
	}
	if devtype != "" {
		args = append(args, "-d", devtype)
	}
	args = append(args, "/dev/"+dev)
	res, err := s.run.Run(ctx, "smartctl", args...)
	if err != nil {
		return nil, nil, err
	}
	out := &proto.SmartGetResult{Device: dev, DevType: devtype, ExitStatus: res.ExitCode}
	if json.Valid(res.Stdout) {
		out.Raw = res.Stdout
	}
	rep, perr := smart.Parse(res.Stdout, devtype)
	if perr == nil {
		out.Standby = rep.Standby
	}
	return out, rep, nil
}

func normSerial(s string) string { return strings.ToUpper(strings.TrimSpace(s)) }

// smartGet queries a disk. For SCSI-looking disks with no ATA data it tries
// ATA pass-through (-d sat), which SATA disks behind SAS bridges need for
// real SMART data. Pass-through is only accepted when it reports the same
// serial number as the disk's own SCSI identity: some bridges route
// pass-through commands to a different drive.
func (s *Server) smartGet(ctx context.Context, dev string, wake bool) (*proto.SmartGetResult, error) {
	s.mu.Lock()
	choice, cached := s.smartTypes[dev]
	s.mu.Unlock()

	if cached && choice.devtype == "sat" {
		out, rep, err := s.smartctl(ctx, dev, "sat", wake, false)
		if err != nil {
			return nil, err
		}
		if rep == nil || rep.Standby || normSerial(rep.Serial) == choice.serial {
			return out, nil
		}
		// Serial changed (disk renamed or swapped): re-detect.
		s.mu.Lock()
		delete(s.smartTypes, dev)
		s.mu.Unlock()
	} else if cached {
		out, _, err := s.smartctl(ctx, dev, "", wake, false)
		return out, err
	}

	out, rep, err := s.smartctl(ctx, dev, "", wake, false)
	if err != nil {
		return nil, err
	}
	if rep == nil || rep.Standby || out.ExitStatus&0x3 != 0 {
		return out, nil
	}
	native := normSerial(rep.Serial)
	if rep.LooksLikeBridgedATA() {
		satOut, satRep, err := s.smartctl(ctx, dev, "sat", wake, false)
		if err == nil && satRep != nil && satRep.Protocol == "ATA" && len(satRep.Attributes) > 0 {
			if native != "" && normSerial(satRep.Serial) == native {
				s.mu.Lock()
				s.smartTypes[dev] = smartChoice{devtype: "sat", serial: native}
				s.mu.Unlock()
				return satOut, nil
			}
			s.logger.Printf("SAFETY: %s: ATA pass-through answered with serial %q but the disk reports %q; pass-through disabled for this disk", dev, satRep.Serial, rep.Serial)
			out.Raw = annotate(out.Raw, fmt.Sprintf("ATA pass-through (-d sat) answered with serial %s, but this disk reports %s. The bridge may route pass-through commands to another drive, so FSView will not use -d sat for %s.", satRep.Serial, rep.Serial, dev))
		}
	}
	s.mu.Lock()
	s.smartTypes[dev] = smartChoice{devtype: "", serial: native}
	s.mu.Unlock()
	return out, nil
}

// annotate adds a message to smartctl's JSON "smartctl.messages" list so
// the UI shows it next to the data.
func annotate(raw json.RawMessage, msg string) json.RawMessage {
	var doc map[string]any
	if json.Unmarshal(raw, &doc) != nil {
		return raw
	}
	sc, _ := doc["smartctl"].(map[string]any)
	if sc == nil {
		sc = map[string]any{}
		doc["smartctl"] = sc
	}
	msgs, _ := sc["messages"].([]any)
	sc["messages"] = append(msgs, map[string]any{"string": "FSView: " + msg, "severity": "warning"})
	b, err := json.Marshal(doc)
	if err != nil {
		return raw
	}
	return b
}

// verifyPassThrough confirms, right before a write, that -d sat still
// reaches the addressed disk.
func (s *Server) verifyPassThrough(ctx context.Context, dev string) error {
	_, native, err := s.smartctl(ctx, dev, "", true, true)
	if err != nil {
		return err
	}
	_, sat, err := s.smartctl(ctx, dev, "sat", true, true)
	if err != nil {
		return err
	}
	if native == nil || sat == nil || native.Serial == "" || normSerial(native.Serial) != normSerial(sat.Serial) {
		ns, ss := "", ""
		if native != nil {
			ns = native.Serial
		}
		if sat != nil {
			ss = sat.Serial
		}
		return fmt.Errorf("refusing: ATA pass-through to %s answered with serial %q but the disk reports %q", dev, ss, ns)
	}
	return nil
}
