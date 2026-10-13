package helper

import (
	"context"
	"encoding/json"
	"os"
	"strings"

	"github.com/krifmaz/fsview/internal/proto"
	"github.com/krifmaz/fsview/internal/smart"
)

func serialOf(dev string) string {
	for _, p := range []string{"/sys/block/" + dev + "/device/serial", "/sys/block/" + dev + "/device/wwid"} {
		if b, err := os.ReadFile(p); err == nil {
			return strings.TrimSpace(string(b))
		}
	}
	return ""
}

func (s *Server) cachedSmartType(dev string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.smartTypes[dev+"|"+serialOf(dev)]
}

func (s *Server) setSmartType(dev, t string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.smartTypes[dev+"|"+serialOf(dev)] = t
}

func (s *Server) smartctl(ctx context.Context, dev, devtype string, wake bool) (*proto.SmartGetResult, *smart.Report, error) {
	args := []string{"-j", "-a"}
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

// smartGet queries a disk. For SCSI-looking disks with no ATA data it tries
// ATA pass-through (-d sat) once and remembers the better choice: SATA
// disks behind SAS expanders/bridges only expose real SMART that way.
func (s *Server) smartGet(ctx context.Context, dev string, wake bool) (*proto.SmartGetResult, error) {
	if t := s.cachedSmartType(dev); t != "" {
		if t == "-" {
			t = ""
		}
		out, _, err := s.smartctl(ctx, dev, t, wake)
		return out, err
	}
	out, rep, err := s.smartctl(ctx, dev, "", wake)
	if err != nil {
		return nil, err
	}
	if rep != nil && rep.LooksLikeBridgedATA() && !rep.Standby {
		satOut, satRep, err := s.smartctl(ctx, dev, "sat", wake)
		if err == nil && satRep != nil && satRep.Protocol == "ATA" && len(satRep.Attributes) > 0 && satOut.ExitStatus&0x3 == 0 {
			s.setSmartType(dev, "sat")
			return satOut, nil
		}
	}
	if rep != nil && !rep.Standby && out.ExitStatus&0x3 == 0 {
		s.setSmartType(dev, "-")
	}
	return out, nil
}
