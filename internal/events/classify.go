package events

import (
	"regexp"
	"strings"
	"time"
)

// Event is a classified disk-related kernel message.
type Event struct {
	Cursor       string    `json:"cursor"`
	Time         time.Time `json:"time"`
	BootID       string    `json:"boot_id"`
	MonotonicSec float64   `json:"monotonic_sec"`
	Category     string    `json:"category"`
	Severity     string    `json:"severity"` // error | warn | info
	Device       string    `json:"device,omitempty"`
	Message      string    `json:"message"`
	// Late is set for "device appeared" events well after boot.
	Late bool `json:"late,omitempty"`
}

const (
	CatIOError  = "io_error"
	CatReset    = "reset"
	CatLinkDown = "link_down"
	CatAppeared = "appeared"
	CatRemoved  = "removed"
	CatFS       = "filesystem"
	CatMedium   = "medium_error"
)

type rule struct {
	re       *regexp.Regexp
	category string
	severity string
}

var rules = []rule{
	{regexp.MustCompile(`(?i)(Medium Error|Unrecovered read error|critical medium error|Sense Key : Medium Error)`), CatMedium, "error"},
	{regexp.MustCompile(`(?i)(I/O error|blk_update_request|Buffer I/O error|end_request: I/O error|failed command: (READ|WRITE)|UNC\b)`), CatIOError, "error"},
	{regexp.MustCompile(`(?i)(EXT4-fs error|EXT4-fs warning|XFS \(.*\): (Corruption|metadata I/O error|Filesystem has been shut down)|BTRFS (error|critical|warning)|ntfs3?.*error|FAT-fs .*error|remounting filesystem read-only|Remounting filesystem read-only)`), CatFS, "error"},
	{regexp.MustCompile(`(?i)(SATA link down|link is down|phy.* link down|detected link down|ata\d+: (link|SATA) .*down)`), CatLinkDown, "warn"},
	{regexp.MustCompile(`(?i)(hard resetting link|soft resetting link|attempting task abort|task abort|device_reset|target reset|host reset|bus reset|resetting controller|nvme.*reset|controller is down|timeout, (aborting|resetting)|log_info\(0x31)`), CatReset, "warn"},
	{regexp.MustCompile(`(Attached SCSI (removable )?disk|nvme\d+n\d+: p\d|nvme nvme\d+: \d+/\d+/\d+ default/read/poll queues)`), CatAppeared, "info"},
	{regexp.MustCompile(`(?i)(removing handle|Synchronizing SCSI cache|device offlined|rejecting I/O to offline device|nvme.*removing)`), CatRemoved, "warn"},
	{regexp.MustCompile(`(EXT4-fs \(.*\): mounted filesystem|XFS \(.*\): Mounting|BTRFS info .*: (disk space caching|use .* compression)|EXT4-fs \(.*\): unmounting)`), CatFS, "info"},
}

var deviceREs = []*regexp.Regexp{
	regexp.MustCompile(`\[(sd[a-z]+)\]`),
	regexp.MustCompile(`\b(nvme\d+n\d+(p\d+)?)\b`),
	regexp.MustCompile(`\b(nvme\d+)\b`),
	regexp.MustCompile(`dev (sd[a-z]+\d*)\b`),
	regexp.MustCompile(`\((sd[a-z]+\d*|dm-\d+|md\d+|nvme\d+n\d+p?\d*)\)`),
	regexp.MustCompile(`\b(sd \d+:\d+:\d+:\d+)\b`),
	regexp.MustCompile(`\b(ata\d+(\.\d+)?)\b`),
	regexp.MustCompile(`\b(sd[a-z]+)\b`),
}

// Classify returns an Event for disk-related kernel messages.
// lateAfterSec marks "appeared" events later than this as late (0 disables).
func Classify(e Entry, lateAfterSec float64) (Event, bool) {
	for _, r := range rules {
		if !r.re.MatchString(e.Message) {
			continue
		}
		ev := Event{
			Cursor:       e.Cursor,
			Time:         e.Time(),
			BootID:       e.BootID,
			MonotonicSec: e.MonotonicSec(),
			Category:     r.category,
			Severity:     r.severity,
			Message:      strings.TrimSpace(e.Message),
			Device:       extractDevice(e.Message),
		}
		if ev.Category == CatAppeared && lateAfterSec > 0 && ev.MonotonicSec > lateAfterSec {
			ev.Late = true
			ev.Severity = "warn"
		}
		return ev, true
	}
	return Event{}, false
}

func extractDevice(msg string) string {
	for _, re := range deviceREs {
		if m := re.FindStringSubmatch(msg); m != nil {
			return m[1]
		}
	}
	return ""
}

var attachRE = regexp.MustCompile(`\[(sd[a-z]+)\] Attached SCSI`)
var nvmePartRE = regexp.MustCompile(`^\s*(nvme\d+n\d+): p\d`)

// AttachedDevice returns the disk name if the message announces a disk.
func AttachedDevice(msg string) string {
	if m := attachRE.FindStringSubmatch(msg); m != nil {
		return m[1]
	}
	if m := nvmePartRE.FindStringSubmatch(msg); m != nil {
		return m[1]
	}
	return ""
}
