package inventory

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// LsblkColumns are the columns requested from lsblk (with -b for byte sizes).
const LsblkColumns = "NAME,KNAME,PATH,PKNAME,TYPE,SIZE,MODEL,SERIAL,VENDOR,REV,TRAN,HCTL,WWN,ROTA,RM,RO,STATE," +
	"PTTYPE,FSTYPE,FSVER,LABEL,UUID,PARTUUID,PARTLABEL,PARTTYPENAME,PARTN,MOUNTPOINTS,FSSIZE,FSUSED,FSAVAIL"

// LsblkArgs is the full argument list for lsblk.
var LsblkArgs = []string{"-J", "-b", "-o", LsblkColumns}

// flexInt accepts JSON numbers, numeric strings and null.
type flexInt struct {
	V     int64
	Valid bool
}

func (f *flexInt) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if string(b) == "null" {
		return nil
	}
	s := strings.Trim(string(b), `"`)
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		// Human sizes (from lsblk without -b) are tolerated but ignored.
		return nil
	}
	f.V, f.Valid = n, true
	return nil
}

// flexBool accepts true/false, "0"/"1", 0/1 and null.
type flexBool bool

func (f *flexBool) UnmarshalJSON(b []byte) error {
	switch strings.Trim(strings.TrimSpace(string(b)), `"`) {
	case "true", "1":
		*f = true
	default:
		*f = false
	}
	return nil
}

// flexStr accepts strings, numbers and null.
type flexStr string

func (f *flexStr) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if string(b) == "null" {
		*f = ""
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*f = flexStr(strings.TrimSpace(s))
		return nil
	}
	*f = flexStr(strings.TrimSpace(string(b)))
	return nil
}

type lsblkDev struct {
	Name         flexStr    `json:"name"`
	KName        flexStr    `json:"kname"`
	Path         flexStr    `json:"path"`
	PKName       flexStr    `json:"pkname"`
	Type         flexStr    `json:"type"`
	Size         flexInt    `json:"size"`
	Model        flexStr    `json:"model"`
	Serial       flexStr    `json:"serial"`
	Vendor       flexStr    `json:"vendor"`
	Rev          flexStr    `json:"rev"`
	Tran         flexStr    `json:"tran"`
	HCTL         flexStr    `json:"hctl"`
	WWN          flexStr    `json:"wwn"`
	Rota         flexBool   `json:"rota"`
	RM           flexBool   `json:"rm"`
	RO           flexBool   `json:"ro"`
	State        flexStr    `json:"state"`
	PTType       flexStr    `json:"pttype"`
	FSType       flexStr    `json:"fstype"`
	FSVer        flexStr    `json:"fsver"`
	Label        flexStr    `json:"label"`
	UUID         flexStr    `json:"uuid"`
	PartUUID     flexStr    `json:"partuuid"`
	PartLabel    flexStr    `json:"partlabel"`
	PartTypeName flexStr    `json:"parttypename"`
	PartN        flexInt    `json:"partn"`
	Mountpoints  []*string  `json:"mountpoints"`
	Mountpoint   *string    `json:"mountpoint"`
	FSSize       flexInt    `json:"fssize"`
	FSUsed       flexInt    `json:"fsused"`
	FSAvail      flexInt    `json:"fsavail"`
	Children     []lsblkDev `json:"children"`
}

func (d *lsblkDev) mounts() []string {
	var out []string
	seen := map[string]bool{}
	add := func(s *string) {
		if s != nil && *s != "" && !seen[*s] {
			seen[*s] = true
			out = append(out, *s)
		}
	}
	for _, m := range d.Mountpoints {
		add(m)
	}
	add(d.Mountpoint)
	return out
}

func (d *lsblkDev) usage() *Usage {
	if !d.FSSize.Valid {
		return nil
	}
	return &Usage{SizeBytes: d.FSSize.V, UsedBytes: d.FSUsed.V, AvailBytes: d.FSAvail.V}
}

func (d *lsblkDev) toNode() Node {
	n := Node{
		Name:         string(d.Name),
		KName:        string(d.KName),
		Path:         string(d.Path),
		Type:         string(d.Type),
		SizeBytes:    d.Size.V,
		FSType:       string(d.FSType),
		FSVersion:    string(d.FSVer),
		Label:        string(d.Label),
		UUID:         string(d.UUID),
		PartUUID:     string(d.PartUUID),
		PartLabel:    string(d.PartLabel),
		PartTypeName: string(d.PartTypeName),
		PartNumber:   int(d.PartN.V),
		ReadOnly:     bool(d.RO),
		Mounts:       d.mounts(),
		Usage:        d.usage(),
	}
	if n.KName == "" {
		n.KName = n.Name
	}
	if n.Path == "" {
		n.Path = "/dev/" + n.Name
	}
	for i := range d.Children {
		n.Children = append(n.Children, d.Children[i].toNode())
	}
	return n
}

// ParseLsblk converts lsblk -J output into disks. Only whole disks (and
// loop devices when includeLoop is set) become top-level entries.
func ParseLsblk(data []byte, includeLoop bool) ([]Disk, error) {
	var doc struct {
		BlockDevices []lsblkDev `json:"blockdevices"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse lsblk: %w", err)
	}
	var disks []Disk
	for i := range doc.BlockDevices {
		d := &doc.BlockDevices[i]
		typ := string(d.Type)
		name := string(d.Name)
		switch {
		case typ == "disk" && !strings.HasPrefix(name, "zram"):
		case typ == "loop" && includeLoop && d.Size.V > 0:
		default:
			continue
		}
		disk := Disk{
			Name:       name,
			Path:       string(d.Path),
			Type:       typ,
			Model:      DisplayModel(string(d.Vendor), string(d.Model)),
			Vendor:     string(d.Vendor),
			Serial:     string(d.Serial),
			WWN:        string(d.WWN),
			Revision:   string(d.Rev),
			SizeBytes:  d.Size.V,
			Transport:  string(d.Tran),
			HCTL:       string(d.HCTL),
			Rotational: bool(d.Rota),
			Removable:  bool(d.RM),
			ReadOnly:   bool(d.RO),
			State:      string(d.State),
			PTType:     string(d.PTType),
			FSType:     string(d.FSType),
			FSVersion:  string(d.FSVer),
			Label:      string(d.Label),
			UUID:       string(d.UUID),
			Mounts:     d.mounts(),
			Usage:      d.usage(),
		}
		if disk.Path == "" {
			disk.Path = "/dev/" + name
		}
		if typ == "loop" {
			disk.Transport = "loop"
		}
		for j := range d.Children {
			disk.Children = append(disk.Children, d.Children[j].toNode())
		}
		disks = append(disks, disk)
	}
	return disks, nil
}

// DisplayModel combines vendor and model the way people expect to read it.
// Generic vendor strings like "ATA" are dropped.
func DisplayModel(vendor, model string) string {
	vendor = strings.TrimSpace(vendor)
	model = strings.TrimSpace(model)
	switch strings.ToUpper(vendor) {
	case "", "ATA", "NVME":
		return model
	}
	if strings.HasPrefix(strings.ToUpper(model), strings.ToUpper(vendor)) {
		return model
	}
	return vendor + " " + model
}
