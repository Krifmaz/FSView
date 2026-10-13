// Package inventory builds a picture of the host's disks from lsblk, sysfs
// and findmnt, and decides which disks are protected system disks.
package inventory

import "time"

type Inventory struct {
	Hostname    string      `json:"hostname"`
	CollectedAt time.Time   `json:"collected_at"`
	Disks       []Disk      `json:"disks"`
	HBAs        []HBA       `json:"hbas"`
	Enclosures  []Enclosure `json:"enclosures"`
	Warnings    []string    `json:"warnings,omitempty"`
}

// Disk is a whole block device (type "disk", or "loop" in tests).
type Disk struct {
	Name       string   `json:"name"`
	Path       string   `json:"path"`
	Type       string   `json:"type"`
	Model      string   `json:"model"`
	Vendor     string   `json:"vendor,omitempty"`
	Serial     string   `json:"serial,omitempty"`
	WWN        string   `json:"wwn,omitempty"`
	Revision   string   `json:"revision,omitempty"`
	SizeBytes  int64    `json:"size_bytes"`
	Transport  string   `json:"transport"`
	HCTL       string   `json:"hctl,omitempty"`
	Rotational bool     `json:"rotational"`
	Removable  bool     `json:"removable"`
	ReadOnly   bool     `json:"read_only"`
	State      string   `json:"state,omitempty"`
	PTType     string   `json:"pttype,omitempty"`
	FSType     string   `json:"fstype,omitempty"`
	FSVersion  string   `json:"fsver,omitempty"`
	Label      string   `json:"label,omitempty"`
	UUID       string   `json:"uuid,omitempty"`
	Mounts     []string `json:"mountpoints,omitempty"`
	Usage      *Usage   `json:"usage,omitempty"`
	Children   []Node   `json:"children,omitempty"`
	Topology   Topology `json:"topology"`

	Protected        bool     `json:"protected"`
	ProtectedReasons []string `json:"protected_reasons,omitempty"`
}

// Node is anything below a disk: partitions, LVM volumes, md arrays, crypt.
type Node struct {
	Name         string   `json:"name"`
	KName        string   `json:"kname"`
	Path         string   `json:"path"`
	Type         string   `json:"type"`
	SizeBytes    int64    `json:"size_bytes"`
	FSType       string   `json:"fstype,omitempty"`
	FSVersion    string   `json:"fsver,omitempty"`
	Label        string   `json:"label,omitempty"`
	UUID         string   `json:"uuid,omitempty"`
	PartUUID     string   `json:"partuuid,omitempty"`
	PartLabel    string   `json:"partlabel,omitempty"`
	PartTypeName string   `json:"parttypename,omitempty"`
	PartNumber   int      `json:"partn,omitempty"`
	ReadOnly     bool     `json:"read_only,omitempty"`
	Mounts       []string `json:"mountpoints,omitempty"`
	Usage        *Usage   `json:"usage,omitempty"`
	Children     []Node   `json:"children,omitempty"`
}

type Usage struct {
	SizeBytes  int64 `json:"size_bytes"`
	UsedBytes  int64 `json:"used_bytes"`
	AvailBytes int64 `json:"avail_bytes"`
}

// Topology is where a disk physically lives.
type Topology struct {
	DevPath    string         `json:"devpath,omitempty"`
	HBA        string         `json:"hba,omitempty"` // PCI address
	HBAName    string         `json:"hba_name,omitempty"`
	HBADriver  string         `json:"hba_driver,omitempty"`
	SCSIHost   string         `json:"scsi_host,omitempty"`
	Port       string         `json:"port,omitempty"` // ata port, usb port...
	Expander   string         `json:"expander,omitempty"`
	EndDevice  string         `json:"end_device,omitempty"`
	SASAddress string         `json:"sas_address,omitempty"`
	BayID      *int           `json:"bay_id,omitempty"`
	Enclosure  *EnclosureSlot `json:"enclosure,omitempty"`
}

type EnclosureSlot struct {
	Enclosure string `json:"enclosure"` // e.g. "2:0:0:0"
	Component string `json:"component"` // e.g. "Slot 05"
	Slot      *int   `json:"slot,omitempty"`
	Status    string `json:"status,omitempty"`
	Fault     bool   `json:"fault,omitempty"`
	Locate    bool   `json:"locate,omitempty"`
}

type HBA struct {
	PCI    string   `json:"pci"`
	Name   string   `json:"name,omitempty"`
	Driver string   `json:"driver,omitempty"`
	Hosts  []string `json:"hosts,omitempty"`
	Disks  []string `json:"disks,omitempty"`
}

type Enclosure struct {
	ID         string               `json:"id"` // SCSI address of the SES device
	LogicalID  string               `json:"logical_id,omitempty"`
	Vendor     string               `json:"vendor,omitempty"`
	Model      string               `json:"model,omitempty"`
	Components []EnclosureComponent `json:"components"`
}

type EnclosureComponent struct {
	Name   string `json:"name"`
	Slot   *int   `json:"slot,omitempty"`
	Status string `json:"status,omitempty"`
	Fault  bool   `json:"fault,omitempty"`
	Locate bool   `json:"locate,omitempty"`
	Active bool   `json:"active,omitempty"`
	Disk   string `json:"disk,omitempty"`
}

// Walk calls fn for every node below the disk (depth first).
func (d *Disk) Walk(fn func(n *Node)) {
	var rec func(ns []Node)
	rec = func(ns []Node) {
		for i := range ns {
			fn(&ns[i])
			rec(ns[i].Children)
		}
	}
	rec(d.Children)
}

// FindDisk returns the disk with the given kernel name.
func (inv *Inventory) FindDisk(name string) *Disk {
	for i := range inv.Disks {
		if inv.Disks[i].Name == name {
			return &inv.Disks[i]
		}
	}
	return nil
}
