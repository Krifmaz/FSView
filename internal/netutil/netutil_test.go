package netutil

import (
	"net/netip"
	"strings"
	"testing"
)

const route = `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
vmbr0	00000000	0101A8C0	0003	0	0	0	00000000	0	0	0
vmbr0	0001A8C0	00000000	0001	0	0	0	00FFFFFF	0	0	0
`

func TestDefaultRoute(t *testing.T) {
	n, err := DefaultRouteInterface(strings.NewReader(route))
	if err != nil || n != "vmbr0" {
		t.Fatalf("%q %v", n, err)
	}
}

func TestResolve(t *testing.T) {
	lan := netip.MustParseAddr("192.168.1.20")
	l, err := ResolveListen([]string{"auto", "10.0.0.5", "127.0.0.1:9300"}, 9200, lan)
	if err != nil || strings.Join(l, ",") != "192.168.1.20:9200,10.0.0.5:9200,127.0.0.1:9300" {
		t.Fatalf("%v %v", l, err)
	}
	if _, err := ResolveListen([]string{"auto"}, 9200, netip.Addr{}); err == nil {
		t.Fatal("auto without LAN must fail, not fall back to 0.0.0.0")
	}
	allow, err := ResolveAllow([]string{"auto"}, netip.MustParsePrefix("192.168.1.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	for ip, want := range map[string]bool{
		"192.168.1.77": true, "100.101.102.103": true, "::ffff:192.168.1.5": true,
		"192.168.2.1": false, "8.8.8.8": false, "100.128.0.1": false, "127.0.0.1": false,
	} {
		if got := Allowed(netip.MustParseAddr(ip), allow); got != want {
			t.Errorf("%s allowed=%v want %v", ip, got, want)
		}
	}
	if _, err := ResolveAllow([]string{"nonsense"}, netip.Prefix{}); err == nil {
		t.Fatal("bad CIDR accepted")
	}
}
