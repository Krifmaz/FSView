// Package netutil picks the default listen address and the client
// allow-list (LAN subnet plus the Tailscale CGNAT range).
package netutil

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
)

// TailscaleCIDR is the CGNAT range Tailscale assigns addresses from.
const TailscaleCIDR = "100.64.0.0/10"

// DefaultRouteInterface parses /proc/net/route for the IPv4 default route.
func DefaultRouteInterface(r io.Reader) (string, error) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) >= 8 && f[1] == "00000000" && f[7] == "00000000" {
			return f[0], nil
		}
	}
	return "", fmt.Errorf("no IPv4 default route")
}

// LANAddress returns the first IPv4 address (and its network) on the
// interface that carries the default route.
func LANAddress() (netip.Addr, netip.Prefix, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return netip.Addr{}, netip.Prefix{}, err
	}
	defer f.Close()
	name, err := DefaultRouteInterface(f)
	if err != nil {
		return netip.Addr{}, netip.Prefix{}, err
	}
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return netip.Addr{}, netip.Prefix{}, err
	}
	addrs, err := ifc.Addrs()
	if err != nil {
		return netip.Addr{}, netip.Prefix{}, err
	}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok || ipn.IP.To4() == nil {
			continue
		}
		p, err := netip.ParsePrefix(ipn.String())
		if err != nil {
			continue
		}
		return p.Addr(), p.Masked(), nil
	}
	return netip.Addr{}, netip.Prefix{}, fmt.Errorf("interface %s has no IPv4 address", name)
}

// ResolveListen expands "auto" entries into host:port strings. It never
// produces a wildcard address unless one is configured explicitly.
func ResolveListen(entries []string, port int, lan netip.Addr) ([]string, error) {
	var out []string
	for _, e := range entries {
		if e == "auto" {
			if !lan.IsValid() {
				return nil, fmt.Errorf("listen = auto but no LAN address was detected; set listen explicitly")
			}
			out = append(out, netip.AddrPortFrom(lan, uint16(port)).String())
			continue
		}
		if _, _, err := net.SplitHostPort(e); err == nil {
			out = append(out, e)
			continue
		}
		ip, err := netip.ParseAddr(e)
		if err != nil {
			return nil, fmt.Errorf("invalid listen address %q", e)
		}
		out = append(out, netip.AddrPortFrom(ip, uint16(port)).String())
	}
	return out, nil
}

// ResolveAllow expands "auto" into the LAN prefix and the Tailscale range.
func ResolveAllow(entries []string, lan netip.Prefix) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, e := range entries {
		if e == "auto" {
			if lan.IsValid() {
				out = append(out, lan)
			}
			out = append(out, netip.MustParsePrefix(TailscaleCIDR))
			continue
		}
		if !strings.Contains(e, "/") {
			a, err := netip.ParseAddr(e)
			if err != nil {
				return nil, fmt.Errorf("invalid allow entry %q", e)
			}
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
			continue
		}
		p, err := netip.ParsePrefix(e)
		if err != nil {
			return nil, fmt.Errorf("invalid allow entry %q", e)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// Allowed reports whether addr is inside any prefix.
func Allowed(addr netip.Addr, prefixes []netip.Prefix) bool {
	addr = addr.Unmap()
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
