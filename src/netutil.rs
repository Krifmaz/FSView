//! Default listen address and the client allow-list (LAN subnet plus the
//! Tailscale CGNAT range).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// The range Tailscale assigns addresses from.
pub const TAILSCALE_CIDR: &str = "100.64.0.0/10";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Prefix {
    pub addr: IpAddr,
    pub bits: u8,
}

impl Prefix {
    pub fn parse(s: &str) -> Result<Prefix, String> {
        let bad = || format!("invalid allow entry {s:?}");
        let (a, bits) = match s.split_once('/') {
            Some((a, b)) => (
                a.parse::<IpAddr>().map_err(|_| bad())?,
                Some(b.parse::<u8>().map_err(|_| bad())?),
            ),
            None => (s.parse::<IpAddr>().map_err(|_| bad())?, None),
        };
        let max = if a.is_ipv4() { 32 } else { 128 };
        let bits = bits.unwrap_or(max);
        if bits > max {
            return Err(bad());
        }
        Ok(Prefix {
            addr: mask(a, bits),
            bits,
        })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = unmap(ip);
        ip.is_ipv4() == self.addr.is_ipv4() && mask(ip, self.bits) == self.addr
    }
}

impl std::fmt::Display for Prefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.bits)
    }
}

impl serde::Serialize for Prefix {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

fn mask(ip: IpAddr, bits: u8) -> IpAddr {
    match ip {
        IpAddr::V4(v) => {
            let m = if bits == 0 {
                0
            } else {
                u32::MAX << (32 - bits as u32)
            };
            IpAddr::V4(Ipv4Addr::from(u32::from(v) & m))
        }
        IpAddr::V6(v) => {
            let m = if bits == 0 {
                0
            } else {
                u128::MAX << (128 - bits as u32)
            };
            IpAddr::V6((u128::from(v) & m).into())
        }
    }
}

pub fn unmap(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v) => v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        _ => ip,
    }
}

pub fn allowed(ip: IpAddr, prefixes: &[Prefix]) -> bool {
    prefixes.iter().any(|p| p.contains(ip))
}

/// Interface carrying the IPv4 default route, from /proc/net/route.
pub fn default_route_interface(route: &str) -> Option<String> {
    route.lines().find_map(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        (f.len() >= 8 && f[1] == "00000000" && f[7] == "00000000").then(|| f[0].to_string())
    })
}

/// First IPv4 address and its network on the default-route interface.
pub fn lan_address() -> Result<(Ipv4Addr, Prefix), String> {
    let route = std::fs::read_to_string("/proc/net/route").map_err(|e| e.to_string())?;
    let ifname = default_route_interface(&route).ok_or("no IPv4 default route")?;
    let addrs = nix::ifaddrs::getifaddrs().map_err(|e| e.to_string())?;
    for a in addrs {
        if a.interface_name != ifname {
            continue;
        }
        let (Some(addr), Some(mask)) = (a.address, a.netmask) else {
            continue;
        };
        let (Some(ip), Some(m)) = (addr.as_sockaddr_in(), mask.as_sockaddr_in()) else {
            continue;
        };
        let ip = ip.ip();
        let bits = u32::from(m.ip()).count_ones() as u8;
        return Ok((
            ip,
            Prefix {
                addr: mask_v4(ip, bits),
                bits,
            },
        ));
    }
    Err(format!("interface {ifname} has no IPv4 address"))
}

fn mask_v4(ip: Ipv4Addr, bits: u8) -> IpAddr {
    mask(IpAddr::V4(ip), bits)
}

/// Expands "auto" into the LAN address. Never produces a wildcard unless
/// one is configured explicitly.
pub fn resolve_listen(
    entries: &[String],
    port: u16,
    lan: Option<Ipv4Addr>,
) -> Result<Vec<SocketAddr>, String> {
    let mut out = Vec::new();
    for e in entries {
        if e == "auto" {
            let lan =
                lan.ok_or("listen = auto but no LAN address was detected; set listen explicitly")?;
            out.push(SocketAddr::new(IpAddr::V4(lan), port));
        } else if let Ok(sa) = e.parse::<SocketAddr>() {
            out.push(sa);
        } else {
            let ip: IpAddr = e
                .parse()
                .map_err(|_| format!("invalid listen address {e:?}"))?;
            out.push(SocketAddr::new(ip, port));
        }
    }
    Ok(out)
}

/// Expands "auto" into the LAN prefix and the Tailscale range.
pub fn resolve_allow(entries: &[String], lan: Option<Prefix>) -> Result<Vec<Prefix>, String> {
    let mut out = Vec::new();
    for e in entries {
        if e == "auto" {
            out.extend(lan);
            out.push(Prefix::parse(TAILSCALE_CIDR)?);
        } else {
            out.push(Prefix::parse(e)?);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route() {
        let r = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\nvmbr0\t00000000\t0101A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\nvmbr0\t0001A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\n";
        assert_eq!(default_route_interface(r).as_deref(), Some("vmbr0"));
    }

    #[test]
    fn resolve() {
        let lan: Ipv4Addr = "192.168.1.20".parse().unwrap();
        let l = resolve_listen(
            &["auto".into(), "10.0.0.5".into(), "127.0.0.1:9300".into()],
            9200,
            Some(lan),
        )
        .unwrap();
        assert_eq!(
            l.iter().map(|a| a.to_string()).collect::<Vec<_>>(),
            ["192.168.1.20:9200", "10.0.0.5:9200", "127.0.0.1:9300"]
        );
        assert!(
            resolve_listen(&["auto".into()], 9200, None).is_err(),
            "must not fall back to 0.0.0.0"
        );
        let allow = resolve_allow(
            &["auto".into()],
            Some(Prefix::parse("192.168.1.0/24").unwrap()),
        )
        .unwrap();
        for (ip, want) in [
            ("192.168.1.77", true),
            ("100.101.102.103", true),
            ("::ffff:192.168.1.5", true),
            ("192.168.2.1", false),
            ("8.8.8.8", false),
            ("100.128.0.1", false),
            ("127.0.0.1", false),
        ] {
            assert_eq!(allowed(ip.parse().unwrap(), &allow), want, "{ip}");
        }
        assert!(resolve_allow(&["nonsense".into()], None).is_err());
        assert_eq!(
            Prefix::parse("192.168.1.77/24").unwrap().to_string(),
            "192.168.1.0/24"
        );
    }
}
