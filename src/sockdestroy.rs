//! Kill established connections of given IPs through netlink `SOCK_DIAG` / `SOCK_DESTROY`
//! (what `ss -K` does). Needs CAP_NET_ADMIN and a kernel with CONFIG_INET_DIAG_DESTROY.

use std::{io, net::IpAddr};

const NETLINK_SOCK_DIAG: i32 = 4;
const SOCK_DIAG_BY_FAMILY: u16 = 20;
const SOCK_DESTROY: u16 = 21;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_ACK: u16 = 0x4;
const NLM_F_DUMP: u16 = 0x300;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;

const TCP_LISTEN: u8 = 10;
const HDR_LEN: usize = 16;
const REQ_LEN: usize = 56;
const ID_OFFSET: usize = 8; // inside inet_diag_req_v2
const ID_LEN: usize = 48;
const DIAG_MSG_ID_OFFSET: usize = 4; // inside inet_diag_msg
const DIAG_MSG_LEN: usize = 72;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct KillReport {
    pub matched: usize,
    pub destroyed: usize,
    pub failed: usize,
}

struct Nl {
    fd: i32,
    seq: u32,
}

impl Nl {
    fn open() -> io::Result<Self> {
        // SAFETY: plain socket(2) call.
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                NETLINK_SOCK_DIAG,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let tv = libc::timeval {
            tv_sec: 5,
            tv_usec: 0,
        };
        // SAFETY: valid pointer/len for SO_RCVTIMEO.
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as u32,
            )
        };
        Ok(Self { fd, seq: 1 })
    }

    fn send(&mut self, msg_type: u16, flags: u16, req: &[u8; REQ_LEN]) -> io::Result<()> {
        let mut buf = Vec::with_capacity(HDR_LEN + REQ_LEN);
        buf.extend_from_slice(&((HDR_LEN + REQ_LEN) as u32).to_ne_bytes());
        buf.extend_from_slice(&msg_type.to_ne_bytes());
        buf.extend_from_slice(&flags.to_ne_bytes());
        buf.extend_from_slice(&self.seq.to_ne_bytes());
        buf.extend_from_slice(&0u32.to_ne_bytes());
        buf.extend_from_slice(req);
        self.seq += 1;
        // SAFETY: buffer is valid for its length.
        let n = unsafe { libc::send(self.fd, buf.as_ptr() as *const libc::c_void, buf.len(), 0) };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        // SAFETY: buffer is valid for its length.
        let n = unsafe { libc::recv(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }
}

impl Drop for Nl {
    fn drop(&mut self) {
        // SAFETY: fd is owned by us.
        unsafe { libc::close(self.fd) };
    }
}

fn dump_request(family: u8, protocol: u8) -> [u8; REQ_LEN] {
    let mut r = [0u8; REQ_LEN];
    r[0] = family;
    r[1] = protocol;
    r[4..8].copy_from_slice(&u32::MAX.to_ne_bytes()); // all TCP states
    r
}

fn destroy_request(family: u8, protocol: u8, id: &[u8; ID_LEN]) -> [u8; REQ_LEN] {
    let mut r = [0u8; REQ_LEN];
    r[0] = family;
    r[1] = protocol;
    r[4..8].copy_from_slice(&u32::MAX.to_ne_bytes());
    r[ID_OFFSET..ID_OFFSET + ID_LEN].copy_from_slice(id);
    r
}

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// Address as stored in `inet_diag_sockid` (16 bytes, v4 uses the first 4).
fn matches(family: u8, id: &[u8; ID_LEN], targets: &[IpAddr]) -> bool {
    let src = &id[4..20];
    let dst = &id[20..36];
    targets.iter().any(|ip| match (family as i32, ip) {
        (libc::AF_INET, IpAddr::V4(v4)) => src[..4] == v4.octets() || dst[..4] == v4.octets(),
        (libc::AF_INET6, IpAddr::V6(v6)) => src == v6.octets() || dst == v6.octets(),
        (libc::AF_INET6, IpAddr::V4(v4)) => {
            // dual-stack sockets carry IPv4 peers as ::ffff:a.b.c.d
            let mut mapped = [0u8; 16];
            mapped[10] = 0xff;
            mapped[11] = 0xff;
            mapped[12..].copy_from_slice(&v4.octets());
            src == mapped || dst == mapped
        }
        _ => false,
    })
}

fn collect(
    nl: &mut Nl,
    family: u8,
    protocol: u8,
    targets: &[IpAddr],
) -> io::Result<Vec<(u8, u8, [u8; ID_LEN])>> {
    nl.send(
        SOCK_DIAG_BY_FAMILY,
        NLM_F_REQUEST | NLM_F_DUMP,
        &dump_request(family, protocol),
    )?;
    let mut found = Vec::new();
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = nl.recv(&mut buf)?;
        let mut off = 0;
        while off + HDR_LEN <= n {
            let len = u32::from_ne_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
            let ty = u16::from_ne_bytes(buf[off + 4..off + 6].try_into().unwrap());
            if len < HDR_LEN || off + len > n {
                break;
            }
            match ty {
                NLMSG_DONE => return Ok(found),
                NLMSG_ERROR => {
                    let code = i32::from_ne_bytes(
                        buf[off + HDR_LEN..off + HDR_LEN + 4].try_into().unwrap(),
                    );
                    return Err(io::Error::from_raw_os_error(-code));
                }
                _ if len >= HDR_LEN + DIAG_MSG_LEN => {
                    let body = &buf[off + HDR_LEN..off + len];
                    let fam = body[0];
                    let mut id = [0u8; ID_LEN];
                    id.copy_from_slice(&body[DIAG_MSG_ID_OFFSET..DIAG_MSG_ID_OFFSET + ID_LEN]);
                    let state = body[1];
                    let listening = state == TCP_LISTEN;
                    // unconnected UDP sockets (remote port 0) are listeners too
                    let unconnected =
                        protocol == libc::IPPROTO_UDP as u8 && id[2] == 0 && id[3] == 0;
                    if !listening && !unconnected && matches(fam, &id, targets) {
                        found.push((fam, protocol, id));
                    }
                }
                _ => {}
            }
            off += align4(len);
        }
    }
}

fn destroy(nl: &mut Nl, family: u8, protocol: u8, id: &[u8; ID_LEN]) -> io::Result<()> {
    nl.send(
        SOCK_DESTROY,
        NLM_F_REQUEST | NLM_F_ACK,
        &destroy_request(family, protocol, id),
    )?;
    let mut buf = [0u8; 4096];
    let n = nl.recv(&mut buf)?;
    if n >= HDR_LEN + 4 && u16::from_ne_bytes(buf[4..6].try_into().unwrap()) == NLMSG_ERROR {
        let code = i32::from_ne_bytes(buf[HDR_LEN..HDR_LEN + 4].try_into().unwrap());
        if code != 0 {
            return Err(io::Error::from_raw_os_error(-code));
        }
    }
    Ok(())
}

/// Destroys every TCP/UDP socket that has one of `ips` as local or remote address.
pub fn kill_sockets(ips: &[IpAddr]) -> io::Result<KillReport> {
    let mut report = KillReport::default();
    if ips.is_empty() {
        return Ok(report);
    }
    let mut nl = Nl::open()?;
    let mut victims = Vec::new();
    for family in [libc::AF_INET as u8, libc::AF_INET6 as u8] {
        for protocol in [libc::IPPROTO_TCP as u8, libc::IPPROTO_UDP as u8] {
            match collect(&mut nl, family, protocol, ips) {
                Ok(mut v) => victims.append(&mut v),
                // UDP diag may be absent (CONFIG_INET_UDP_DIAG): skip that protocol only.
                Err(e)
                    if protocol == libc::IPPROTO_UDP as u8
                        && e.raw_os_error() == Some(libc::ENOENT) => {}
                Err(e) => return Err(e),
            }
        }
    }
    report.matched = victims.len();
    for (family, protocol, id) in victims {
        match destroy(&mut nl, family, protocol, &id) {
            Ok(()) => report.destroyed += 1,
            Err(e) => {
                tracing::debug!("SOCK_DESTROY failed: {e}");
                report.failed += 1;
            }
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::Read,
        net::{TcpListener, TcpStream},
    };

    #[test]
    fn matcher_handles_v4_and_mapped_addresses() {
        let mut id = [0u8; ID_LEN];
        id[4..8].copy_from_slice(&[10, 1, 2, 3]);
        assert!(matches(
            libc::AF_INET as u8,
            &id,
            &["10.1.2.3".parse().unwrap()]
        ));
        assert!(!matches(
            libc::AF_INET as u8,
            &id,
            &["10.1.2.4".parse().unwrap()]
        ));

        let mut id6 = [0u8; ID_LEN];
        id6[20 + 10] = 0xff;
        id6[20 + 11] = 0xff;
        id6[20 + 12..20 + 16].copy_from_slice(&[10, 1, 2, 3]);
        assert!(matches(
            libc::AF_INET6 as u8,
            &id6,
            &["10.1.2.3".parse().unwrap()]
        ));
    }

    /// Needs CAP_NET_ADMIN + CONFIG_INET_DIAG_DESTROY; skips itself where unavailable.
    #[test]
    fn destroys_a_loopback_connection() {
        if !crate::sys::has_cap_net_admin() {
            eprintln!("skipped: no CAP_NET_ADMIN");
            return;
        }
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).unwrap();
        let (_server_side, _) = listener.accept().unwrap();

        let report = match kill_sockets(&["127.0.0.1".parse().unwrap()]) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("skipped: netlink sock_diag unavailable: {e}");
                return;
            }
        };
        assert!(
            report.matched >= 2,
            "both ends of the loopback connection must be found: {report:?}"
        );
        if report.destroyed == 0 {
            eprintln!("kernel refused SOCK_DESTROY (no CONFIG_INET_DIAG_DESTROY): {report:?}");
            return;
        }
        client
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let mut b = [0u8; 1];
        let r = client.read(&mut b);
        assert!(
            matches!(r, Ok(0)) || r.is_err(),
            "connection must be dead, got {r:?}"
        );
    }
}
