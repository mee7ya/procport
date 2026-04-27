use std::{
    fmt::Display,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use windows::{
    Win32::{
        Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_NO_MORE_FILES, WIN32_ERROR},
        NetworkManagement::IpHelper::{
            GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID,
            MIB_TCP6TABLE_OWNER_PID, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID,
            MIB_UDP6ROW_OWNER_PID, MIB_UDP6TABLE_OWNER_PID, MIB_UDPROW_OWNER_PID,
            MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
        },
        Networking::WinSock::{AF_INET, AF_INET6},
        System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
            TH32CS_SNAPPROCESS,
        },
    },
    core::Error,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    // Udp,
}

impl Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "TCP"),
            // Protocol::Udp => write!(f, "UDP"),
        }
    }
}

#[derive(Debug, Eq)]
pub struct Connection {
    pub protocol: Protocol,
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub pid: u32,
    pub active: bool,
}

impl PartialEq for Connection {
    fn eq(&self, other: &Self) -> bool {
        self.local == other.local && self.remote == other.remote && self.pid == other.pid
    }
}

/// Returns all PIDs whose executable name matches `process_name` (case-insensitive).
/// `process_name` should include the ".exe" extension (e.g. "chrome.exe").
pub fn get_pids_by_name(process_name: &str) -> Result<Vec<u32>, Error> {
    let mut pids = Vec::new();

    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)? };

    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };

    let name_lower = process_name.to_lowercase();

    unsafe {
        if let Err(e) = Process32FirstW(snapshot, &mut entry) {
            CloseHandle(snapshot)?;

            if WIN32_ERROR(e.code().0 as u32 & 0xFFFF) == ERROR_NO_MORE_FILES {
                return Ok(pids); // Acceptable if no processes are found
            } else {
                return Err(e);
            }
        }

        loop {
            // Process name is up to first 0x00 byte
            let exe_name = String::from_utf16_lossy(
                &entry.szExeFile[..entry
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0x00)
                    .unwrap_or(entry.szExeFile.len())],
            )
            .to_lowercase();

            if exe_name == name_lower {
                pids.push(entry.th32ProcessID);
            }

            if let Err(e) = Process32NextW(snapshot, &mut entry) {
                if WIN32_ERROR(e.code().0 as u32 & 0xFFFF) == ERROR_NO_MORE_FILES {
                    break; // Acceptable if no processes are found
                } else {
                    CloseHandle(snapshot)?;
                    return Err(e);
                }
            }
        }
        CloseHandle(snapshot)?;
    }

    Ok(pids)
}

/// Returns all TCP connections filtered by `pids`
pub fn get_connections_by_pids(pids: &[u32]) -> Result<Vec<Connection>, Error> {
    let tcp4 = get_tcp4_table()?.into_iter().filter_map(|row| {
        if pids.contains(&row.dwOwningPid) {
            Some(Connection {
                protocol: Protocol::Tcp,
                local: SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::from(row.dwLocalAddr.to_be())),
                    u16::from_be(row.dwLocalPort as u16),
                ),
                remote: SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::from(row.dwRemoteAddr.to_be())),
                    u16::from_be(row.dwRemotePort as u16),
                ),
                pid: row.dwOwningPid,
                active: true,
            })
        } else {
            None
        }
    });
    let tcp6 = get_tcp6_table()?.into_iter().filter_map(|row| {
        if pids.contains(&row.dwOwningPid) {
            Some(Connection {
                protocol: Protocol::Tcp,
                local: SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::from(row.ucLocalAddr)),
                    u16::from_be(row.dwLocalPort as u16),
                ),
                remote: SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::from(row.ucRemoteAddr)),
                    u16::from_be(row.dwRemotePort as u16),
                ),
                pid: row.dwOwningPid,
                active: true,
            })
        } else {
            None
        }
    });

    // let udp4 = get_udp4_table()?.into_iter().filter(|row| pids.contains(&row.dwOwningPid));
    // let udp6 = get_udp6_table()?.into_iter().filter(|row| pids.contains(&row.dwOwningPid));

    Ok(tcp4.chain(tcp6).collect::<Vec<_>>())
}

fn get_tcp4_table() -> Result<Vec<MIB_TCPROW_OWNER_PID>, Error> {
    let mut size: u32 = 0;

    unsafe {
        // First call to get required buffer size — always returns ERROR_INSUFFICIENT_BUFFER
        let rc = WIN32_ERROR(GetExtendedTcpTable(
            None,
            &mut size,
            false,
            AF_INET.0 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        ));
        if rc != ERROR_INSUFFICIENT_BUFFER {
            return Err(rc.into());
        }

        let mut buf = vec![0u8; size as usize];

        // Second call to get actual data
        WIN32_ERROR(GetExtendedTcpTable(
            Some(buf.as_mut_ptr() as *mut _),
            &mut size,
            false,
            AF_INET.0 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        ))
        .ok()?;

        let table = &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
        Ok((0..table.dwNumEntries)
            .map(|i| *table.table.as_ptr().add(i as usize))
            .collect())
    }
}

fn get_tcp6_table() -> Result<Vec<MIB_TCP6ROW_OWNER_PID>, Error> {
    let mut size: u32 = 0;

    unsafe {
        // First call to get required buffer size — always returns ERROR_INSUFFICIENT_BUFFER
        let rc = WIN32_ERROR(GetExtendedTcpTable(
            None,
            &mut size,
            false,
            AF_INET6.0 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        ));
        if rc != ERROR_INSUFFICIENT_BUFFER {
            return Err(rc.into());
        }

        let mut buf = vec![0u8; size as usize];

        // Second call to get actual data
        WIN32_ERROR(GetExtendedTcpTable(
            Some(buf.as_mut_ptr() as *mut _),
            &mut size,
            false,
            AF_INET6.0 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        ))
        .ok()?;

        let table = &*(buf.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID);
        Ok((0..table.dwNumEntries)
            .map(|i| *table.table.as_ptr().add(i as usize))
            .collect())
    }
}

fn _get_udp4_table() -> Result<Vec<MIB_UDPROW_OWNER_PID>, Error> {
    let mut size: u32 = 0;

    unsafe {
        // First call to get required buffer size
        WIN32_ERROR(GetExtendedUdpTable(
            None,
            &mut size,
            false,
            AF_INET.0 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        ))
        .ok()?;

        let mut buf = vec![0u8; size as usize];

        // Second call to get actual data
        WIN32_ERROR(GetExtendedUdpTable(
            Some(buf.as_mut_ptr() as *mut _),
            &mut size,
            false,
            AF_INET.0 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        ))
        .ok()?;

        let table = &*(buf.as_ptr() as *const MIB_UDPTABLE_OWNER_PID);
        Ok((0..table.dwNumEntries)
            .map(|i| *table.table.as_ptr().add(i as usize))
            .collect())
    }
}

fn _get_udp6_table() -> Result<Vec<MIB_UDP6ROW_OWNER_PID>, Error> {
    let mut size: u32 = 0;

    unsafe {
        // First call to get required buffer size
        WIN32_ERROR(GetExtendedUdpTable(
            None,
            &mut size,
            false,
            AF_INET6.0 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        ))
        .ok()?;

        let mut buf = vec![0u8; size as usize];

        // Second call to get actual data
        WIN32_ERROR(GetExtendedUdpTable(
            Some(buf.as_mut_ptr() as *mut _),
            &mut size,
            false,
            AF_INET6.0 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        ))
        .ok()?;

        let table = &*(buf.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID);
        Ok((0..table.dwNumEntries)
            .map(|i| *table.table.as_ptr().add(i as usize))
            .collect())
    }
}
