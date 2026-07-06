use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMetrics {
    pub interfaces: Vec<InterfaceStats>,
    pub listening_ports: Vec<ListeningPort>,
    pub active_connections: Vec<TcpConnection>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceStats {
    pub name: String,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub packets_sent: u64,
    pub packets_recv: u64,
    pub errors_in: u64,
    pub errors_out: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListeningPort {
    pub protocol: String, // "tcp" | "udp"
    pub local_addr: String,
    pub port: u16,
    pub pid: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpConnection {
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub state: String,
    pub pid: Option<u32>,
}

pub async fn collect() -> Result<NetworkMetrics> {
    tokio::task::spawn_blocking(collect_sync)
        .await
        .map_err(|e| anyhow::anyhow!("spawn_blocking error: {}", e))?
}

fn collect_sync() -> Result<NetworkMetrics> {
    let interfaces = collect_interfaces();
    let (listening_ports, active_connections) = collect_connections();

    Ok(NetworkMetrics {
        interfaces,
        listening_ports,
        active_connections,
    })
}

fn collect_interfaces() -> Vec<InterfaceStats> {
    let networks = sysinfo::Networks::new_with_refreshed_list();
    networks
        .iter()
        .map(|(name, n)| InterfaceStats {
            name: name.clone(),
            bytes_sent: n.total_transmitted(),
            bytes_recv: n.total_received(),
            packets_sent: n.total_packets_transmitted(),
            packets_recv: n.total_packets_received(),
            errors_in: n.total_errors_on_received(),
            errors_out: n.total_errors_on_transmitted(),
        })
        .collect()
}

fn collect_connections() -> (Vec<ListeningPort>, Vec<TcpConnection>) {
    #[cfg(target_os = "linux")]
    return collect_connections_linux();

    #[cfg(not(target_os = "linux"))]
    return (vec![], vec![]);
}

#[cfg(target_os = "linux")]
fn collect_connections_linux() -> (Vec<ListeningPort>, Vec<TcpConnection>) {
    let mut listening = Vec::new();
    let mut active = Vec::new();

    // Legge /proc/net/tcp e /proc/net/tcp6
    for path in &["/proc/net/tcp", "/proc/net/tcp6"] {
        if let Ok(content) = std::fs::read_to_string(path) {
            for line in content.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 12 {
                    continue;
                }

                let local = parse_proc_addr(parts[1]);
                let remote = parse_proc_addr(parts[2]);
                let state_hex = parts[3];
                let state = tcp_state(state_hex);

                if state == "LISTEN" {
                    listening.push(ListeningPort {
                        protocol: "tcp".to_string(),
                        local_addr: local.0.clone(),
                        port: local.1,
                        pid: None,
                    });
                } else if !state.is_empty() && remote.1 != 0 {
                    active.push(TcpConnection {
                        local_addr: local.0,
                        local_port: local.1,
                        remote_addr: remote.0,
                        remote_port: remote.1,
                        state,
                        pid: None,
                    });
                }
            }
        }
    }

    (listening, active)
}

#[cfg(target_os = "linux")]
fn parse_proc_addr(s: &str) -> (String, u16) {
    // Formato /proc/net/tcp: "0100007F:0050" (little-endian hex)
    let parts: Vec<&str> = s.splitn(2, ':').collect();
    if parts.len() != 2 {
        return ("0.0.0.0".to_string(), 0);
    }

    let port = u16::from_str_radix(parts[1], 16).unwrap_or(0);

    // IPv4: 8 caratteri hex
    let addr = if parts[0].len() == 8 {
        let n = u32::from_str_radix(parts[0], 16).unwrap_or(0);
        let b = n.to_le_bytes();
        format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
    } else {
        // IPv6: semplificato
        parts[0].to_string()
    };

    (addr, port)
}

#[cfg(target_os = "linux")]
fn tcp_state(hex: &str) -> String {
    match hex {
        "01" => "ESTABLISHED",
        "02" => "SYN_SENT",
        "03" => "SYN_RECV",
        "04" => "FIN_WAIT1",
        "05" => "FIN_WAIT2",
        "06" => "TIME_WAIT",
        "07" => "CLOSE",
        "08" => "CLOSE_WAIT",
        "09" => "LAST_ACK",
        "0A" => "LISTEN",
        "0B" => "CLOSING",
        _ => "",
    }
    .to_string()
}
