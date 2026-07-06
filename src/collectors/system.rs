use anyhow::Result;
use serde::{Deserialize, Serialize};
use sysinfo::System;

/// Metriche di sistema: CPU, memoria, disco, rete, uptime, load average.
/// Usate sia dal heartbeat FireDog che dal collector CyberSheppard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemMetrics {
    pub cpu_percent: f32,
    pub memory_total_kb: u64,
    pub memory_used_kb: u64,
    pub memory_percent: f32,
    pub disk_total_kb: u64,
    pub disk_used_kb: u64,
    pub disk_percent: f32,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub uptime_seconds: u64,
    pub load_avg: [f64; 3],
    pub process_count: usize,
}

pub async fn collect() -> Result<SystemMetrics> {
    tokio::task::spawn_blocking(collect_sync)
        .await
        .map_err(|e| anyhow::anyhow!("spawn_blocking error: {}", e))?
}

fn collect_sync() -> Result<SystemMetrics> {
    let mut sys = System::new_all();
    // La prima lettura CPU non è accurata senza una pausa;
    // usiamo una breve sleep e una seconda lettura.
    sys.refresh_cpu_usage();
    std::thread::sleep(std::time::Duration::from_millis(200));
    sys.refresh_all();

    let cpu_percent = sys.global_cpu_info().cpu_usage();

    let memory_total_kb = sys.total_memory() / 1024;
    let memory_used_kb = sys.used_memory() / 1024;
    let memory_percent = if memory_total_kb > 0 {
        (memory_used_kb as f32 / memory_total_kb as f32) * 100.0
    } else {
        0.0
    };

    // Disco: somma di tutti i dischi
    let disks = sysinfo::Disks::new_with_refreshed_list();
    let disk_total_kb: u64 = disks.iter().map(|d| d.total_space() / 1024).sum();
    let disk_available_kb: u64 = disks.iter().map(|d| d.available_space() / 1024).sum();
    let disk_used_kb = disk_total_kb.saturating_sub(disk_available_kb);
    let disk_percent = if disk_total_kb > 0 {
        (disk_used_kb as f32 / disk_total_kb as f32) * 100.0
    } else {
        0.0
    };

    // Rete: somma di tutte le interfacce
    let networks = sysinfo::Networks::new_with_refreshed_list();
    let bytes_sent: u64 = networks.iter().map(|(_, n)| n.total_transmitted()).sum();
    let bytes_recv: u64 = networks.iter().map(|(_, n)| n.total_received()).sum();

    let uptime_seconds = System::uptime();

    let load_avg = System::load_average();
    let load_avg = [load_avg.one, load_avg.five, load_avg.fifteen];

    let process_count = sys.processes().len();

    Ok(SystemMetrics {
        cpu_percent,
        memory_total_kb,
        memory_used_kb,
        memory_percent,
        disk_total_kb,
        disk_used_kb,
        disk_percent,
        bytes_sent,
        bytes_recv,
        uptime_seconds,
        load_avg,
        process_count,
    })
}
