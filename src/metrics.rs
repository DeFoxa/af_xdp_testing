use std::time::Duration;
use std::{
    fmt,
    sync::atomic::{AtomicUsize, Ordering},
};

pub struct BenchmarkMetrics {
    pub socket_type: SocketType,
    pub total_packets_sent: AtomicUsize,
    pub total_packets_received: AtomicUsize,
    pub packet_size: usize,
    pub elapsed_time: Duration,
    pub throughput_gbps: f64,
    pub packets_per_sec: f64,
    pub average_latency: Duration,
}

impl BenchmarkMetrics {
    pub fn new(socket_type: SocketType, packet_size: usize) -> Self {
        BenchmarkMetrics {
            socket_type,
            total_packets_sent: AtomicUsize::new(0),
            total_packets_received: AtomicUsize::new(0),
            packet_size,
            elapsed_time: Duration::new(0, 0),
            throughput_gbps: 0.0,
            packets_per_sec: 0.0,
            average_latency: Duration::new(0, 0),
        }
    }

    pub fn increment_sent(&self) {
        self.total_packets_sent.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_received(&self) {
        self.total_packets_received.fetch_add(1, Ordering::Relaxed);
    }

    pub fn calculate_metrics(&mut self) {
        let elapsed_secs = self.elapsed_time.as_secs_f64();
        let total_sent = self.total_packets_sent.load(Ordering::Relaxed);
        let total_received = self.total_packets_received.load(Ordering::Relaxed);
        let bytes_sent = (total_sent * self.packet_size) as f64;

        self.throughput_gbps = (bytes_sent * 8.0) / (elapsed_secs * 1_000_000_000.0);
        self.packets_per_sec = total_sent as f64 / elapsed_secs;

        if total_received > 0 {
            self.average_latency = self.elapsed_time / total_received as u32;
        }
    }
}

#[derive(Debug)]
pub enum SocketType {
    Afxdp,
    Udp,
}

impl fmt::Display for BenchmarkMetrics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Benchmark Results:")?;
        writeln!(f, "Socket Type: {:?}", self.socket_type)?;
        writeln!(
            f,
            "Total Packets Sent: {}",
            self.total_packets_sent.load(Ordering::Relaxed)
        )?;
        writeln!(
            f,
            "Total Packets Received: {}",
            self.total_packets_received.load(Ordering::Relaxed)
        )?;
        writeln!(f, "Packet Size: {} bytes", self.packet_size)?;
        writeln!(f, "Elapsed Time: {:.2?}", self.elapsed_time)?;
        writeln!(f, "Throughput: {:.2} Gbps", self.throughput_gbps)?;
        writeln!(f, "Packets per Second: {:.2}", self.packets_per_sec)?;
        writeln!(f, "Average Latency: {:.2?}", self.average_latency)?;
        Ok(())
    }
}
