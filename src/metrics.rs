use std::fmt;
use std::time::Duration;

pub struct BenchmarkMetrics {
    pub socket_type: SocketType,
    pub total_packets_sent: usize,
    pub total_packets_received: usize,
    pub packet_size: usize,
    pub elapsed_tiem: Duration,
    pub throughput_gbps: f64,
    pub average_latency: Duration,
}

pub enum SocketType {
    Afxdp,
    Udp,
}
