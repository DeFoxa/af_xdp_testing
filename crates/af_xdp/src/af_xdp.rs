use crate::metrics::BenchmarkMetrics;
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use structopt::StructOpt;
use xsk_rs::{
    config::{BindFlags, FrameSize, Interface, QueueSize, SocketConfig, UmemConfig},
    CompQueue, FillQueue, FrameDesc, RxQueue, Socket, TxQueue, Umem,
};

static SENDER_DONE: AtomicBool = AtomicBool::new(false);

pub struct Xsk {
    pub umem: Umem,
    pub fq: FillQueue,
    pub cq: CompQueue,
    pub tx_q: TxQueue,
    pub rx_q: RxQueue,
    pub descs: Vec<FrameDesc>,
}

#[derive(Debug, Clone, Copy)]
struct XskConfig {
    tx_q_size: QueueSize,
    rx_q_size: QueueSize,
    cq_size: QueueSize,
    fq_size: QueueSize,
    frame_size: FrameSize,
    frame_count: u32,
}
#[derive(Debug, Clone, Copy)]
struct Config {
    multithreaded: bool,
    poll_ms_timeout: i32,
    payload_size: usize,
    max_batch_size: usize,
    num_packets_to_send: usize,
    sender: XskConfig,
    receiver: XskConfig,
}

impl From<Opt> for Config {
    fn from(opt: Opt) -> Self {
        let sender = XskConfig {
            tx_q_size: opt.tx_q_size_sender.try_into().unwrap(),
            rx_q_size: opt.rx_q_size_sender.try_into().unwrap(),
            cq_size: opt.cq_size_sender.try_into().unwrap(),
            fq_size: opt.fq_size_sender.try_into().unwrap(),
            frame_count: opt.fq_size_sender + opt.cq_size_receiver,
            frame_size: opt.frame_size_sender.try_into().unwrap(),
        };

        let receiver = XskConfig {
            tx_q_size: opt.tx_q_size_receiver.try_into().unwrap(),
            rx_q_size: opt.rx_q_size_receiver.try_into().unwrap(),
            cq_size: opt.cq_size_receiver.try_into().unwrap(),
            fq_size: opt.fq_size_receiver.try_into().unwrap(),
            frame_count: opt.fq_size_receiver + opt.cq_size_receiver,
            frame_size: opt.frame_size_receiver.try_into().unwrap(),
        };

        Config {
            multithreaded: opt.multithreaded,
            poll_ms_timeout: opt.poll_ms_timeout,
            payload_size: opt.payload_size,
            max_batch_size: opt.max_batch_size,
            num_packets_to_send: opt.num_packets_to_send,
            sender,
            receiver,
        }
    }
}

#[derive(Debug, StructOpt)]
#[structopt(name = "dev1_to_dev2")]
struct Opt {
    /// Run sender and receiver in separate threads
    #[structopt(short, long)]
    multithreaded: bool,

    /// Sender fill queue size
    #[structopt(default_value = "8192")]
    fq_size_sender: u32,

    /// Sender comp queue size
    #[structopt(default_value = "4096")]
    cq_size_sender: u32,

    /// Sender tx queue size
    #[structopt(default_value = "4096")]
    tx_q_size_sender: u32,

    /// Sender rx queue size
    #[structopt(default_value = "4096")]
    rx_q_size_sender: u32,

    /// Sender frame size
    #[structopt(default_value = "2048")]
    frame_size_sender: u32,

    /// Receiver fill queue size
    #[structopt(default_value = "8192")]
    fq_size_receiver: u32,

    /// Receiver comp queue size
    #[structopt(default_value = "4096")]
    cq_size_receiver: u32,

    /// Receiver tx queue size
    #[structopt(default_value = "4096")]
    tx_q_size_receiver: u32,

    /// Receuver rx queue size
    #[structopt(default_value = "4096")]
    rx_q_size_receiver: u32,

    /// Receiver frame size
    #[structopt(default_value = "2048")]
    frame_size_receiver: u32,

    /// Socket poll timeout in milliseconds
    #[structopt(default_value = "100")]
    poll_ms_timeout: i32,

    /// Packet payload size
    #[structopt(default_value = "32")]
    payload_size: usize,

    /// Max number of packets to send at once
    #[structopt(default_value = "64")]
    max_batch_size: usize,

    /// Total number of packets to send
    #[structopt(default_value = "5000000")]
    num_packets_to_send: usize,
}

fn run_tx_thread<const BATCH_SIZE: usize>(
    mut xsk: Xsk,
    config: XskConfig,
    stats: Arc<BenchmarkMetrics>,
    bench_duration: u64,
) {
    // NOTE: Prepare batch
    let mut batch = vec![FrameDesc::default(); BATCH_SIZE];
    let mut packets_sent = 0;
    let start_time = Instant::now();

    while start_time.elapsed() < Duration::from_secs(bench_duration) {
        for frame in &mut batch {
            unsafe {
                let data = xsk.umem.data_mut(frame);
                generate_test_packet(data);
            }
        }
    }

    let mut sent = 0;
    while sent < batch.len() {
        match unsafe { xsk.tx_q.produce(&batch[sent..]) } {
            0 => {
                if xsk.tx_q.needs_wakeup() {
                    xsk.tx_q.wakeup().unwrap();
                }
            }
            n => {
                sent += n;
                packets_sent += n;
            }
        }
    }

    let mut completed = [FrameDesc::default(); BATCH_SIZE];
    let n = unsafe { xsk.cq.consume(&mut completed) };
    if n > 0 {
        todo!();
        // NOTE: process completed transmissions
        stats.total_packets_received.fetch_add(n, Ordering::Relaxed);
    }

    stats
        .total_packets_sent
        .fetch_add(packets_sent, Ordering::Relaxed);
}

//TODO: Remove generic, add explicit type later
fn generate_test_packet<T>(data: T) {
    todo!();
}

fn current_time_ns() -> u64 {
    let now = std::time::SystemTime::now();
    now.duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}
