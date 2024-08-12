use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};
use structopt::StructOpt;
use xsk_rs::{
    config::{BindFlags, FrameSize, Interface, QueueSize, SocketConfig, UmemConfig},
    CompQueue, FillQueue, FrameDesc, RxQueue, Socket, TxQueue, Umem,
};

/*
Safety NOTE
    - When a frame / address has been submitted to the fill queue or tx ring, do not use it again until you have consumed it from either the completion queue or rx ring.

   -  Do not use one UMEM's frame descriptors to access frames of another, different UMEM.

*/

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
