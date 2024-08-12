#![allow(warnings)]
use std::{net::UdpSocket, time::Instant};
// use xsk_rs::{Config, Socket, Umem};
use std::sync::atomic::{AtomicBool, Ordering};
use structopt::StructOpt;
use xsk_rs::{
    config::{BindFlags, FrameSize, Interface, QueueSize, SocketConfig, UmemConfig},
    CompQueue, FillQueue, FrameDesc, RxQueue, Socket, TxQueue, Umem,
};

pub mod af_xdp;
pub mod metrics;
pub mod udp;
