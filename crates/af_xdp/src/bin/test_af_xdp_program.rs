#![allow(warnings)]

use aya::maps::XskMap;
use aya::{
    include_bytes_aligned,
    programs::{Xdp, XdpFlags},
    Bpf,
};
use aya_log::BpfLogger;
use env_logger::{Builder, Env};
use eyre::Result;
use lib::udp::setup_udp_server;
use log::info;
use std::convert::TryFrom;
use std::ffi::CString;
use std::str::FromStr;
use std::thread;
use structopt::StructOpt;
use xsk_rs::{
    config::{Interface, SocketConfig, UmemConfig},
    CompQueue, FillQueue, RxQueue, Socket, TxQueue, Umem,
};

const INTERFACE: &str = "enp97s0f1";

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    thread::spawn(|| {
        setup_udp_server();
    });

    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../../../target/bpfel-unknown-none/release/xdp-trace-ebpf"
    ))?;

    if let Err(e) = BpfLogger::init(&mut bpf) {
        log::warn!("failure to initialize eBPF logger {}", e);
    }

    let program: &mut Xdp = bpf.program_mut("af_xdp_router").unwrap().try_into()?;
    program.load()?;
    program.attach(INTERFACE, XdpFlags::default())?;
    info!("xdp program attached");

    let xsks_map = XskMap::try_from(bpf.map_mut("XSKS_MAP").unwrap())?;

    let umem_config = UmemConfig::default();

    let (umem, mut frame_desc) = Umem::new(umem_config, 32.try_into()?, false)?;

    let (mut tx_q, mut rx_q, mut fq_cq) = unsafe {
        Socket::new(
            SocketConfig::default(),
            &umem,
            &Interface::from_str(INTERFACE).unwrap(),
            0,
        )?
    };
    let (mut fq, cq) = fq_cq.expect("missing fill queue and completion queue");

    // xsks_map.set(0, socket.fd(), 0)?;

    loop {
        //NOTE: don't think this setup will work properly for application due to the lack of
        // specific management logic for queues. keep it simple for initial testing.
        // TODO: fix above when appropriate
        unsafe { fq.produce(&mut frame_desc) };

        // if let Some(descs) = rx_q.consume() {
        //     for desc in descs {
        //         frame_desc.push(desc);
        //     }
        // }
        let pkt = "test pkt".as_bytes();

        unsafe { tx_q.produce_and_wakeup(&frame_desc[..1]) };

        let poll_timeout: i32 = 100;

        let pkts_recvd = unsafe {
            rx_q.poll_and_consume(&mut frame_desc, poll_timeout)
                .unwrap()
        };

        for recv_desc in frame_desc.iter().take(pkts_recvd) {
            let data = unsafe { umem.data(recv_desc) };

            if data.contents() == pkt {
                println!("received packet!");
                return Ok(());
            }
        }

        // if let Some(descs) = cq.consume() {
        //     for desc in descs {
        //         frame_desc.push(desc);
        //     }
        // }
    }

    Ok(())
}
