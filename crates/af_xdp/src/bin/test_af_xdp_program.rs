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
const DEFAULT_TIMEOUT: i32 = 30;

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
            &Interface::from_str(INTERFACE)?,
            0,
        )?
    };
    let (mut fq, cq) = fq_cq.expect("missing fill queue and completion queue");

    // xsks_map.set(0, socket.fd(), 0)?;

    loop {
        //NOTE: this impl wont work properly for application due to the lack of
        // management logic for queues
        // TODO: fix above when appropriate

        // NOTE: wake-up methods only on tx_q send, not necessary on cq methods
        // NOTE: user space interaction with umem data should involve operations on data in shared
        // memory. i.e. no copy or movement of data to user_space. write method into xdp program (not sure if this should be in the xdp program bin or xdp lib - test xdp program first), that takes closure for data manipulation operation (dependent upon type of operation, try Fn closure, if necessary FnMut)

        unsafe { fq.produce(&mut frame_desc) };

        // if let Some(descs) = rx_q.consume() {
        //     for desc in descs {
        //         frame_desc.push(desc);
        //     }
        // }
        let pkt = "test pkt".as_bytes();

        unsafe { tx_q.produce_and_wakeup(&frame_desc[..1]) };

        let pkts_recvd = unsafe { rx_q.poll_and_consume(&mut frame_desc, DEFAULT_TIMEOUT)? };

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
