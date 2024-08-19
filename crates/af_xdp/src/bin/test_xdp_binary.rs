#![allow(warnings)]

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
use std::thread;
use structopt::StructOpt;
use tokio::signal;

#[derive(Debug, StructOpt)]
struct Opt {
    #[structopt(short, long, default_value = "xsk_test_dev1@xsk_test_dev2")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opt = Opt::from_args();
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
    program.attach(
        /* &opt.iface */ "enp97s0f1",
        /* XdpFlags::SKB_MODE */ XdpFlags::default(),
    )?;

    info!("waiting for ctrl-c");
    signal::ctrl_c().await?;
    info!("exiting");

    Ok(())
}

fn setup_loggin() {
    Builder::from_env(Env::default().default_filter_or("info")).init();
}
