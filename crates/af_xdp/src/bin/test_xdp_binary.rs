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
use tokio::signal;

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

    let program: &mut Xdp = bpf.program_mut("xdp_tracer").unwrap().try_into()?;
    program.load()?;
    program.attach("lo", XdpFlags::default())?;

    info!("waiting for ctrl-c");
    signal::ctrl_c().await?;
    info!("exiting");

    Ok(())
}

fn setup_loggin() {
    Builder::from_env(Env::default().default_filter_or("info")).init();
}
