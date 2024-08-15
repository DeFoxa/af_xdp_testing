#![allow(warnings)]

use aya::{
    include_bytes_aligned,
    programs::{Xdp, XdpFlags},
    Bpf,
};
use aya_log::BpfLogger;
use eyre::Result;
use log::info;
use tokio::signal;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    println!("program running");

    // #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../../../target/bpfel-unknown-none/release/xdp-trace-ebpf"
    ))?;
    // let bpf_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("")

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
