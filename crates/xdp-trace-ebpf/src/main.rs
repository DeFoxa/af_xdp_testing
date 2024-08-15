#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    helpers::bpf_ktime_get_ns,
    macros::{map, xdp},
    maps::PerfEventArray,
    programs::XdpContext,
};
use aya_log_ebpf::info;
use core::panic::PanicInfo;

#[derive(Debug, Copy, Clone)]
#[repr(C)]
struct XdpEvent {
    timestamp: u64,
    packet_size: u32,
    action: u32,
}

#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<XdpEvent> = PerfEventArray::new(0);

#[xdp]
pub fn xdp_tracer(ctx: XdpContext) -> u32 {
    match try_xdp_tracer(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_xdp_tracer(ctx: XdpContext) -> Result<u32, u32> {
    let event = XdpEvent {
        timestamp: unsafe { bpf_ktime_get_ns() },
        packet_size: (ctx.data_end() - ctx.data()) as u32,
        action: xdp_action::XDP_PASS,
    };

    unsafe {
        EVENTS.output(&ctx, &event, 0);
    }

    info!(&ctx, "XDP event logged");

    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
