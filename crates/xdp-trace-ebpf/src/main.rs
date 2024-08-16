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
use core::{mem, panic::PanicInfo, ptr};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};

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
    if should_process_packet(&ctx) {
        let event = XdpEvent {
            timestamp: unsafe { bpf_ktime_get_ns() },
            packet_size: (ctx.data_end() - ctx.data()) as u32,
            action: xdp_action::XDP_PASS,
        };

        unsafe {
            EVENTS.output(&ctx, &event, 0);
        }

        info!(&ctx, "XDP event logged");
    }

    Ok(xdp_action::XDP_PASS)
}

fn should_process_packet(ctx: &XdpContext) -> bool {
    match try_should_process_packet(ctx) {
        Ok(should_process) => should_process,
        Err(_) => false,
    }
}
fn try_should_process_packet(ctx: &XdpContext) -> Result<bool, ()> {
    let eth = unsafe { ptr_at::<EthHdr>(ctx, 0) }?;

    let ether_type = unsafe { ptr::read_unaligned(ptr::addr_of!((*eth).ether_type)) };

    if ether_type != EtherType::Ipv4 {
        return Ok(false);
    }

    let ip = unsafe { ptr_at::<Ipv4Hdr>(ctx, EthHdr::LEN) }?;

    if ip.proto != IpProto::Udp {
        return Ok(false);
    }

    let udp = unsafe { ptr_at::<UdpHdr>(ctx, EthHdr::LEN + Ipv4Hdr::LEN) }?;

    let dst_port = u16::from_be(unsafe { ptr::read_unaligned(ptr::addr_of!((*udp).dest)) });

    info!(ctx, "UDP packet detected, port: {}", dst_port);

    Ok(dst_port == 7777)
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<&T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();

    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }
    let ptr = (start + offset) as *const T;

    Ok(&*ptr)
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
