#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    helpers::{bpf_ktime_get_ns, bpf_redirect_map},
    macros::{map, xdp},
    maps::{PerfEventArray, XskMap},
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

#[map(name = "XSKS_MAP")]
static mut XSKS_MAP: XskMap = XskMap::with_max_entries(1, 0);

#[xdp]
pub fn af_xdp_router(ctx: XdpContext) -> u32 {
    match try_af_xdp_router(&ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}
#[inline(always)]
fn try_af_xdp_router(ctx: &XdpContext) -> Result<u32, u32> {
    let eth = ptr_at::<EthHdr>(ctx, 0)?;
    if unsafe { (*eth).ether_type } != EtherType::Ipv4 {
        return Ok(xdp_action::XDP_PASS);
    }

    let ipv4 = ptr_at::<Ipv4Hdr>(ctx, EthHdr::LEN)?;
    if unsafe { (*ipv4).proto } != IpProto::Udp {
        return Ok(xdp_action::XDP_PASS);
    }

    let udp = ptr_at::<UdpHdr>(ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
    let dst_port = u16::from_be(unsafe { (*udp).dest });

    if dst_port == 7777 {
        let event = XdpEvent {
            timestamp: unsafe { bpf_ktime_get_ns() },
            packet_size: (ctx.data_end() - ctx.data()) as u32,
            action: xdp_action::XDP_PASS,
        };
        unsafe {
            EVENTS.output(ctx, &event, 0);
        }
        info!(ctx, "Packet on port 7777 detected");

        match unsafe { bpf_redirect_map(ptr::addr_of!(XSKS_MAP) as *mut _, 0, 0) } {
            0 => Ok(xdp_action::XDP_REDIRECT),
            _ => {
                info!(
                    ctx,
                    "failed to redirect to af_xdp socket, passed to network stack"
                );
                Ok(xdp_action::XDP_PASS)
            }
        }
    } else {
        Ok(xdp_action::XDP_PASS)
    }
}
#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, u32> {
    let start = ctx.data();
    let end = ctx.data_end();

    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(xdp_action::XDP_ABORTED);
    }
    Ok((start + offset) as *const T)
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
