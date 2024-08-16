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
    match try_xdp_tracer(&ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}
#[inline(always)]
fn try_xdp_tracer(ctx: &XdpContext) -> Result<u32, u32> {
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
    let src_port = u16::from_be(unsafe { (*udp).source });

    if src_port == 7777 || dst_port == 7777 {
        let event = XdpEvent {
            timestamp: unsafe { bpf_ktime_get_ns() },
            packet_size: (ctx.data_end() - ctx.data()) as u32,
            action: xdp_action::XDP_PASS,
        };
        unsafe {
            EVENTS.output(ctx, &event, 0);
        }
        info!(ctx, "Packet on port 7777 detected");
    }

    Ok(xdp_action::XDP_PASS)
}

fn should_process_packet(ctx: &XdpContext) -> Result<bool, u32> {
    let eth = ptr_at::<EthHdr>(ctx, 0).unwrap();
    if unsafe { (*eth).ether_type } != EtherType::Ipv4 {
        return Ok(false);
    }

    let ipv4 = ptr_at::<Ipv4Hdr>(ctx, EthHdr::LEN).unwrap();
    if unsafe { (*ipv4).proto } != IpProto::Udp {
        return Ok(false);
    }

    let udp = ptr_at::<UdpHdr>(ctx, EthHdr::LEN + Ipv4Hdr::LEN).unwrap();
    let dst_port = u16::from_be(unsafe { (*udp).dest });
    let src_port = u16::from_be(unsafe { (*udp).source });

    Ok(src_port == 7777 || dst_port == 7777)
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
