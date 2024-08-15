#![no_std]
#![no_main]

use aya_ebpf::{macros::xdp, maps::PerfEventArray, programs::XdpContext};

pub fn test() {
    println!("test");
}
