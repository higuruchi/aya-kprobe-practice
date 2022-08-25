#![no_std]
#![no_main]

#[allow(unused_variablesm, non_camel_case_types)]
mod vmlinux;

use vmlinux::{path, dentry, inode, kuid_t};
use aya_log_ebpf::info;
use aya_bpf::{
    programs::ProbeContext, cty::c_uint, macros::{kprobe, map}, maps::PerfEventArray,
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_comm, bpf_probe_read, bpf_printk},
};

use ebpf_kprobe_common::ProcessData;

#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<ProcessData> = PerfEventArray::<ProcessData>::with_max_entries(1024, 0);


#[kprobe(name="ebpf_kprobe")]
pub fn ebpf_kprobe(ctx: ProbeContext) -> u32 {
    unsafe { bpf_printk!(b"hi there! dec: %d, hex: 0x%08X %d\n", 42, 0x1234, 100) };

    match unsafe { try_ebpf_kprobe(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_ebpf_kprobe(ctx: ProbeContext) -> Result<u32, u32> {
    let path: *const path = ctx.arg(0).ok_or(1u32)?;
    let dentry: *const dentry = bpf_probe_read(&(*path).dentry).map_err(|_| 1u32)?;
    let d_flags: c_uint = bpf_probe_read(&(*dentry).d_flags).map_err(|_| 1u32)?;
    let inode: *const inode = bpf_probe_read(&(*dentry).d_inode).map_err(|_| 1u32)?;
    let k_uid: kuid_t = bpf_probe_read(&(*inode).i_uid).map_err(|_| 1u32)?;
    let i_uid: c_uint = bpf_probe_read(&k_uid.val).map_err(|_| 1u32)?;
    let process_data = ProcessData {
        pid: i_uid,
    };

    EVENTS.output(&ctx, &process_data, 0);
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
