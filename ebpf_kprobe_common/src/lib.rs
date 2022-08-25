#![no_std]

// use aya_bpf::cty::c_uint;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ProcessData {
    pub pid: u32,       // Process ID
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ProcessData {}
