#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessInfo {
    pub pid: u32,
    pub tgid: u32,
    pub comm: [u8; 16],
    pub last_seen: u64,
    pub start_time_ns: u64,
    pub cpu: u32,
    // 4 bytes implicit trailing pad to 48-byte alignment
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ProcessInfo {}
