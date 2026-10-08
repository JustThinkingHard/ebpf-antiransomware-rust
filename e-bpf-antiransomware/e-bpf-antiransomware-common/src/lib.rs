#![no_std]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct LinkEvent {
    pub pid: u32,
    pub tgid: u32,
    pub fd: u32,
    pub comm: [u8; 16],
    pub size: u64,
    pub data: [u8; 512],
    pub inode: u64,
}

pub const READ_SZ: u32 = 512;