#![no_std]
#![no_main]

mod vmlinux;

use aya_ebpf::{
    EbpfContext,
    helpers::{
        bpf_get_current_pid_tgid, bpf_probe_read_kernel, bpf_probe_read_user_buf,
        generated::bpf_get_current_task_btf,
    },
    macros::{lsm, map, tracepoint},
    maps::{HashMap, RingBuf},
    programs::{LsmContext, TracePointContext},
};
use aya_log_ebpf::info;
use e_bpf_antiransomware_common::{LinkEvent, READ_SZ};
use vmlinux::{mm_struct, task_struct};

use crate::vmlinux::iattr;

#[map]
pub static RING_BUFFER: RingBuf = RingBuf::with_byte_size(1 << 18, 0);
#[map]
pub static WHITELIST: HashMap<u64, u8> = HashMap::with_max_entries(10240, 0);
#[map]
pub static BLACKLIST: HashMap<u64, u8> = HashMap::with_max_entries(10240, 0);

#[lsm(hook = "file_permission")]
pub fn check_file_permission(ctx: LsmContext) -> i32 {
    match try_file_permission(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[lsm(hook = "inode_setattr")]
pub fn check_trunc(ctx: LsmContext) -> i32 {
    match try_inode_setattr(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn e_bpf_antiransomware(ctx: TracePointContext) -> u32 {
    match try_e_bpf_antiransomware(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn find_inode() -> Result<u64, i32> {
    let task = unsafe { bpf_get_current_task_btf() } as *const task_struct;
    if task.is_null() {
        return Err(-1);
    }
    let mm: *const mm_struct = unsafe { bpf_probe_read_kernel(&(*task).mm)? };
    if mm.is_null() {
        return Err(-1);
    }
    let exe_file = unsafe { bpf_probe_read_kernel(&(*mm).__bindgen_anon_1.exe_file)? };
    if exe_file.is_null() {
        return Err(-1);
    }
    let f_inode = unsafe { bpf_probe_read_kernel(&(*exe_file).f_inode)? };
    if f_inode.is_null() {
        return Err(-1);
    }
    let i_ino = unsafe { bpf_probe_read_kernel(&(*f_inode).i_ino)? };
    Ok(i_ino)
}

fn try_inode_setattr(ctx: LsmContext) -> Result<i32, i32> {
    let attr: *const iattr = ctx.arg(1);
    let ia_valid = match unsafe { bpf_probe_read_kernel(&(*attr).ia_valid) } {
        Ok(i) => i,
        Err(_) => return Err(-1),
    };
    // ATTR_SIZE = 8
    if (ia_valid & 8) == 0 {
        return Ok(0);
    }
    let inode = match find_inode() {
        Ok(i) => i,
        Err(_) => return Err(-1),
    };

    if unsafe { BLACKLIST.get(&inode) }.is_some() {
        info!(&ctx, "inode {} stopped in LSM inode setattr !", inode);
        return Err(-1);
    }
    Ok(0)
}

fn try_file_permission(ctx: LsmContext) -> Result<i32, i32> {
    let mask: i32 = ctx.arg(1);

    // 0x2 = MAY_WRITE, 0x8 = MAY_APPEND
    if (mask & (0x2 | 0x8)) == 0 {
        return Ok(0);
    }
    let inode = match find_inode() {
        Ok(i) => i,
        Err(_) => return Err(-1),
    };

    if unsafe { BLACKLIST.get(&inode) }.is_some() {
        info!(&ctx, "inode {} stopped in LSM file permission !", inode);
        return Err(-1);
    }
    Ok(0)
}

fn try_e_bpf_antiransomware(ctx: TracePointContext) -> Result<u32, i32> {
    let pid_tgid: u64 = bpf_get_current_pid_tgid();
    let inode: u64 = find_inode()?;

    if unsafe { BLACKLIST.get(&inode) }.is_some() {
        return Ok(0);
    }
    if unsafe { WHITELIST.get(&inode) }.is_some() {
        return Ok(0);
    }

    const FD_OFFSET: usize = 16;
    let fd: u32 = unsafe { ctx.read_at(FD_OFFSET)? };

    const BUFFER_OFFSET: usize = 24;
    let buf_read: *const u8 = unsafe { ctx.read_at(BUFFER_OFFSET)? };

    const COUNT_OFFSET: usize = 32;
    let count: usize = unsafe { ctx.read_at(COUNT_OFFSET)? };

    let command = ctx.command()?;

    if count < READ_SZ {
        return Ok(0);
    }

    let mut read_from = buf_read;
    if count > READ_SZ * 2 {
        read_from = unsafe { buf_read.add(count / 2) };
    }
    if let Some(mut entry) = RING_BUFFER.reserve::<LinkEvent>(0) {
        // if the ringbuffer has not space left, it returns none.

        let link = entry.as_mut_ptr();
        let data_ptr = unsafe { (&raw mut (*link).data) as *mut u8 };
        let data_slice = unsafe { core::slice::from_raw_parts_mut(data_ptr, 512) };
        let result = unsafe { bpf_probe_read_user_buf(read_from, data_slice) }; // sample written in ring buffer
        if result.is_err() {
            entry.discard(0);
            return Ok(0);
        }

        // SAFETY: `link` points to a reserved, correctly-sized and aligned LinkEvent
        // slot from RING_BUFFER.reserve. We make sure to leave no field uninitialized.
        unsafe {
            (&raw mut (*link).size).write(count as u64);
            (&raw mut (*link).pid).write((pid_tgid >> 32) as u32);
            (&raw mut (*link).tgid).write(pid_tgid as u32);
            (&raw mut (*link).fd).write(fd);
            (&raw mut (*link).inode).write(inode);
            (&raw mut (*link).comm).write(command);
        };

        entry.submit(0);
    }

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
