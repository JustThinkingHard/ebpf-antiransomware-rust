#![no_std]
#![no_main]

use aya_ebpf::{EbpfContext, helpers::{bpf_get_current_pid_tgid, bpf_probe_read_user_buf}, macros::{tracepoint, map}, maps::{PerCpuArray, RingBuf}, programs::TracePointContext};
use aya_log_ebpf::info;
use e_bpf_antiransomware_common::LinkEvent;

#[map]
pub static RING_BUFFER: RingBuf = RingBuf::with_byte_size(1 << 18, 0);

#[tracepoint]
pub fn e_bpf_antiransomware(ctx: TracePointContext) -> u32 {
    match try_e_bpf_antiransomware(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn try_e_bpf_antiransomware(ctx: TracePointContext) -> Result<u32, i32> {
    let pid_tgid:u64 =  bpf_get_current_pid_tgid();

    const FD_OFFSET: usize = 16;
    let fd: u32 = unsafe { ctx.read_at(FD_OFFSET)? };

    const BUFFER_OFFSET: usize = 24;
    let buf_read: *const u8 = unsafe { ctx.read_at(BUFFER_OFFSET)? };

    const READ_SZ_OFFSET: usize = 512;
    let count: usize = unsafe { ctx.read_at(READ_SZ_OFFSET)? };

    let command = ctx.command()?;

    if count < READ_SZ_OFFSET {
        return Ok(0);
    }

    let mut read_from = buf_read;
    if count > READ_SZ_OFFSET * 2 {
        read_from = unsafe { buf_read.add(count / 2) };
    }

    if let Some(mut entry) = RING_BUFFER.reserve::<LinkEvent>(0) {
        // if the ringbuffer has not space left, it returns none.

        let link= entry.as_mut_ptr();
        let data_ptr = unsafe { (&raw mut (*link).data) as *mut u8 };
        let data_slice = unsafe { core::slice::from_raw_parts_mut(data_ptr, 512) };
        let result = unsafe { bpf_probe_read_user_buf(read_from, data_slice) }; // sample written in ring buffer
        if result.is_err() {
            entry.discard(0);
            return Ok(0);
        }

        unsafe { (&raw mut (*link).size).write(count as u64);
                 (&raw mut (*link).pid).write((pid_tgid >> 32) as u32);
                 (&raw mut (*link).tgid).write(pid_tgid as u32);
                 (&raw mut (*link).fd).write(fd);
                 (&raw mut (*link).inode).write(0);
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
