use aya::{maps::RingBuf, programs::TracePoint};
#[rustfmt::skip]
use log::{debug, warn};
use tokio::{io::unix::AsyncFd};
use tokio::signal::unix::{signal, SignalKind};
use e_bpf_antiransomware_common::{LinkEvent, READ_SZ};


fn compute_entropy(data: &[u8]) -> f64 {
    let mut freq = [0u32; 256];
    let mut entropy = 0.0;

    for &byte in data {
        freq[byte as usize] += 1;
    }

    for count in freq {
        if count > 0 {
            let p = count as f64 / data.len() as f64;
            entropy -= p * p.log2();
        }
    }

    return entropy;
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/e-bpf-antiransomware"
    )))?;
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }

    // attach eBPF program 
    let program: &mut TracePoint = ebpf.program_mut("e_bpf_antiransomware").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_write")?;

    let ring = RingBuf::try_from(ebpf.map_mut("RING_BUFFER").unwrap())?;
    let mut async_fd = AsyncFd::with_interest(ring, tokio::io::Interest::READABLE)?;
    let mut sigint = signal(SignalKind::interrupt())?;
    loop {
        tokio::select! {
            _ = sigint.recv() => {
                println!("signal received");
                break;
            }
            x = async_fd.readable_mut() => {
                let mut guard = x?;
                let inner_ring = guard.get_inner_mut();
                let mut iteration: u32 = 0;
                while let Some(item) = inner_ring.next() {
                    if item.len() != size_of::<LinkEvent>() {
                        continue;
                    }
                    
                    let event = unsafe { &*(item.as_ptr() as *const LinkEvent) };
                    let entropy: f64 = compute_entropy(&event.data[..]);
                    let command = core::ffi::CStr::from_bytes_until_nul(&event.comm)?;
                    let command = unsafe { core::str::from_utf8_unchecked(command.to_bytes()) };

                    if entropy >= 7.3 {
                        println!("[ENTROPY] Command {command} = {entropy}");
                    }
                }
                guard.clear_ready();
            }
        }
    }
    println!("Exiting...");

    Ok(())
}
