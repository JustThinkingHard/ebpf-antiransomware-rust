use std::{
    fs::{OpenOptions, metadata},
    io::Write,
    os::linux::fs::MetadataExt,
};

use anyhow::Context;
use aya::{
    Btf,
    maps::{HashMap, MapData, RingBuf},
    programs::{Lsm, TracePoint},
};

#[rustfmt::skip]
use log::{debug, warn};
use std::fs::read_to_string;

use e_bpf_antiransomware_common::{BLACKLIST_PATH, LinkEvent, WHITELIST_PATH};
use tokio::{
    io::unix::AsyncFd,
    signal::unix::{SignalKind, signal},
};

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

    entropy
}

fn write_blacklist(list: &mut HashMap<MapData, u64, u8>, banned_inode: u64) -> anyhow::Result<()> {
    list.insert(banned_inode, 1, 0)?;

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(BLACKLIST_PATH)?;
    writeln!(file, "{}", banned_inode)?;

    Ok(())
}

fn load_list(list_type: &str, list: &mut HashMap<MapData, u64, u8>) -> anyhow::Result<()> {
    let contents =
        read_to_string(list_type).context(format!("Failed to read file: {}", list_type))?;
    for line in contents.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let trimed = line.trim();

        if list_type == BLACKLIST_PATH {
            let ino: u64 = trimed.parse()?;
            if list.insert(ino, 1, 0).is_err() {
                eprintln!("Couldn't load {trimed}");
                continue;
            }
        } else {
            let metadata = metadata(trimed)?;
            if list.insert(metadata.st_ino(), 1, 0).is_err() {
                eprintln!("Couldn't load {trimed}");
                continue;
            }
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/e-bpf-antiransomware"
    )))?;
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
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
    let btf = Btf::from_sys_fs()?;

    {
        let program: &mut TracePoint = ebpf
            .program_mut("e_bpf_antiransomware")
            .unwrap()
            .try_into()?;
        program.load()?;
        let lsm_trunc: &mut Lsm = ebpf.program_mut("check_trunc").unwrap().try_into()?;
        lsm_trunc.load("inode_setattr", &btf)?;
        let lsm_file_perm: &mut Lsm = ebpf
            .program_mut("check_file_permission")
            .unwrap()
            .try_into()?;
        lsm_file_perm.load("file_permission", &btf)?;
    }
    let mut whitelist: HashMap<_, u64, u8> =
        HashMap::try_from(ebpf.take_map("WHITELIST").unwrap())?;
    let mut blacklist: HashMap<_, u64, u8> =
        HashMap::try_from(ebpf.take_map("BLACKLIST").unwrap())?;

    load_list(WHITELIST_PATH, &mut whitelist)?;
    load_list(BLACKLIST_PATH, &mut blacklist)?;

    let program: &mut TracePoint = ebpf
        .program_mut("e_bpf_antiransomware")
        .unwrap()
        .try_into()?;
    program.attach("syscalls", "sys_enter_write")?;

    let lsm_trunc: &mut Lsm = ebpf.program_mut("check_trunc").unwrap().try_into()?;
    lsm_trunc.attach()?;
    let lsm_file_perm: &mut Lsm = ebpf
        .program_mut("check_file_permission")
        .unwrap()
        .try_into()?;
    lsm_file_perm.attach()?;

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
                while let Some(item) = inner_ring.next() {
                    if item.len() != size_of::<LinkEvent>() {
                        continue;
                    }
                    let event = unsafe { &*(item.as_ptr() as *const LinkEvent) };
                    let inode: u64 = event.inode;
                    if blacklist.get(&inode, 0).is_ok() {
                        continue;
                    }

                    let entropy: f64 = compute_entropy(&event.data[..]);
                    let command = core::ffi::CStr::from_bytes_until_nul(&event.comm)?;
                    let command = unsafe { core::str::from_utf8_unchecked(command.to_bytes()) };
                    if entropy >= 7.3 {
                        println!("[ENTROPY] Command {command} with i_node {inode} = {entropy} has been banned !");
                        let _ = write_blacklist(&mut blacklist, inode);
                    }
                }
                guard.clear_ready();
            }
        }
    }
    println!("Exiting...");

    Ok(())
}
