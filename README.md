# ebpf-antiransomware

A behavioural anti-ransomware agent for Linux, written in Rust with [aya](https://aya-rs.dev).
It measures the entropy of file writes from inside the kernel, and when a process starts
writing high-entropy data over files, it blocks that binary through BPF-LSM.

This is a Rust/aya rewrite of my original C implementation. Enjoy!

## How it works

There are three stages. They share two eBPF maps, a whitelist and a blacklist, both keyed by
the inode of the writing process's executable.

```
 sys_enter_write                userspace daemon              LSM hooks
 (tracepoint)                   (tokio)                       (file_permission,
                                                               inode_setattr)
      |                              |                              |
  sample 512 bytes  --ring buf-->  Shannon entropy                  |
  of the write                     > 7.3 ?                          |
      |                              |                              |
  skip if inode in                  blacklist the                 deny (-EPERM)
  whitelist/blacklist               executable inode  --map-->    any write/truncate
                                     (map + blacklist.txt)         from a blacklisted inode
```

A tracepoint on `sys_enter_write` runs first. It resolves the executable inode of the writing
process (`task->mm->exe_file->f_inode->i_ino`), drops the event if that inode is whitelisted
or already blacklisted, copies a 512-byte sample of the write, and pushes it to userspace over
a ring buffer.

The daemon reads each sample and computes its Shannon entropy. When the entropy goes above the
threshold (7.3 out of 8), the write looks like ciphertext, so the daemon adds the executable's
inode to the blacklist map and appends it to `blacklist.txt`.

From then on, two BPF-LSM programs do the enforcement. `file_permission` and `inode_setattr`
return `-EPERM` for any write or truncation coming from a blacklisted inode, so the operation
fails before it touches the file.

The agent keys everything on the executable inode rather than the PID. Banning one inode
therefore stops every process running that binary, including ones that start later. The
whitelist and blacklist live on disk and are reloaded at startup, so a ban survives a restart
of the daemon.

## Requirements

- Linux kernel 5.7 or newer with BPF-LSM enabled (see below).
- Rust toolchains: `rustup toolchain install stable` and
  `rustup toolchain install nightly --component rust-src`.
- `bpf-linker`: `cargo install bpf-linker`.
- `aya-tool`, used to generate the kernel type bindings. See
  [aya-rs/aya](https://github.com/aya-rs/aya).
- Root privileges to load the programs. The cargo runner uses `sudo`.

### Enabling BPF-LSM

BPF-LSM is off by default on most distributions. You need to add `bpf` to the kernel LSM list
while keeping the ones already active (`cat /sys/kernel/security/lsm` prints them). Edit
`/etc/default/grub`:

```
GRUB_CMDLINE_LINUX_DEFAULT="quiet splash lsm=lockdown,capability,landlock,yama,apparmor,ima,evm,bpf"
```

Regenerate GRUB and reboot:

```shell
sudo update-grub
sudo reboot
```

After the reboot, check that `bpf` shows up in `cat /sys/kernel/security/lsm`.

## Setup and build

`setup.sh` generates the kernel bindings (`vmlinux.rs`), builds a starting whitelist from the
system binaries, and creates `blacklist.txt` and `safe_test.txt`:

```shell
./setup.sh
cargo run --release
```

`vmlinux.rs` comes from this machine's BTF and is tied to its kernel. On a different kernel you
may hit struct errors, in which case regenerate it:

```shell
aya-tool generate task_struct iattr mm_struct > e-bpf-antiransomware-ebpf/src/vmlinux.rs
```

## Configuration

`whitelist.txt` holds one executable path per line. The daemon resolves each to an inode at
startup and never scores writes from those binaries.

`blacklist.txt` holds one inode per line. It is loaded at startup and appended to whenever a
new binary is detected.

## Testing

`test/test.c` is a small pseudo-ransomware. It reads 4 KB from `/dev/urandom` and overwrites
`safe_test.txt` with it.

```shell
cc test/test.c -o test/a.out
./test/a.out
```

With the agent running, the first write is caught on entropy, the binary's inode is
blacklisted, and the LSM hooks reject any further write or truncation from it.

## Limitations

Detection is asynchronous. A handful of writes can slip through between the first malicious
write and the moment the inode lands in the blacklist. The LSM stage then shuts the door on
everything the binary does afterwards. Entropy on its own also catches legitimate processes
that write compressed or encrypted data, so those binaries belong in the whitelist.

## License

Dual MIT / Apache-2.0, except the eBPF code, which is dual MIT / GPL-2.0. See the LICENSE files.