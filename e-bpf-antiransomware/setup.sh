find -L /usr/bin /bin /sbin /usr/sbin /usr/libexec /usr/local/bin /usr/lib/apt/methods /usr/lib/git-core /usr/lib/firefox /usr/share/code /opt /snap/*/current/usr/bin -type f -executable 2>/dev/null > whitelist.txt
touch blacklist.txt
aya-tool generate task_struct iattr mm_struct > e-bpf-antiransomware-ebpf/src/vmlinux.rs || echo "you should have aya-tool to build this repository."
echo "Hello,

This is a file to test a pseudo-ransomware. It should be overwritten once, but not twice !" > safe_test.txt

echo "setup finished, you can build and launch the binary with :

RUST_LOG=info cargo run --release"