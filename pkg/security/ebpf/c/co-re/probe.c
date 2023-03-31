#include "ktypes.h"
#include "bpf_endian.h"
#include "bpf_tracing.h"

#include "maps.h"

SEC("kprobe/security_bprm_check")
int BPF_KPROBE(kprobe_security_bprm_check, struct linux_binprm *bprm) {
    bpf_printk("we're on!\n");
    return 0;
}

// This number will be interpreted by elf-loader to set the current running kernel version
__u32 _version SEC("version") = 0xFFFFFFFE; // NOLINT(bugprone-reserved-identifier)

char _license[] SEC("license") = "GPL"; // NOLINT(bugprone-reserved-identifier)
