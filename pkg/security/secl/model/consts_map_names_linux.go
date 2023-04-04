// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package model

var bpfMapNames = []string{
	"path_id",
	"enabled_events",
	"buffer_selector",
	"dr_erpc_state",
	"dr_erpc_buffer",
	"inode_discarder_revisions",
	"discarders_revision",
	"filter_policy",
	"mmap_flags_approvers",
	"mmap_protection_approvers",
	"mprotect_vm_protection_approvers",
	"mprotect_req_protection_approvers",
	"open_flags_approvers",
	"pipefs_mountid",
	"selinux_enforce_status",
	"splice_entry_flags_approvers",
	"splice_exit_flags_approvers",
	"activity_dumps_config",
	"activity_dump_config_defaults",
	"traced_cgroups",
	"cgroup_wait_list",
	"traced_pids",
	"traced_comms",
	"basename_approvers",
	"register_netdevice_cache",
	"netdevice_lookup_cache",
	"fd_link_pid",
	"activity_dump_rate_limiters",
	"mount_ref",
	"bpf_maps",
	"bpf_progs",
	"tgid_fd_map_id",
	"tgid_fd_prog_id",
	"syscalls",
	"proc_cache",
	"pid_cache",
	"pid_ignored",
	"exec_count_fb",
	"exec_count_bb",
	"exec_pid_transfer",
	"netns_cache",
	"span_tls",
	"inode_discarders",
	"pid_discarders",
	"pathnames",
	"flow_pid",
	"conntrack",
	"io_uring_ctx_pid",
	"veth_state_machine",
	"veth_devices",
	"veth_device_name_to_ifindex",
	"exec_file_cache",
	"syscall_monitor",
	"syscall_table",
	"cgroup_tracing_event_gen",
	"discarder_stats_fb",
	"discarder_stats_bb",
	"str_array_buffers",
	"process_event_gen",
	"dr_erpc_stats_fb",
	"dr_erpc_stats_bb",
	"is_discarded_by_inode_gen",
	"dns_event",
	"packets",
	"selinux_write_buffer",
	"events",
	"events_stats",
	"events_ringbuf_stats",
}
