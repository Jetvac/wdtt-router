package agent

import "context"

const sysctlPath = "/etc/sysctl.d/90-wdtt-router.conf"

// Network tuning for a tunnel server: BBR with fair queueing, and socket
// buffers large enough for the WDTT and chain sockets to absorb bursts.
const sysctlText = `# managed by wdtt-router
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.netdev_max_backlog = 16384
net.ipv4.tcp_rmem = 4096 131072 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.tcp_mtu_probing = 1
`

func reconcileSysctl(ctx context.Context, changed *[]string) error {
	_ = run(ctx, "modprobe", "tcp_bbr")
	c, err := writeIfChanged(sysctlPath, []byte(sysctlText), 0644)
	if err != nil {
		return err
	}
	if c {
		// Unknown keys (e.g. BBR missing from the kernel) must not fail the apply.
		_, _ = output(ctx, "sysctl", "-q", "-e", "-p", sysctlPath)
		*changed = append(*changed, "network tuning applied")
	}
	return nil
}
