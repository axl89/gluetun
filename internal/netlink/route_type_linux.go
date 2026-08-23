//go:build linux

package netlink

import "golang.org/x/sys/unix"

// Route types from the Linux kernel rtnetlink API, see
// include/uapi/linux/rtnetlink.h.
const (
	routeTypeUnreachable = unix.RTN_UNREACHABLE
	routeTypeProhibit    = unix.RTN_PROHIBIT
	routeTypeBlackhole   = unix.RTN_BLACKHOLE
)
