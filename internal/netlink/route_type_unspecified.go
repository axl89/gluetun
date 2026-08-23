//go:build !linux

package netlink

// Route types values that can never match on non-Linux platforms,
// see route_type_linux.go for the Linux values.
const (
	routeTypeUnreachable = -1
	routeTypeProhibit    = -2
	routeTypeBlackhole   = -3
)
