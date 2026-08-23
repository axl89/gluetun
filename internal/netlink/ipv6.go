package netlink

import (
	"fmt"
)

func (n *NetLink) IsIPv6Supported() (supported bool, err error) {
	routes, err := n.RouteList(FamilyV6)
	if err != nil {
		return false, fmt.Errorf("listing IPv6 routes: %w", err)
	}

	// Check each route for IPv6 due to Podman bug listing IPv4 routes
	// as IPv6 routes at container start, see:
	// https://github.com/qdm12/gluetun/issues/1241#issuecomment-1333405949
	for _, route := range routes {
		sourceIsIPv6 := route.Src.IsValid() && route.Src.Is6()
		destinationIsIPv6 := route.Dst.IsValid() && route.Dst.Addr().Is6()
		// Skip routes that can never deliver packets, in particular
		// `unreachable default dev lo` routes that some kernels install
		// in containers without IPv6. The netlink library synthesizes a
		// `::/0` destination for them, and `::` is the unspecified
		// address, not the loopback one, so they would otherwise be
		// wrongly counted as IPv6 support.
		// See: https://github.com/qdm12/gluetun/issues/3444
		switch {
		case !sourceIsIPv6 && !destinationIsIPv6,
			destinationIsIPv6 && route.Dst.Addr().IsLoopback(),
			isUnusableRouteType(route.Type):
			continue
		}

		link, err := n.LinkByIndex(route.LinkIndex)
		if err != nil {
			return false, fmt.Errorf("finding link corresponding to route: %w", err)
		}

		n.debugLogger.Debugf("IPv6 is supported by link %s", link.Name)
		return true, nil
	}

	n.debugLogger.Debugf("IPv6 is not supported after searching %d routes",
		len(routes))
	return false, nil
}

// isUnusableRouteType reports whether a route of the given type can
// never deliver packets, and therefore cannot be evidence of IPv6
// support.
func isUnusableRouteType(routeType int) bool {
	switch routeType {
	case routeTypeUnreachable, routeTypeProhibit, routeTypeBlackhole:
		return true
	default:
		return false
	}
}
