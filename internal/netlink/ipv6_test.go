package netlink

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_isUnusableRouteType(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		routeType int
		expected  bool
	}{
		"unreachable": {routeTypeUnreachable, true},
		"prohibit":    {routeTypeProhibit, true},
		"blackhole":   {routeTypeBlackhole, true},
		// Linux route types that can deliver packets, see
		// include/uapi/linux/rtnetlink.h.
		"unspecified": {0, false},
		"unicast":     {1, false},
		"local":       {2, false},
		"broadcast":   {3, false},
		"anycast":     {4, false},
		"multicast":   {5, false},
		"throw":       {9, false},
		"nat":         {10, false},
		"xresolve":    {11, false},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, testCase.expected,
				isUnusableRouteType(testCase.routeType))
		})
	}
}
