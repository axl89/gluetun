package nftables

import (
	"runtime/debug"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Version(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		buildInfo   *debug.BuildInfo
		expectedErr bool
	}{
		"dependency_found": {
			buildInfo: &debug.BuildInfo{
				Deps: []*debug.Module{
					{Path: "github.com/google/nftables", Version: "v0.2.0"},
					{Path: "other/dep", Version: "v1.0.0"},
				},
			},
			expectedErr: false,
		},
		"dependency_not_found": {
			buildInfo: &debug.BuildInfo{
				Deps: []*debug.Module{
					{Path: "other/dep", Version: "v1.0.0"},
				},
			},
			expectedErr: true,
		},
		"empty_deps": {
			buildInfo: &debug.BuildInfo{
				Deps: []*debug.Module{},
			},
			expectedErr: true,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			firewall := &Firewall{buildInfo: testCase.buildInfo}

			ctx := t.Context()
			version, err := firewall.Version(ctx)

			if testCase.expectedErr {
				assert.Error(t, err)
				assert.Empty(t, version)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, "v0.2.0 (google/nftables)", version)
			}
		})
	}
}
