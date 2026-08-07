package nftables

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func Test_IsSupported(t *testing.T) {
	t.Parallel()

	expectedSupported := true

	// Check nft is available and working
	nftPath, err := exec.LookPath("nft")
	if err != nil {
		t.Skip("nft command not found")
	}
	cmd := exec.CommandContext(t.Context(), nftPath, "list", "tables")
	data, err := cmd.CombinedOutput()
	if err != nil {
		// nft failed so most likely nftables is not supported
		expectedSupported = false
	} else {
		for line := range strings.SplitSeq(strings.TrimSpace(string(data)), "\n") {
			if !strings.HasPrefix(line, "table ") {
				t.Skipf("nft command output does not contain expected table lines: %s",
					string(data))
			}
		}
	}

	supported := IsSupported()
	assert.Equal(t, expectedSupported, supported)
}

func Test_Version(t *testing.T) {
	t.Parallel()

	buildInfo := &debug.BuildInfo{
		Deps: []*debug.Module{
			{
				Path:    "github.com/google/nftables",
				Version: "v0.3.0",
			},
		},
	}

	logger := (Logger)(nil)
	firewall := New(logger, buildInfo)
	version, err := firewall.Version(t.Context())
	require.NoError(t, err)
	t.Log(version)
}

func Test_RunUserPostRules(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		setupFile       func(t *testing.T, dir string) string
		expectError     bool
		expectWarnf     bool
		errorContains   string
		warnfFormatHint string
	}{
		"file does not exist - returns nil": {
			setupFile: func(t *testing.T, dir string) string {
				t.Helper()
				return filepath.Join(dir, "does_not_exist.txt")
			},
			expectError: false,
		},
		"empty file - succeeds": {
			setupFile: func(t *testing.T, dir string) string {
				t.Helper()
				path := filepath.Join(dir, "empty.txt")
				require.NoError(t, os.WriteFile(path, []byte(""), 0o644)) //nolint:gosec // test file
				return path
			},
			expectError: false,
		},
		"comment lines only - succeeds": {
			setupFile: func(t *testing.T, dir string) string {
				t.Helper()
				path := filepath.Join(dir, "comments.txt")
				content := "# This is a comment\n# Another comment\n\n"
				require.NoError(t, os.WriteFile(path, []byte(content), 0o644)) //nolint:gosec // test file
				return path
			},
			expectError: false,
		},
		"blank lines only - succeeds": {
			setupFile: func(t *testing.T, dir string) string {
				t.Helper()
				path := filepath.Join(dir, "blanks.txt")
				content := "\n\n\n   \n"
				require.NoError(t, os.WriteFile(path, []byte(content), 0o644)) //nolint:gosec // test file
				return path
			},
			expectError: false,
		},
		"non-nft command skipped with warning": {
			setupFile: func(t *testing.T, dir string) string {
				t.Helper()
				path := filepath.Join(dir, "skip.txt")
				content := "iptables -A INPUT -j ACCEPT\n"
				require.NoError(t, os.WriteFile(path, []byte(content), 0o644)) //nolint:gosec // test file
				return path
			},
			expectError:     false,
			expectWarnf:     true,
			warnfFormatHint: "skipping unrecognized command",
		},
		"nftables command prefix skipped with warning": {
			setupFile: func(t *testing.T, dir string) string {
				t.Helper()
				path := filepath.Join(dir, "nftables_prefix.txt")
				content := "nftables something\n"
				require.NoError(t, os.WriteFile(path, []byte(content), 0o644)) //nolint:gosec // test file
				return path
			},
			expectError:     false,
			expectWarnf:     true,
			warnfFormatHint: "skipping unrecognized command",
		},
		"nftrace command prefix skipped with warning": {
			setupFile: func(t *testing.T, dir string) string {
				t.Helper()
				path := filepath.Join(dir, "nftrace_prefix.txt")
				content := "nftrace something\n"
				require.NoError(t, os.WriteFile(path, []byte(content), 0o644)) //nolint:gosec // test file
				return path
			},
			expectError:     false,
			expectWarnf:     true,
			warnfFormatHint: "skipping unrecognized command",
		},
		"only nft without arguments - skipped": {
			setupFile: func(t *testing.T, dir string) string {
				t.Helper()
				path := filepath.Join(dir, "nft_only.txt")
				content := "nft\n"
				require.NoError(t, os.WriteFile(path, []byte(content), 0o644)) //nolint:gosec // test file
				return path
			},
			expectError: false,
			expectWarnf: false,
		},
		"invalid nft command - error": {
			setupFile: func(t *testing.T, dir string) string {
				t.Helper()
				path := filepath.Join(dir, "invalid.txt")
				content := "nft invalid_command_that_does_not_exist\n"
				require.NoError(t, os.WriteFile(path, []byte(content), 0o644)) //nolint:gosec // test file
				return path
			},
			expectError:   true,
			errorContains: "running user rule on line 1",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			logger := NewMockLogger(ctrl)

			// Set up expected Warnf call if needed
			if testCase.expectWarnf {
				logger.EXPECT().Warnf(gomock.Any(), gomock.Any()).AnyTimes()
			}

			buildInfo := (*debug.BuildInfo)(nil)
			firewall := New(logger, buildInfo)

			dir := t.TempDir()
			filepath := testCase.setupFile(t, dir)

			err := firewall.RunUserPostRules(t.Context(), filepath)

			if testCase.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), testCase.errorContains)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func Test_RunUserPostRules_valid_nft_command(t *testing.T) {
	t.Parallel()

	if os.Getenv("NFT_AVAILABLE") != "1" {
		t.Skip("nft command not available")
	}

	ctrl := gomock.NewController(t)
	logger := NewMockLogger(ctrl)
	buildInfo := (*debug.BuildInfo)(nil)
	firewall := New(logger, buildInfo)

	dir := t.TempDir()
	path := filepath.Join(dir, "valid.txt")
	// Add and then delete a rule in a unique table to avoid affecting system
	content := `
nft add table inet test_gluetun_` + filepath.Base(dir) + `
nft add chain inet test_gluetun_` + filepath.Base(dir) + ` input { type filter hook input priority 0; }
nft delete table inet test_gluetun_` + filepath.Base(dir) + `
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644)) //nolint:gosec // test file

	err := firewall.RunUserPostRules(t.Context(), path)
	assert.NoError(t, err)
}
