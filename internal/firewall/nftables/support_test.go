package nftables

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func Test_IsSupported(t *testing.T) {
	t.Parallel()

	// Test with real nftables if available
	if _, exists := os.LookupEnv("NFT_AVAILABLE"); !exists {
		t.Skip("NFT_AVAILABLE not set, skipping integration test")
	}

	result := IsSupported()
	t.Logf("IsSupported: %v", result)
}

func Test_RunUserPostRules(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		setupFile     func() string
		filepath      string
		errorContains string
		warnfCalled   bool
	}{
		"file_does_not_exist": {
			filepath: "/nonexistent/path/rules.conf",
		},
		"empty_file": {
			setupFile: func() string {
				tmpDir := t.TempDir()
				filepath := filepath.Join(tmpDir, "rules.conf")
				_ = os.WriteFile(filepath, nil, 0o600)
				return filepath
			},
		},
		"comment_only_file": {
			setupFile: func() string {
				tmpDir := t.TempDir()
				filepath := filepath.Join(tmpDir, "rules.conf")
				_ = os.WriteFile(filepath, []byte("# this is a comment\n"), 0o600)
				return filepath
			},
		},
		"whitespace_only_lines": {
			setupFile: func() string {
				tmpDir := t.TempDir()
				filepath := filepath.Join(tmpDir, "rules.conf")
				_ = os.WriteFile(filepath, []byte("   \n\n  \n"), 0o600)
				return filepath
			},
		},
		"unrecognized_command_skipped": {
			setupFile: func() string {
				tmpDir := t.TempDir()
				filepath := filepath.Join(tmpDir, "rules.conf")
				_ = os.WriteFile(filepath, []byte("iptables -A INPUT -j ACCEPT\n"), 0o600)
				return filepath
			},
			warnfCalled: true,
		},
		"not_nft_command_skipped": {
			setupFile: func() string {
				tmpDir := t.TempDir()
				filepath := filepath.Join(tmpDir, "rules.conf")
				_ = os.WriteFile(filepath, []byte("nftrace\n"), 0o600)
				return filepath
			},
			warnfCalled: true,
		},
		"nft_with_no_args_skipped": {
			setupFile: func() string {
				tmpDir := t.TempDir()
				filepath := filepath.Join(tmpDir, "rules.conf")
				_ = os.WriteFile(filepath, []byte("nft\n"), 0o600)
				return filepath
			},
			warnfCalled: false,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			logger := NewMockLogger(ctrl)

			if testCase.warnfCalled {
				logger.EXPECT().Warnf(gomock.Any(), gomock.Any())
			}

			var testFilepath string
			if testCase.setupFile != nil {
				testFilepath = testCase.setupFile()
			} else {
				testFilepath = testCase.filepath
			}

			firewall := &Firewall{logger: logger}

			ctx := t.Context()
			err := firewall.RunUserPostRules(ctx, testFilepath)

			if testCase.errorContains != "" {
				assert.Error(t, err)
				if testCase.errorContains != "" {
					assert.ErrorContains(t, err, testCase.errorContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func Test_RunUserPostRules_nft_command_execution(t *testing.T) {
	t.Parallel()

	// Skip if nft is not available
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft not available")
	}

	ctrl := gomock.NewController(t)
	logger := NewMockLogger(ctrl)

	tmpDir := t.TempDir()
	filepath := filepath.Join(tmpDir, "rules.conf")

	// Create a file with a simple nft command
	_ = os.WriteFile(filepath, []byte("nft list tables\n"), 0o600)

	firewall := &Firewall{logger: logger}

	ctx := t.Context()
	err := firewall.RunUserPostRules(ctx, filepath)
	assert.NoError(t, err)
}

func Test_New(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		logger   Logger
		validate func(t *testing.T, fw *Firewall)
	}{
		"with_nil_logger": {
			logger: nil,
			validate: func(t *testing.T, fw *Firewall) {
				t.Helper()
				assert.NotNil(t, fw.dialFunc)
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			firewall := New(testCase.logger, nil)
			assert.NotNil(t, firewall)

			if testCase.validate != nil {
				testCase.validate(t, firewall)
			}
		})
	}
}
