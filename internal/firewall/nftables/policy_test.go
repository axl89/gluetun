package nftables

import (
	"testing"

	"github.com/google/nftables"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func Test_SetIPv4AllPolicies(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		policy        string
		setupMockConn func(dialErr error, flushErr error) dialFunc
		errorContains string
	}{
		"invalid_policy": {
			policy: "invalid",
			setupMockConn: func(_, _ error) dialFunc {
				return nil
			},
			errorContains: "unknown policy",
		},
		"dial_error": {
			policy: "accept",
			setupMockConn: func(dialErr error, _ error) dialFunc {
				return func() (conn, error) { return nil, dialErr }
			},
			errorContains: "creating nftables connection",
		},
		"flush_error": {
			policy: "drop",
			setupMockConn: func(_ error, flushErr error) dialFunc {
				ctrl := gomock.NewController(t)
				mockConn := NewMockConn(ctrl)

				mockConn.EXPECT().AddTable(gomock.Any()).DoAndReturn(func(table *nftables.Table) *nftables.Table {
					return table
				})
				mockConn.EXPECT().AddChain(gomock.Any()).DoAndReturn(func(chain *nftables.Chain) *nftables.Chain {
					return chain
				}).Times(6)
				mockConn.EXPECT().Flush().Return(flushErr)

				return func() (conn, error) { return mockConn, nil }
			},
			errorContains: "flushing nftables changes",
		},
		"success_accept": {
			policy: "accept",
			setupMockConn: func(_, _ error) dialFunc {
				ctrl := gomock.NewController(t)
				mockConn := NewMockConn(ctrl)

				mockConn.EXPECT().AddTable(gomock.Any()).DoAndReturn(func(table *nftables.Table) *nftables.Table {
					return table
				})
				mockConn.EXPECT().AddChain(gomock.Any()).DoAndReturn(func(chain *nftables.Chain) *nftables.Chain {
					return chain
				}).Times(6)
				mockConn.EXPECT().Flush().Return(nil)

				return func() (conn, error) { return mockConn, nil }
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var dialFunc dialFunc
			if testCase.setupMockConn != nil {
				dialFunc = testCase.setupMockConn(assert.AnError, assert.AnError)
			}

			firewall := &Firewall{dialFunc: dialFunc}

			ctx := t.Context()
			err := firewall.SetIPv4AllPolicies(ctx, testCase.policy)

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

func Test_SetIPv6AllPolicies(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		policy        string
		setupMockConn func(dialErr error, flushErr error) dialFunc
		errorContains string
	}{
		"invalid_policy": {
			policy: "invalid",
			setupMockConn: func(_, _ error) dialFunc {
				return nil
			},
			errorContains: "unknown policy",
		},
		"dial_error": {
			policy: "accept",
			setupMockConn: func(dialErr error, _ error) dialFunc {
				return func() (conn, error) { return nil, dialErr }
			},
			errorContains: "creating nftables connection",
		},
		"flush_error": {
			policy: "drop",
			setupMockConn: func(_ error, flushErr error) dialFunc {
				ctrl := gomock.NewController(t)
				mockConn := NewMockConn(ctrl)

				mockConn.EXPECT().AddTable(gomock.Any()).DoAndReturn(func(table *nftables.Table) *nftables.Table {
					return table
				})
				mockConn.EXPECT().AddChain(gomock.Any()).DoAndReturn(func(chain *nftables.Chain) *nftables.Chain {
					return chain
				}).Times(6)
				mockConn.EXPECT().Flush().Return(flushErr)

				return func() (conn, error) { return mockConn, nil }
			},
			errorContains: "flushing nftables changes",
		},
		"success_accept": {
			policy: "accept",
			setupMockConn: func(_, _ error) dialFunc {
				ctrl := gomock.NewController(t)
				mockConn := NewMockConn(ctrl)

				mockConn.EXPECT().AddTable(gomock.Any()).DoAndReturn(func(table *nftables.Table) *nftables.Table {
					return table
				})
				mockConn.EXPECT().AddChain(gomock.Any()).DoAndReturn(func(chain *nftables.Chain) *nftables.Chain {
					return chain
				}).Times(6)
				mockConn.EXPECT().Flush().Return(nil)

				return func() (conn, error) { return mockConn, nil }
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var dialFunc dialFunc
			if testCase.setupMockConn != nil {
				dialFunc = testCase.setupMockConn(assert.AnError, assert.AnError)
			}

			firewall := &Firewall{dialFunc: dialFunc}

			ctx := t.Context()
			err := firewall.SetIPv6AllPolicies(ctx, testCase.policy)

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
