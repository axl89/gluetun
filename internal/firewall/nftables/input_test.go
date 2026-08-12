package nftables

import (
	"net/netip"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func Test_AcceptInputThroughInterface(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		interfaceName string
		setupMockConn func() (dialFunc, *MockConn)
		errorContains string
		validateExprs func(t *testing.T, rule *nftables.Rule)
	}{
		"dial_error": {
			interfaceName: "eth0",
			setupMockConn: func() (dialFunc, *MockConn) {
				return func() (conn, error) { return nil, assert.AnError }, nil
			},
			errorContains: "creating nftables connection",
		},
		"flush_error": {
			interfaceName: "eth0",
			setupMockConn: func() (dialFunc, *MockConn) {
				ctrl := gomock.NewController(t)
				mockConn := NewMockConn(ctrl)

				mockConn.EXPECT().AddTable(gomock.Any()).DoAndReturn(func(table *nftables.Table) *nftables.Table {
					return table
				})
				mockConn.EXPECT().AddChain(gomock.Any()).DoAndReturn(func(chain *nftables.Chain) *nftables.Chain {
					return chain
				}).Times(3)
				mockConn.EXPECT().AddRule(gomock.Any())
				mockConn.EXPECT().Flush().Return(assert.AnError)

				return func() (conn, error) { return mockConn, nil }, mockConn
			},
			errorContains: "flushing",
		},
		"success_with_interface": {
			interfaceName: "tun0",
			setupMockConn: func() (dialFunc, *MockConn) {
				ctrl := gomock.NewController(t)
				mockConn := NewMockConn(ctrl)

				mockConn.EXPECT().AddTable(gomock.Any()).DoAndReturn(func(table *nftables.Table) *nftables.Table {
					return table
				})
				mockConn.EXPECT().AddChain(gomock.Any()).DoAndReturn(func(chain *nftables.Chain) *nftables.Chain {
					return chain
				}).Times(3)
				mockConn.EXPECT().AddRule(gomock.Any()).DoAndReturn(func(rule *nftables.Rule) *nftables.Rule {
					exprs := rule.Exprs
					assert.Len(t, exprs, 3)

					// Meta key IIFNAME
					metaExpr, ok := exprs[0].(*expr.Meta)
					assert.True(t, ok)
					assert.Equal(t, expr.MetaKeyIIFNAME, metaExpr.Key)

					// Cmp for interface name
					cmpExpr, ok := exprs[1].(*expr.Cmp)
					assert.True(t, ok)
					assert.Equal(t, expr.CmpOpEq, cmpExpr.Op)
					assert.Equal(t, []byte("tun0\x00"), cmpExpr.Data)

					// Verdict Accept
					verdictExpr, ok := exprs[2].(*expr.Verdict)
					assert.True(t, ok)
					assert.Equal(t, expr.VerdictAccept, verdictExpr.Kind)

					return rule
				})
				mockConn.EXPECT().Flush().Return(nil)

				return func() (conn, error) { return mockConn, nil }, mockConn
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			dialFunc, _ := testCase.setupMockConn()

			firewall := &Firewall{dialFunc: dialFunc}

			ctx := t.Context()
			err := firewall.AcceptInputThroughInterface(ctx, testCase.interfaceName)

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

func Test_AcceptInputToPort(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		intf          string
		port          uint16
		remove        bool
		setupFirewall func() *Firewall
		setupMockConn func() (dialFunc, *MockConn)

		errorContains     string
		expectedRuleCount int
	}{
		"dial_error": {
			intf: "eth0",
			port: 80,
			setupMockConn: func() (dialFunc, *MockConn) {
				return func() (conn, error) { return nil, assert.AnError }, nil
			},
			errorContains: "creating nftables connection",
		},
		"flush_error_add_mode": {
			intf: "",
			port: 443,
			setupMockConn: func() (dialFunc, *MockConn) {
				ctrl := gomock.NewController(t)
				mockConn := NewMockConn(ctrl)

				mockConn.EXPECT().AddTable(gomock.Any()).DoAndReturn(func(table *nftables.Table) *nftables.Table {
					return table
				})
				mockConn.EXPECT().AddChain(gomock.Any()).DoAndReturn(func(chain *nftables.Chain) *nftables.Chain {
					return chain
				}).Times(3)
				mockConn.EXPECT().AddRule(gomock.Any()).Times(2)
				mockConn.EXPECT().Flush().Return(assert.AnError)

				return func() (conn, error) { return mockConn, nil }, mockConn
			},
			errorContains: "flushing",
		},
		"success_add_rules_without_interface": {
			intf: "",
			port: 1234,
			setupMockConn: func() (dialFunc, *MockConn) {
				ctrl := gomock.NewController(t)
				mockConn := NewMockConn(ctrl)
				portBytes := []byte{0x04, 0xd2}

				mockConn.EXPECT().AddTable(gomock.Any()).DoAndReturn(func(table *nftables.Table) *nftables.Table {
					return table
				})
				mockConn.EXPECT().AddChain(gomock.Any()).DoAndReturn(func(chain *nftables.Chain) *nftables.Chain {
					return chain
				}).Times(3)
				mockConn.EXPECT().AddRule(gomock.Any()).DoAndReturn(func(rule *nftables.Rule) *nftables.Rule {
					exprs := rule.Exprs
					assert.Len(t, exprs, 5)

					// Protocol check (TCP or UDP)
					payloadExpr, ok := exprs[0].(*expr.Payload)
					assert.True(t, ok)
					assert.Equal(t, expr.PayloadBaseNetworkHeader, payloadExpr.Base)
					assert.Equal(t, uint32(9), payloadExpr.Offset)

					cmpExpr, ok := exprs[1].(*expr.Cmp)
					assert.True(t, ok)
					assert.Contains(t, []byte{6, 17}, cmpExpr.Data[0])

					// Port check
					portPayload, ok := exprs[2].(*expr.Payload)
					assert.True(t, ok)
					assert.Equal(t, expr.PayloadBaseTransportHeader, portPayload.Base)
					assert.Equal(t, uint32(2), portPayload.Offset)

					portCmp, ok := exprs[3].(*expr.Cmp)
					assert.True(t, ok)
					assert.Equal(t, portBytes, portCmp.Data)

					verdictExpr, ok := exprs[4].(*expr.Verdict)
					assert.True(t, ok)
					assert.Equal(t, expr.VerdictAccept, verdictExpr.Kind)

					return rule
				}).Times(2)
				mockConn.EXPECT().Flush().Return(nil)

				return func() (conn, error) { return mockConn, nil }, mockConn
			},

			expectedRuleCount: 2,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var firewall *Firewall
			if testCase.setupFirewall != nil {
				firewall = testCase.setupFirewall()
			}

			dialFunc, _ := testCase.setupMockConn()
			if firewall == nil {
				firewall = &Firewall{dialFunc: dialFunc}
			} else {
				firewall.dialFunc = dialFunc
			}

			ctx := t.Context()
			err := firewall.AcceptInputToPort(ctx, testCase.intf, testCase.port, testCase.remove)

			if testCase.errorContains != "" {
				assert.Error(t, err)
				if testCase.errorContains != "" {
					assert.ErrorContains(t, err, testCase.errorContains)
				}
			} else {
				assert.NoError(t, err)
			}
			if testCase.expectedRuleCount > 0 {
				assert.Len(t, firewall.rules, testCase.expectedRuleCount)
			}
		})
	}
}

func Test_AcceptInputToSubnet(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		intf          string
		subnet        netip.Prefix
		setupMockConn func() (dialFunc, *MockConn)
		errorContains string
	}{
		"dial_error": {
			intf:   "eth0",
			subnet: netip.MustParsePrefix("192.168.1.0/24"),
			setupMockConn: func() (dialFunc, *MockConn) {
				return func() (conn, error) { return nil, assert.AnError }, nil
			},
			errorContains: "creating nftables connection",
		},
		"flush_error": {
			intf:   "eth0",
			subnet: netip.MustParsePrefix("192.168.1.0/24"),
			setupMockConn: func() (dialFunc, *MockConn) {
				ctrl := gomock.NewController(t)
				mockConn := NewMockConn(ctrl)

				mockConn.EXPECT().AddTable(gomock.Any()).DoAndReturn(func(table *nftables.Table) *nftables.Table {
					return table
				})
				mockConn.EXPECT().AddChain(gomock.Any()).DoAndReturn(func(chain *nftables.Chain) *nftables.Chain {
					return chain
				}).Times(3)
				mockConn.EXPECT().AddRule(gomock.Any())
				mockConn.EXPECT().Flush().Return(assert.AnError)

				return func() (conn, error) { return mockConn, nil }, mockConn
			},
			errorContains: "flushing",
		},
		"success_ipv4_with_interface": {
			intf:   "eth0",
			subnet: netip.MustParsePrefix("10.0.0.0/8"),
			setupMockConn: func() (dialFunc, *MockConn) {
				ctrl := gomock.NewController(t)
				mockConn := NewMockConn(ctrl)

				mockConn.EXPECT().AddTable(gomock.Any()).DoAndReturn(func(table *nftables.Table) *nftables.Table {
					return table
				})
				mockConn.EXPECT().AddChain(gomock.Any()).DoAndReturn(func(chain *nftables.Chain) *nftables.Chain {
					return chain
				}).Times(3)
				mockConn.EXPECT().AddRule(gomock.Any()).DoAndReturn(func(rule *nftables.Rule) *nftables.Rule {
					exprs := rule.Exprs
					assert.Len(t, exprs, 5)

					// Interface check
					metaExpr, ok := exprs[0].(*expr.Meta)
					assert.True(t, ok)
					assert.Equal(t, expr.MetaKeyIIFNAME, metaExpr.Key)

					// IPv4 destination payload offset
					payloadExpr, ok := exprs[2].(*expr.Payload)
					assert.True(t, ok)
					assert.Equal(t, uint32(16), payloadExpr.Offset)
					assert.Equal(t, uint32(4), payloadExpr.Len)

					// Cmp for IP address
					cmpExpr, ok := exprs[3].(*expr.Cmp)
					assert.True(t, ok)
					assert.Equal(t, []byte{10, 0, 0, 0}, cmpExpr.Data)

					// Verdict
					verdictExpr, ok := exprs[4].(*expr.Verdict)
					assert.True(t, ok)
					assert.Equal(t, expr.VerdictAccept, verdictExpr.Kind)

					return rule
				})
				mockConn.EXPECT().Flush().Return(nil)

				return func() (conn, error) { return mockConn, nil }, mockConn
			},
		},
		"success_ipv6_with_interface": {
			intf:   "eth0",
			subnet: netip.MustParsePrefix("2001:db8::/32"),
			setupMockConn: func() (dialFunc, *MockConn) {
				ctrl := gomock.NewController(t)
				mockConn := NewMockConn(ctrl)

				mockConn.EXPECT().AddTable(gomock.Any()).DoAndReturn(func(table *nftables.Table) *nftables.Table {
					return table
				})
				mockConn.EXPECT().AddChain(gomock.Any()).DoAndReturn(func(chain *nftables.Chain) *nftables.Chain {
					return chain
				}).Times(3)
				mockConn.EXPECT().AddRule(gomock.Any()).DoAndReturn(func(rule *nftables.Rule) *nftables.Rule {
					exprs := rule.Exprs
					assert.Len(t, exprs, 5)

					// IPv6 destination payload offset
					payloadExpr, ok := exprs[2].(*expr.Payload)
					assert.True(t, ok)
					assert.Equal(t, uint32(24), payloadExpr.Offset)
					assert.Equal(t, uint32(16), payloadExpr.Len)

					return rule
				})
				mockConn.EXPECT().Flush().Return(nil)

				return func() (conn, error) { return mockConn, nil }, mockConn
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			dialFunc, _ := testCase.setupMockConn()

			firewall := &Firewall{dialFunc: dialFunc}

			ctx := t.Context()
			err := firewall.AcceptInputToSubnet(ctx, testCase.intf, testCase.subnet)

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
