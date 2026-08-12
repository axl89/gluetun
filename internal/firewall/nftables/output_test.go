package nftables

import (
	"net/netip"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func Test_AcceptIpv6MulticastOutput(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		intf          string
		setupMockConn func() (dialFunc, *MockConn)
		errorContains string
	}{
		"dial_error": {
			intf: "eth0",
			setupMockConn: func() (dialFunc, *MockConn) {
				return func() (conn, error) { return nil, assert.AnError }, nil
			},
			errorContains: "creating nftables connection",
		},
		"flush_error": {
			intf: "eth0",
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
			intf: "eth0",
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
					assert.Len(t, exprs, 6)

					// Interface check with OIFNAME
					metaExpr, ok := exprs[0].(*expr.Meta)
					assert.True(t, ok)
					assert.Equal(t, expr.MetaKeyOIFNAME, metaExpr.Key)
					cmpExpr, ok := exprs[1].(*expr.Cmp)
					assert.True(t, ok)
					assert.Equal(t, []byte("eth0\x00"), cmpExpr.Data)

					// IPv6 multicast destination payload check
					payloadExpr, ok := exprs[2].(*expr.Payload)
					assert.True(t, ok)
					assert.Equal(t, expr.PayloadBaseNetworkHeader, payloadExpr.Base)
					assert.Equal(t, uint32(24), payloadExpr.Offset)
					assert.Equal(t, uint32(16), payloadExpr.Len)

					// Bitwise for multicast mask
					bwExpr, ok := exprs[3].(*expr.Bitwise)
					assert.True(t, ok)
					assert.Equal(t, uint32(16), bwExpr.Len)

					// Cmp for multicast address
					cmpAddr, ok := exprs[4].(*expr.Cmp)
					assert.True(t, ok)
					assert.Equal(t, []byte{
						0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
						0x00, 0x00, 0x00, 0x01, 0xff, 0x00, 0x00, 0x00,
					}, cmpAddr.Data)

					// Verdict
					verdictExpr, ok := exprs[5].(*expr.Verdict)
					assert.True(t, ok)
					assert.Equal(t, expr.VerdictAccept, verdictExpr.Kind)

					return rule
				})
				mockConn.EXPECT().Flush().Return(nil)

				return func() (conn, error) { return mockConn, nil }, mockConn
			},
		},
		"success_without_interface": {
			intf: "",
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
					// Should be 4 exprs without interface: payload, bitwise, cmp, verdict
					assert.Len(t, exprs, 4)
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

			var dialFunc dialFunc
			if testCase.setupMockConn != nil {
				dialFunc, _ = testCase.setupMockConn()
			}

			firewall := &Firewall{dialFunc: dialFunc}

			ctx := t.Context()
			err := firewall.AcceptIpv6MulticastOutput(ctx, testCase.intf)

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

func Test_AcceptOutputTrafficToVPN(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		intf          string
		connection    models.Connection
		remove        bool
		setupFirewall func() *Firewall
		setupMockConn func() (dialFunc, *MockConn)

		errorContains     string
		expectedRuleCount int
	}{
		"dial_error": {
			intf: "eth0",
			connection: models.Connection{
				IP:       netip.MustParseAddr("1.2.3.4"),
				Port:     1194,
				Protocol: "udp",
			},
			setupMockConn: func() (dialFunc, *MockConn) {
				return func() (conn, error) { return nil, assert.AnError }, nil
			},
			errorContains: "creating nftables connection",
		},
		"unsupported_protocol": {
			intf: "eth0",
			connection: models.Connection{
				IP:       netip.MustParseAddr("1.2.3.4"),
				Port:     1194,
				Protocol: "icmp",
			},
			setupMockConn: func() (dialFunc, *MockConn) {
				ctrl := gomock.NewController(t)
				mockConn := NewMockConn(ctrl)

				mockConn.EXPECT().AddTable(gomock.Any()).DoAndReturn(func(table *nftables.Table) *nftables.Table {
					return table
				})
				mockConn.EXPECT().AddChain(gomock.Any()).DoAndReturn(func(chain *nftables.Chain) *nftables.Chain {
					return chain
				}).Times(3)

				return func() (conn, error) { return mockConn, nil }, mockConn
			},
			errorContains: "unsupported protocol",
		},
		"flush_error_add_mode": {
			intf: "eth0",
			connection: models.Connection{
				IP:       netip.MustParseAddr("1.2.3.4"),
				Port:     1194,
				Protocol: "udp",
			},
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
		"success_tcp_connection_with_interface": {
			intf: "eth0",
			connection: models.Connection{
				IP:       netip.MustParseAddr("198.51.100.1"),
				Port:     443,
				Protocol: "tcp",
			},
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
					// With interface: Meta+Cmp(iface) + Payload+Cmp(ip) + Meta+Cmp(proto) + Payload+Cmp(port) + Verdict = 9
					assert.Len(t, exprs, 9)

					// Interface check
					metaExpr, ok := exprs[0].(*expr.Meta)
					assert.True(t, ok)
					assert.Equal(t, expr.MetaKeyOIFNAME, metaExpr.Key)

					// IPv4 destination address check
					payloadExpr, ok := exprs[2].(*expr.Payload)
					assert.True(t, ok)
					assert.Equal(t, uint32(16), payloadExpr.Offset)
					cmpExpr, ok := exprs[3].(*expr.Cmp)
					assert.True(t, ok)
					assert.Equal(t, []byte{198, 51, 100, 1}, cmpExpr.Data)

					// Protocol check with MetaKeyL4PROTO
					protoMeta, ok := exprs[4].(*expr.Meta)
					assert.True(t, ok)
					assert.Equal(t, expr.MetaKeyL4PROTO, protoMeta.Key)
					protoCmp, ok := exprs[5].(*expr.Cmp)
					assert.True(t, ok)
					assert.Equal(t, []byte{6}, protoCmp.Data)

					// Port check
					portPayload, ok := exprs[6].(*expr.Payload)
					assert.True(t, ok)
					assert.Equal(t, expr.PayloadBaseTransportHeader, portPayload.Base)
					assert.Equal(t, uint32(2), portPayload.Offset)

					return rule
				})
				mockConn.EXPECT().Flush().Return(nil)

				return func() (conn, error) { return mockConn, nil }, mockConn
			},

			expectedRuleCount: 1,
		},
		"success_ipv6_udp_connection": {
			intf: "eth0",
			connection: models.Connection{
				IP:       netip.MustParseAddr("2001:db8::1"),
				Port:     1194,
				Protocol: "udp",
			},
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
					// With interface: 9 expressions
					assert.Len(t, exprs, 9)

					// IPv6 destination address offset is 24 (at index 2 after iface meta+cmp)
					payloadExpr, ok := exprs[2].(*expr.Payload)
					assert.True(t, ok)
					assert.Equal(t, uint32(24), payloadExpr.Offset)
					assert.Equal(t, uint32(16), payloadExpr.Len)

					// UDP protocol (at index 5 after iface+ip+protocol meta+cmp)
					protoCmp, ok := exprs[5].(*expr.Cmp)
					assert.True(t, ok)
					assert.Equal(t, []byte{17}, protoCmp.Data)

					return rule
				})
				mockConn.EXPECT().Flush().Return(nil)

				return func() (conn, error) { return mockConn, nil }, mockConn
			},

			expectedRuleCount: 1,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var firewall *Firewall
			if testCase.setupFirewall != nil {
				firewall = testCase.setupFirewall()
			}

			var dialFunc dialFunc
			if testCase.setupMockConn != nil {
				dialFunc, _ = testCase.setupMockConn()
			}
			if firewall == nil {
				firewall = &Firewall{dialFunc: dialFunc}
			} else {
				firewall.dialFunc = dialFunc
			}

			ctx := t.Context()
			err := firewall.AcceptOutputTrafficToVPN(ctx, testCase.intf, testCase.connection, testCase.remove)

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

func Test_AcceptOutput(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		protocol      string
		intf          string
		ip            netip.Addr
		port          uint16
		remove        bool
		setupFirewall func() *Firewall
		setupMockConn func() (dialFunc, *MockConn)

		errorContains     string
		expectedRuleCount int
	}{
		"dial_error": {
			protocol: "tcp",
			ip:       netip.MustParseAddr("1.2.3.4"),
			port:     80,
			setupMockConn: func() (dialFunc, *MockConn) {
				return func() (conn, error) { return nil, assert.AnError }, nil
			},
			errorContains: "creating nftables connection",
		},
		"unsupported_protocol": {
			protocol: "icmp",
			ip:       netip.MustParseAddr("1.2.3.4"),
			port:     80,
			setupMockConn: func() (dialFunc, *MockConn) {
				ctrl := gomock.NewController(t)
				mockConn := NewMockConn(ctrl)

				mockConn.EXPECT().AddTable(gomock.Any()).DoAndReturn(func(table *nftables.Table) *nftables.Table {
					return table
				})
				mockConn.EXPECT().AddChain(gomock.Any()).DoAndReturn(func(chain *nftables.Chain) *nftables.Chain {
					return chain
				}).Times(3)

				return func() (conn, error) { return mockConn, nil }, mockConn
			},
			errorContains: "unsupported protocol",
		},
		"flush_error_add_mode": {
			protocol: "tcp",
			ip:       netip.MustParseAddr("1.2.3.4"),
			port:     80,
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
		"success_tcp_ipv4_with_interface": {
			protocol: "tcp",
			intf:     "eth0",
			ip:       netip.MustParseAddr("192.168.1.1"),
			port:     443,
			setupMockConn: func() (dialFunc, *MockConn) {
				ctrl := gomock.NewController(t)
				mockConn := NewMockConn(ctrl)
				portBytes := []byte{0x01, 0xbb}

				mockConn.EXPECT().AddTable(gomock.Any()).DoAndReturn(func(table *nftables.Table) *nftables.Table {
					return table
				})
				mockConn.EXPECT().AddChain(gomock.Any()).DoAndReturn(func(chain *nftables.Chain) *nftables.Chain {
					return chain
				}).Times(3)
				mockConn.EXPECT().AddRule(gomock.Any()).DoAndReturn(func(rule *nftables.Rule) *nftables.Rule {
					exprs := rule.Exprs
					assert.Len(t, exprs, 9)

					// Interface
					metaExpr, ok := exprs[0].(*expr.Meta)
					assert.True(t, ok)
					assert.Equal(t, expr.MetaKeyOIFNAME, metaExpr.Key)

					// IPv4 dest address
					payloadExpr, ok := exprs[2].(*expr.Payload)
					assert.True(t, ok)
					assert.Equal(t, uint32(16), payloadExpr.Offset)
					cmpExpr, ok := exprs[3].(*expr.Cmp)
					assert.True(t, ok)
					assert.Equal(t, []byte{192, 168, 1, 1}, cmpExpr.Data)

					// TCP protocol
					protoCmp, ok := exprs[5].(*expr.Cmp)
					assert.True(t, ok)
					assert.Equal(t, []byte{6}, protoCmp.Data)

					// Port
					portCmp, ok := exprs[7].(*expr.Cmp)
					assert.True(t, ok)
					assert.Equal(t, portBytes, portCmp.Data)

					return rule
				})
				mockConn.EXPECT().Flush().Return(nil)

				return func() (conn, error) { return mockConn, nil }, mockConn
			},

			expectedRuleCount: 1,
		},
	}
	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var firewall *Firewall
			if testCase.setupFirewall != nil {
				firewall = testCase.setupFirewall()
			}

			var dialFunc dialFunc
			if testCase.setupMockConn != nil {
				dialFunc, _ = testCase.setupMockConn()
			}
			if firewall == nil {
				firewall = &Firewall{dialFunc: dialFunc}
			} else {
				firewall.dialFunc = dialFunc
			}

			ctx := t.Context()
			err := firewall.AcceptOutput(ctx, testCase.protocol, testCase.intf, testCase.ip, testCase.port, testCase.remove)

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

func Test_AcceptOutputFromIPPortToIPPort(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		protocol      string
		intf          string
		source        netip.AddrPort
		destination   netip.AddrPort
		remove        bool
		setupFirewall func() *Firewall
		setupMockConn func() (dialFunc, *MockConn)

		errorContains     string
		expectedRuleCount int
	}{
		"dial_error": {
			protocol:    "tcp",
			source:      netip.MustParseAddrPort("127.0.0.1:1234"),
			destination: netip.MustParseAddrPort("192.168.1.1:80"),
			setupMockConn: func() (dialFunc, *MockConn) {
				return func() (conn, error) { return nil, assert.AnError }, nil
			},
			errorContains: "creating nftables connection",
		},
		"unsupported_protocol": {
			protocol:    "icmp",
			source:      netip.MustParseAddrPort("127.0.0.1:1234"),
			destination: netip.MustParseAddrPort("192.168.1.1:80"),
			setupMockConn: func() (dialFunc, *MockConn) {
				ctrl := gomock.NewController(t)
				mockConn := NewMockConn(ctrl)

				mockConn.EXPECT().AddTable(gomock.Any()).DoAndReturn(func(table *nftables.Table) *nftables.Table {
					return table
				})
				mockConn.EXPECT().AddChain(gomock.Any()).DoAndReturn(func(chain *nftables.Chain) *nftables.Chain {
					return chain
				}).Times(3)

				return func() (conn, error) { return mockConn, nil }, mockConn
			},
			errorContains: "unsupported protocol",
		},
		"success_ipv4_tcp": {
			protocol:    "tcp",
			intf:        "eth0",
			source:      netip.MustParseAddrPort("10.0.0.5:45678"),
			destination: netip.MustParseAddrPort("192.168.1.1:80"),
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
					// 13 expressions:
					// 0: Meta(OIFNAME), 1: Cmp(interface)
					// 2: Payload(src IP), 3: Cmp(src IP)
					// 4: Payload(dst IP), 5: Cmp(dst IP)
					// 6: Meta(L4PROTO), 7: Cmp(proto)
					// 8: Payload(src port), 9: Cmp(src port)
					// 10: Payload(dst port), 11: Cmp(dst port)
					// 12: VerdictAccept
					assert.Len(t, exprs, 13)

					// Interface check
					metaExpr, ok := exprs[0].(*expr.Meta)
					assert.True(t, ok)
					assert.Equal(t, expr.MetaKeyOIFNAME, metaExpr.Key)

					// Source IPv4 address (offset 12)
					srcPayload, ok := exprs[2].(*expr.Payload)
					assert.True(t, ok)
					assert.Equal(t, uint32(12), srcPayload.Offset)
					srcCmp, ok := exprs[3].(*expr.Cmp)
					assert.True(t, ok)
					assert.Equal(t, []byte{10, 0, 0, 5}, srcCmp.Data)

					// Dest IPv4 address (offset 16)
					dstPayload, ok := exprs[4].(*expr.Payload)
					assert.True(t, ok)
					assert.Equal(t, uint32(16), dstPayload.Offset)
					dstCmp, ok := exprs[5].(*expr.Cmp)
					assert.True(t, ok)
					assert.Equal(t, []byte{192, 168, 1, 1}, dstCmp.Data)

					// Protocol with MetaKeyL4PROTO
					protoMeta, ok := exprs[6].(*expr.Meta)
					assert.True(t, ok)
					assert.Equal(t, expr.MetaKeyL4PROTO, protoMeta.Key)
					protoCmp, ok := exprs[7].(*expr.Cmp)
					assert.True(t, ok)
					assert.Equal(t, []byte{6}, protoCmp.Data) // tcp

					// Source port (45678 = 0xB26E)
					srcPortPayload, ok := exprs[8].(*expr.Payload)
					assert.True(t, ok)
					assert.Equal(t, uint32(0), srcPortPayload.Offset)
					srcPortCmp, ok := exprs[9].(*expr.Cmp)
					assert.True(t, ok)
					assert.Equal(t, []byte{0xb2, 0x6e}, srcPortCmp.Data)

					// Dest port (80 = 0x0050)
					dstPortPayload, ok := exprs[10].(*expr.Payload)
					assert.True(t, ok)
					assert.Equal(t, uint32(2), dstPortPayload.Offset)
					dstPortCmp, ok := exprs[11].(*expr.Cmp)
					assert.True(t, ok)
					assert.Equal(t, []byte{0x00, 0x50}, dstPortCmp.Data)

					// Verdict
					verdict, ok := exprs[12].(*expr.Verdict)
					assert.True(t, ok)
					assert.Equal(t, expr.VerdictAccept, verdict.Kind)

					return rule
				})
				mockConn.EXPECT().Flush().Return(nil)

				return func() (conn, error) { return mockConn, nil }, mockConn
			},

			expectedRuleCount: 1,
		},
	}
	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var firewall *Firewall
			if testCase.setupFirewall != nil {
				firewall = testCase.setupFirewall()
			}

			var dialFunc dialFunc
			if testCase.setupMockConn != nil {
				dialFunc, _ = testCase.setupMockConn()
			}
			if firewall == nil {
				firewall = &Firewall{dialFunc: dialFunc}
			} else {
				firewall.dialFunc = dialFunc
			}

			ctx := t.Context()
			err := firewall.AcceptOutputFromIPPortToIPPort(
				ctx, testCase.protocol, testCase.intf,
				testCase.source, testCase.destination, testCase.remove,
			)

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

func Test_AcceptOutputFromIPToSubnet(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		intf          string
		assignedIP    netip.Addr
		subnet        netip.Prefix
		remove        bool
		setupFirewall func() *Firewall
		setupMockConn func() (dialFunc, *MockConn)

		errorContains     string
		expectedRuleCount int
	}{
		"dial_error": {
			intf:       "eth0",
			assignedIP: netip.MustParseAddr("10.0.0.5"),
			subnet:     netip.MustParsePrefix("192.168.0.0/16"),
			setupMockConn: func() (dialFunc, *MockConn) {
				return func() (conn, error) { return nil, assert.AnError }, nil
			},
			errorContains: "creating nftables connection",
		},
		"success_ipv4_with_interface": {
			intf:       "eth0",
			assignedIP: netip.MustParseAddr("10.0.0.5"),
			subnet:     netip.MustParsePrefix("192.168.0.0/16"),
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
					assert.Len(t, exprs, 8)

					// Interface (Meta + Cmp)
					metaExpr, ok := exprs[0].(*expr.Meta)
					assert.True(t, ok)
					assert.Equal(t, expr.MetaKeyOIFNAME, metaExpr.Key)

					// Source address (Payload at offset 12 for IPv4 src)
					srcPayload, ok := exprs[2].(*expr.Payload)
					assert.True(t, ok)
					assert.Equal(t, uint32(12), srcPayload.Offset)

					// Dest address (Payload at offset 16 for IPv4 dst)
					dstPayload, ok := exprs[4].(*expr.Payload)
					assert.True(t, ok)
					assert.Equal(t, uint32(16), dstPayload.Offset)

					// Dest subnet mask application (Bitwise)
					bwExpr, ok := exprs[5].(*expr.Bitwise)
					assert.True(t, ok)
					assert.Equal(t, []byte{0xff, 0xff, 0x00, 0x00}, bwExpr.Mask)

					return rule
				})
				mockConn.EXPECT().Flush().Return(nil)

				return func() (conn, error) { return mockConn, nil }, mockConn
			},

			expectedRuleCount: 1,
		},
	}
	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var firewall *Firewall
			if testCase.setupFirewall != nil {
				firewall = testCase.setupFirewall()
			}

			var dialFunc dialFunc
			if testCase.setupMockConn != nil {
				dialFunc, _ = testCase.setupMockConn()
			}
			if firewall == nil {
				firewall = &Firewall{dialFunc: dialFunc}
			} else {
				firewall.dialFunc = dialFunc
			}

			ctx := t.Context()
			err := firewall.AcceptOutputFromIPToSubnet(ctx, testCase.intf, testCase.assignedIP, testCase.subnet, testCase.remove)

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

func Test_AcceptOutputThroughInterface(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		intf          string
		remove        bool
		setupFirewall func() *Firewall
		setupMockConn func() (dialFunc, *MockConn)

		errorContains     string
		expectedRuleCount int
	}{
		"dial_error": {
			intf: "eth0",
			setupMockConn: func() (dialFunc, *MockConn) {
				return func() (conn, error) { return nil, assert.AnError }, nil
			},
			errorContains: "creating nftables connection",
		},
		"flush_error_add_mode": {
			intf: "eth0",
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
			intf: "tun0",
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

					metaExpr, ok := exprs[0].(*expr.Meta)
					assert.True(t, ok)
					assert.Equal(t, expr.MetaKeyOIFNAME, metaExpr.Key)
					cmpExpr, ok := exprs[1].(*expr.Cmp)
					assert.True(t, ok)
					assert.Equal(t, []byte("tun0\x00"), cmpExpr.Data)
					verdictExpr, ok := exprs[2].(*expr.Verdict)
					assert.True(t, ok)
					assert.Equal(t, expr.VerdictAccept, verdictExpr.Kind)

					return rule
				})
				mockConn.EXPECT().Flush().Return(nil)

				return func() (conn, error) { return mockConn, nil }, mockConn
			},

			expectedRuleCount: 1,
		},
		"success_without_interface": {
			intf: "",
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
					// Just verdict, no interface check
					assert.Len(t, exprs, 1)
					verdictExpr, ok := exprs[0].(*expr.Verdict)
					assert.True(t, ok)
					assert.Equal(t, expr.VerdictAccept, verdictExpr.Kind)
					return rule
				})
				mockConn.EXPECT().Flush().Return(nil)

				return func() (conn, error) { return mockConn, nil }, mockConn
			},

			expectedRuleCount: 1,
		},
	}
	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var firewall *Firewall
			if testCase.setupFirewall != nil {
				firewall = testCase.setupFirewall()
			}

			var dialFunc dialFunc
			if testCase.setupMockConn != nil {
				dialFunc, _ = testCase.setupMockConn()
			}
			if firewall == nil {
				firewall = &Firewall{dialFunc: dialFunc}
			} else {
				firewall.dialFunc = dialFunc
			}

			ctx := t.Context()
			err := firewall.AcceptOutputThroughInterface(ctx, testCase.intf, testCase.remove)

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

func Test_cidrMask(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		bits     int
		addrLen  int
		expected []byte
	}{
		"ipv4_8_bits": {
			bits:     8,
			addrLen:  4,
			expected: []byte{0xff, 0x00, 0x00, 0x00},
		},
		"ipv4_16_bits": {
			bits:     16,
			addrLen:  4,
			expected: []byte{0xff, 0xff, 0x00, 0x00},
		},
		"ipv4_24_bits": {
			bits:     24,
			addrLen:  4,
			expected: []byte{0xff, 0xff, 0xff, 0x00},
		},
		"ipv4_32_bits": {
			bits:     32,
			addrLen:  4,
			expected: []byte{0xff, 0xff, 0xff, 0xff},
		},
		"ipv4_12_bits": {
			bits:     12,
			addrLen:  4,
			expected: []byte{0xff, 0xf0, 0x00, 0x00},
		},
		"ipv6_64_bits": {
			bits:    64,
			addrLen: 16,
			expected: []byte{
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			result := cidrMask(testCase.bits, testCase.addrLen)
			assert.Equal(t, testCase.expected, result)
		})
	}
}
