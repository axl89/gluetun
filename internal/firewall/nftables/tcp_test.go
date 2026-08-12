package nftables

import (
	"net/netip"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func Test_TempDropOutputTCPRST(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		src             netip.AddrPort
		dst             netip.AddrPort
		excludeMark     int
		setupFirstConn  func(ctrl *gomock.Controller) dialFunc
		setupSecondConn func(ctrl *gomock.Controller) dialFunc

		errorContains string
		validateRule  func(t *testing.T, rule *nftables.Rule)
	}{
		"dial_error": {
			src: netip.MustParseAddrPort("127.0.0.1:1234"),
			dst: netip.MustParseAddrPort("192.168.1.1:443"),
			setupFirstConn: func(_ *gomock.Controller) dialFunc {
				return func() (conn, error) { return nil, assert.AnError }
			},
			errorContains: "creating nftables connection",
		},
		"flush_error": {
			src: netip.MustParseAddrPort("127.0.0.1:1234"),
			dst: netip.MustParseAddrPort("192.168.1.1:443"),
			setupFirstConn: func(ctrl *gomock.Controller) dialFunc {
				mockConn := NewMockConn(ctrl)

				mockConn.EXPECT().AddTable(gomock.Any()).DoAndReturn(func(table *nftables.Table) *nftables.Table {
					return table
				})
				mockConn.EXPECT().AddChain(gomock.Any()).DoAndReturn(func(chain *nftables.Chain) *nftables.Chain {
					return chain
				}).Times(3)
				mockConn.EXPECT().AddRule(gomock.Any())
				mockConn.EXPECT().Flush().Return(assert.AnError)

				return func() (conn, error) { return mockConn, nil }
			},
			errorContains: "flushing",
		},
		"success_ipv4_with_exclude_mark": {
			src:         netip.MustParseAddrPort("10.0.0.5:50000"),
			dst:         netip.MustParseAddrPort("192.168.1.1:443"),
			excludeMark: 123,
			setupFirstConn: func(ctrl *gomock.Controller) dialFunc {
				mockConn := NewMockConn(ctrl)
				srcPortBytes := []byte{0xc3, 0x50}
				dstPortBytes := []byte{0x01, 0xbb}

				mockConn.EXPECT().AddTable(gomock.Any()).DoAndReturn(func(table *nftables.Table) *nftables.Table {
					return table
				})
				mockConn.EXPECT().AddChain(gomock.Any()).DoAndReturn(func(chain *nftables.Chain) *nftables.Chain {
					return chain
				}).Times(3)
				mockConn.EXPECT().AddRule(gomock.Any()).DoAndReturn(func(rule *nftables.Rule) *nftables.Rule {
					exprs := rule.Exprs
					assert.Len(t, exprs, 15)

					// Source IPv4 address (offset 12)
					srcIPPayload, ok := exprs[0].(*expr.Payload)
					assert.True(t, ok)
					assert.Equal(t, uint32(12), srcIPPayload.Offset)
					srcIPCmp, ok := exprs[1].(*expr.Cmp)
					assert.True(t, ok)
					assert.Equal(t, []byte{10, 0, 0, 5}, srcIPCmp.Data)

					// Dest IPv4 address (offset 16)
					dstIPPayload, ok := exprs[2].(*expr.Payload)
					assert.True(t, ok)
					assert.Equal(t, uint32(16), dstIPPayload.Offset)
					dstIPCmp, ok := exprs[3].(*expr.Cmp)
					assert.True(t, ok)
					assert.Equal(t, []byte{192, 168, 1, 1}, dstIPCmp.Data)

					// TCP protocol
					protoMeta, ok := exprs[4].(*expr.Meta)
					assert.True(t, ok)
					assert.Equal(t, expr.MetaKeyL4PROTO, protoMeta.Key)
					protoCmp, ok := exprs[5].(*expr.Cmp)
					assert.True(t, ok)
					assert.Equal(t, []byte{6}, protoCmp.Data)

					// Source port
					srcPortPayload, ok := exprs[6].(*expr.Payload)
					assert.True(t, ok)
					assert.Equal(t, uint32(0), srcPortPayload.Offset)
					srcPortCmp, ok := exprs[7].(*expr.Cmp)
					assert.True(t, ok)
					assert.Equal(t, srcPortBytes, srcPortCmp.Data)

					// Dest port
					dstPortPayload, ok := exprs[8].(*expr.Payload)
					assert.True(t, ok)
					assert.Equal(t, uint32(2), dstPortPayload.Offset)
					dstPortCmp, ok := exprs[9].(*expr.Cmp)
					assert.True(t, ok)
					assert.Equal(t, dstPortBytes, dstPortCmp.Data)

					// TCP flags (RST = 0x04)
					flagsPayload, ok := exprs[10].(*expr.Payload)
					assert.True(t, ok)
					assert.Equal(t, uint32(13), flagsPayload.Offset)
					flagsCmp, ok := exprs[11].(*expr.Cmp)
					assert.True(t, ok)
					assert.Equal(t, []byte{0x04}, flagsCmp.Data)

					// Exclude mark with MetaKeyMARK
					markMeta, ok := exprs[12].(*expr.Meta)
					assert.True(t, ok)
					assert.Equal(t, expr.MetaKeyMARK, markMeta.Key)
					markCmp, ok := exprs[13].(*expr.Cmp)
					assert.True(t, ok)
					assert.Equal(t, expr.CmpOpNeq, markCmp.Op)

					return rule
				})
				mockConn.EXPECT().Flush().Return(nil)

				return func() (conn, error) { return mockConn, nil }
			},
		},
		"success_ipv6": {
			src:         netip.MustParseAddrPort("[2001:db8::1]:50000"),
			dst:         netip.MustParseAddrPort("[2001:db8::2]:443"),
			excludeMark: 0,
			setupFirstConn: func(ctrl *gomock.Controller) dialFunc {
				mockConn := NewMockConn(ctrl)

				mockConn.EXPECT().AddTable(gomock.Any()).DoAndReturn(func(table *nftables.Table) *nftables.Table {
					return table
				})
				mockConn.EXPECT().AddChain(gomock.Any()).DoAndReturn(func(chain *nftables.Chain) *nftables.Chain {
					return chain
				}).Times(3)
				mockConn.EXPECT().AddRule(gomock.Any()).DoAndReturn(func(rule *nftables.Rule) *nftables.Rule {
					exprs := rule.Exprs
					assert.Len(t, exprs, 15)

					// Source IPv6 address (offset 8)
					srcIPPayload, ok := exprs[0].(*expr.Payload)
					assert.True(t, ok)
					assert.Equal(t, uint32(8), srcIPPayload.Offset)
					assert.Equal(t, uint32(16), srcIPPayload.Len)

					// Dest IPv6 address (offset 24)
					dstIPPayload, ok := exprs[2].(*expr.Payload)
					assert.True(t, ok)
					assert.Equal(t, uint32(24), dstIPPayload.Offset)
					assert.Equal(t, uint32(16), dstIPPayload.Len)

					return rule
				})
				mockConn.EXPECT().Flush().Return(nil)

				return func() (conn, error) { return mockConn, nil }
			},
		},
		"revert_success": {
			src:         netip.MustParseAddrPort("127.0.0.1:1234"),
			dst:         netip.MustParseAddrPort("192.168.1.1:443"),
			excludeMark: 0,
			setupFirstConn: func(ctrl *gomock.Controller) dialFunc {
				mockConn := NewMockConn(ctrl)

				mockConn.EXPECT().AddTable(gomock.Any()).DoAndReturn(func(table *nftables.Table) *nftables.Table {
					return table
				})
				mockConn.EXPECT().AddChain(gomock.Any()).DoAndReturn(func(chain *nftables.Chain) *nftables.Chain {
					return chain
				}).Times(3)
				mockConn.EXPECT().AddRule(gomock.Any()).DoAndReturn(func(rule *nftables.Rule) *nftables.Rule {
					return rule
				})
				mockConn.EXPECT().Flush().Return(nil)

				return func() (conn, error) { return mockConn, nil }
			},
			setupSecondConn: func(ctrl *gomock.Controller) dialFunc {
				mockConn := NewMockConn(ctrl)

				mockConn.EXPECT().DelRule(gomock.Any()).Return(nil)
				mockConn.EXPECT().Flush().Return(nil)

				return func() (conn, error) { return mockConn, nil }
			},
		},
		"revert_dial_error": {
			src:         netip.MustParseAddrPort("127.0.0.1:1234"),
			dst:         netip.MustParseAddrPort("192.168.1.1:443"),
			excludeMark: 0,
			setupFirstConn: func(ctrl *gomock.Controller) dialFunc {
				mockConn := NewMockConn(ctrl)

				mockConn.EXPECT().AddTable(gomock.Any()).DoAndReturn(func(table *nftables.Table) *nftables.Table {
					return table
				})
				mockConn.EXPECT().AddChain(gomock.Any()).DoAndReturn(func(chain *nftables.Chain) *nftables.Chain {
					return chain
				}).Times(3)
				mockConn.EXPECT().AddRule(gomock.Any())
				mockConn.EXPECT().Flush().Return(nil)

				return func() (conn, error) { return mockConn, nil }
			},
			setupSecondConn: func(_ *gomock.Controller) dialFunc {
				return func() (conn, error) { return nil, assert.AnError }
			},
			errorContains: "creating nftables connection for revert",
		},
		"revert_del_rule_error": {
			src:         netip.MustParseAddrPort("127.0.0.1:1234"),
			dst:         netip.MustParseAddrPort("192.168.1.1:443"),
			excludeMark: 0,
			setupFirstConn: func(ctrl *gomock.Controller) dialFunc {
				mockConn := NewMockConn(ctrl)

				mockConn.EXPECT().AddTable(gomock.Any()).DoAndReturn(func(table *nftables.Table) *nftables.Table {
					return table
				})
				mockConn.EXPECT().AddChain(gomock.Any()).DoAndReturn(func(chain *nftables.Chain) *nftables.Chain {
					return chain
				}).Times(3)
				mockConn.EXPECT().AddRule(gomock.Any())
				mockConn.EXPECT().Flush().Return(nil)

				return func() (conn, error) { return mockConn, nil }
			},
			setupSecondConn: func(ctrl *gomock.Controller) dialFunc {
				mockConn := NewMockConn(ctrl)

				mockConn.EXPECT().DelRule(gomock.Any()).Return(assert.AnError)

				return func() (conn, error) { return mockConn, nil }
			},
			errorContains: "deleting rule",
		},
		"revert_flush_error": {
			src:         netip.MustParseAddrPort("127.0.0.1:1234"),
			dst:         netip.MustParseAddrPort("192.168.1.1:443"),
			excludeMark: 0,
			setupFirstConn: func(ctrl *gomock.Controller) dialFunc {
				mockConn := NewMockConn(ctrl)

				mockConn.EXPECT().AddTable(gomock.Any()).DoAndReturn(func(table *nftables.Table) *nftables.Table {
					return table
				})
				mockConn.EXPECT().AddChain(gomock.Any()).DoAndReturn(func(chain *nftables.Chain) *nftables.Chain {
					return chain
				}).Times(3)
				mockConn.EXPECT().AddRule(gomock.Any())
				mockConn.EXPECT().Flush().Return(nil)

				return func() (conn, error) { return mockConn, nil }
			},
			setupSecondConn: func(ctrl *gomock.Controller) dialFunc {
				mockConn := NewMockConn(ctrl)

				mockConn.EXPECT().DelRule(gomock.Any()).Return(nil)
				mockConn.EXPECT().Flush().Return(assert.AnError)

				return func() (conn, error) { return mockConn, nil }
			},
			errorContains: "flushing",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)

			firstConn := testCase.setupFirstConn(ctrl)
			var dialFuncs []dialFunc
			dialFuncs = append(dialFuncs, firstConn)

			if testCase.setupSecondConn != nil {
				secondConn := testCase.setupSecondConn(ctrl)
				dialFuncs = append(dialFuncs, secondConn)
			}

			dialFunc := func() (conn, error) {
				if len(dialFuncs) > 0 {
					df := dialFuncs[0]
					dialFuncs = dialFuncs[1:]
					return df()
				}
				return nil, assert.AnError
			}

			firewall := &Firewall{dialFunc: dialFunc}

			ctx := t.Context()
			revert, err := firewall.TempDropOutputTCPRST(ctx, testCase.src, testCase.dst, testCase.excludeMark)

			if testCase.errorContains != "" && testCase.setupSecondConn == nil {
				assert.Error(t, err)
				if testCase.errorContains != "" {
					assert.ErrorContains(t, err, testCase.errorContains)
				}
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, revert)

			// Call revert if it should work
			if testCase.setupSecondConn != nil {
				revertErr := revert(ctx)

				if testCase.errorContains != "" {
					assert.Error(t, revertErr)
					if testCase.errorContains != "" {
						assert.ErrorContains(t, revertErr, testCase.errorContains)
					}
				} else {
					assert.NoError(t, revertErr)
				}
			}
		})
	}
}

func Test_TempDropOutputTCPRST_expression_count(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	mockConn := NewMockConn(ctrl)

	mockConn.EXPECT().AddTable(gomock.Any()).DoAndReturn(func(table *nftables.Table) *nftables.Table {
		return table
	})
	mockConn.EXPECT().AddChain(gomock.Any()).DoAndReturn(func(chain *nftables.Chain) *nftables.Chain {
		return chain
	}).Times(3)
	mockConn.EXPECT().AddRule(gomock.Any()).DoAndReturn(func(rule *nftables.Rule) *nftables.Rule {
		// Should have exactly 14 expressions:
		// 1. src IP payload
		// 2. src IP cmp
		// 3. dst IP payload
		// 4. dst IP cmp
		// 5. protocol meta
		// 6. protocol cmp
		// 7. src port payload
		// 8. src port cmp
		// 9. dst port payload
		// 10. dst port cmp
		// 11. flags payload
		// 12. flags cmp
		// 13. mark meta
		// 14. mark cmp
		// 15. verdict drop
		assert.Len(t, rule.Exprs, 15)

		// Last expression should be DROP verdict
		verdictExpr, ok := rule.Exprs[len(rule.Exprs)-1].(*expr.Verdict)
		assert.True(t, ok)
		assert.Equal(t, expr.VerdictDrop, verdictExpr.Kind)

		return rule
	})
	mockConn.EXPECT().Flush().Return(nil)

	dialFunc := func() (conn, error) { return mockConn, nil }

	firewall := &Firewall{dialFunc: dialFunc}

	ctx := t.Context()
	revert, err := firewall.TempDropOutputTCPRST(ctx,
		netip.MustParseAddrPort("127.0.0.1:1234"),
		netip.MustParseAddrPort("192.168.1.1:443"),
		0)

	assert.NoError(t, err)
	assert.NotNil(t, revert)
}
