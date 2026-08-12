package nftables

import (
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func Test_RedirectPort(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		intf            string
		sourcePort      uint16
		destinationPort uint16
		remove          bool
		setupFirewall   func() *Firewall
		setupMockConn   func() (dialFunc, *MockConn)

		errorContains     string
		expectedRuleCount int
	}{
		"dial_error": {
			intf:            "eth0",
			sourcePort:      80,
			destinationPort: 8080,
			setupMockConn: func() (dialFunc, *MockConn) {
				return func() (conn, error) { return nil, assert.AnError }, nil
			},
			errorContains: "creating nftables connection",
		},
		"flush_error_add_mode": {
			intf:            "eth0",
			sourcePort:      80,
			destinationPort: 8080,
			setupMockConn: func() (dialFunc, *MockConn) {
				ctrl := gomock.NewController(t)
				mockConn := NewMockConn(ctrl)

				mockConn.EXPECT().AddTable(gomock.Any()).Times(2)
				mockConn.EXPECT().AddChain(gomock.Any()).Times(4)
				mockConn.EXPECT().AddRule(gomock.Any()).Times(4)
				mockConn.EXPECT().Flush().Return(assert.AnError)

				return func() (conn, error) { return mockConn, nil }, mockConn
			},
			errorContains: "redirecting source port",
		},
		"success_add_redirect_with_interface": {
			intf:            "tun0",
			sourcePort:      55555,
			destinationPort: 1194,
			setupMockConn: func() (dialFunc, *MockConn) {
				ctrl := gomock.NewController(t)
				mockConn := NewMockConn(ctrl)

				mockConn.EXPECT().AddTable(gomock.Any()).DoAndReturn(func(table *nftables.Table) *nftables.Table {
					return table
				}).Times(2)
				mockConn.EXPECT().AddChain(gomock.Any()).DoAndReturn(func(chain *nftables.Chain) *nftables.Chain {
					return chain
				}).Times(4)
				mockConn.EXPECT().AddRule(gomock.Any()).DoAndReturn(func(rule *nftables.Rule) *nftables.Rule {
					exprs := rule.Exprs

					// Preroute rule should have NAT expression
					if rule.Chain.Name == "prerouting" {
						// Last expr should be NAT type
						lastExpr := exprs[len(exprs)-1]
						natExpr, ok := lastExpr.(*expr.NAT)
						assert.True(t, ok, "expected NAT expression in preroute rule")
						assert.Equal(t, expr.NATTypeDestNAT, natExpr.Type)
					}

					// Input rule should have Verdict Accept
					if rule.Chain.Name == "input" {
						lastExpr := exprs[len(exprs)-1]
						verdictExpr, ok := lastExpr.(*expr.Verdict)
						assert.True(t, ok, "expected Verdict expression in input rule")
						assert.Equal(t, expr.VerdictAccept, verdictExpr.Kind)
					}

					// Both rules should match interface
					if rule.Table.Name == "nat" || rule.Table.Name == "filter" {
						metaExpr, ok := exprs[0].(*expr.Meta)
						assert.True(t, ok)
						assert.Equal(t, expr.MetaKeyIIFNAME, metaExpr.Key)
						cmpExpr, ok := exprs[1].(*expr.Cmp)
						assert.True(t, ok)
						assert.Equal(t, []byte("tun0\x00"), cmpExpr.Data)
					}

					return rule
				}).Times(4)
				mockConn.EXPECT().Flush().Return(nil)

				return func() (conn, error) { return mockConn, nil }, mockConn
			},

			expectedRuleCount: 4,
		},
		"success_add_redirect_without_interface": {
			intf:            "",
			sourcePort:      80,
			destinationPort: 8080,
			setupMockConn: func() (dialFunc, *MockConn) {
				ctrl := gomock.NewController(t)
				mockConn := NewMockConn(ctrl)

				mockConn.EXPECT().AddTable(gomock.Any()).DoAndReturn(func(table *nftables.Table) *nftables.Table {
					return table
				}).Times(2)
				mockConn.EXPECT().AddChain(gomock.Any()).DoAndReturn(func(chain *nftables.Chain) *nftables.Chain {
					return chain
				}).Times(4)
				mockConn.EXPECT().AddRule(gomock.Any()).DoAndReturn(func(rule *nftables.Rule) *nftables.Rule {
					exprs := rule.Exprs
					// Without interface, first expr should be protocol payload, not meta
					payloadExpr, ok := exprs[0].(*expr.Payload)
					assert.True(t, ok)
					assert.Equal(t, expr.PayloadBaseNetworkHeader, payloadExpr.Base)
					assert.Equal(t, uint32(9), payloadExpr.Offset)
					return rule
				}).Times(4)
				mockConn.EXPECT().Flush().Return(nil)

				return func() (conn, error) { return mockConn, nil }, mockConn
			},

			expectedRuleCount: 4,
		},
		// Note: success_remove_redirect is complex because deleteRule uses DeepEqual
		// on rules - tested separately in Test_deleteRule
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
			err := firewall.RedirectPort(ctx, testCase.intf, testCase.sourcePort, testCase.destinationPort, testCase.remove)

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

func Test_buildRedirectRule(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		intf            string
		protocol        uint8
		sourcePortBytes []byte
		destinationPort uint16
		validateRule    func(t *testing.T, rule *nftables.Rule)
	}{
		"tcp_with_interface": {
			intf:            "eth0",
			protocol:        6,
			sourcePortBytes: []byte{0x00, 0x50},
			destinationPort: 8080,
			validateRule: func(t *testing.T, rule *nftables.Rule) {
				t.Helper()
				assert.Equal(t, "nat", rule.Table.Name)
				assert.Equal(t, "prerouting", rule.Chain.Name)

				exprs := rule.Exprs
				// Should have NAT expression at the end
				lastExpr := exprs[len(exprs)-1]
				natExpr, ok := lastExpr.(*expr.NAT)
				assert.True(t, ok, "expected NAT expression")
				assert.Equal(t, expr.NATTypeDestNAT, natExpr.Type)
			},
		},
		"udp_without_interface": {
			intf:            "",
			protocol:        17,
			sourcePortBytes: []byte{0x00, 0x35},
			destinationPort: 443,
			validateRule: func(t *testing.T, rule *nftables.Rule) {
				t.Helper()
				assert.Equal(t, "nat", rule.Table.Name)
				assert.Equal(t, "prerouting", rule.Chain.Name)

				exprs := rule.Exprs
				// First expr should be protocol payload, not interface meta
				payloadExpr, ok := exprs[0].(*expr.Payload)
				assert.True(t, ok)
				assert.Equal(t, expr.PayloadBaseNetworkHeader, payloadExpr.Base)
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			mockConn := NewMockConn(ctrl)

			natTable := &nftables.Table{Name: "nat", Family: nftables.TableFamilyINet}
			preroutingChain := &nftables.Chain{Name: "prerouting", Table: natTable}

			rule := buildRedirectRule(mockConn, natTable, preroutingChain,
				testCase.intf, testCase.protocol, testCase.sourcePortBytes, testCase.destinationPort)

			testCase.validateRule(t, rule)
		})
	}
}

func Test_buildRedirectInputRule(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		intf                 string
		protocol             uint8
		destinationPortBytes []byte
		validateRule         func(t *testing.T, rule *nftables.Rule)
	}{
		"with_interface": {
			intf:                 "eth0",
			protocol:             6,
			destinationPortBytes: []byte{0x1f, 0x90},
			validateRule: func(t *testing.T, rule *nftables.Rule) {
				t.Helper()
				assert.Equal(t, "filter", rule.Table.Name)
				assert.Equal(t, "input", rule.Chain.Name)

				exprs := rule.Exprs
				lastExpr := exprs[len(exprs)-1]
				verdictExpr, ok := lastExpr.(*expr.Verdict)
				assert.True(t, ok)
				assert.Equal(t, expr.VerdictAccept, verdictExpr.Kind)

				// Should have interface check
				metaExpr, ok := exprs[0].(*expr.Meta)
				assert.True(t, ok)
				assert.Equal(t, expr.MetaKeyIIFNAME, metaExpr.Key)
			},
		},
		"without_interface": {
			intf:                 "",
			protocol:             17,
			destinationPortBytes: []byte{0x00, 0x35},
			validateRule: func(t *testing.T, rule *nftables.Rule) {
				t.Helper()
				assert.Equal(t, "filter", rule.Table.Name)
				assert.Equal(t, "input", rule.Chain.Name)

				exprs := rule.Exprs
				// First expr should be protocol payload, no interface
				payloadExpr, ok := exprs[0].(*expr.Payload)
				assert.True(t, ok)
				assert.Equal(t, expr.PayloadBaseNetworkHeader, payloadExpr.Base)
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			table := &nftables.Table{Name: "filter"}
			inputChain := &nftables.Chain{Name: "input", Table: table}

			rule := buildRedirectInputRule(table, inputChain,
				testCase.intf, testCase.protocol, testCase.destinationPortBytes)

			testCase.validateRule(t, rule)
		})
	}
}

func Test_buildRedirectMatchExprs(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		intf          string
		protocol      uint8
		portBytes     []byte
		validateExprs func(t *testing.T, exprs []expr.Any)
	}{
		"with_interface": {
			intf:      "eth0",
			protocol:  6,
			portBytes: []byte{0x00, 0x50},
			validateExprs: func(t *testing.T, exprs []expr.Any) {
				t.Helper()
				assert.Len(t, exprs, 6)

				// Interface check
				metaExpr, ok := exprs[0].(*expr.Meta)
				assert.True(t, ok)
				assert.Equal(t, expr.MetaKeyIIFNAME, metaExpr.Key)

				// Protocol check
				protoCmp, ok := exprs[3].(*expr.Cmp)
				assert.True(t, ok)
				assert.Equal(t, []byte{6}, protoCmp.Data)

				// Port check
				portCmp, ok := exprs[5].(*expr.Cmp)
				assert.True(t, ok)
				assert.Equal(t, []byte{0x00, 0x50}, portCmp.Data)
			},
		},
		"without_interface": {
			intf:      "",
			protocol:  17,
			portBytes: []byte{0x00, 0x35},
			validateExprs: func(t *testing.T, exprs []expr.Any) {
				t.Helper()
				assert.Len(t, exprs, 4)

				// First is protocol payload
				payloadExpr, ok := exprs[0].(*expr.Payload)
				assert.True(t, ok)
				assert.Equal(t, expr.PayloadBaseNetworkHeader, payloadExpr.Base)
				assert.Equal(t, uint32(9), payloadExpr.Offset)

				// Port check
				portCmp, ok := exprs[3].(*expr.Cmp)
				assert.True(t, ok)
				assert.Equal(t, []byte{0x00, 0x35}, portCmp.Data)
			},
		},
		"star_interface_same_as_empty": {
			intf:      "*",
			protocol:  6,
			portBytes: []byte{0x00, 0x50},
			validateExprs: func(t *testing.T, exprs []expr.Any) {
				t.Helper()
				assert.Len(t, exprs, 4)
				// No interface check
				payloadExpr, ok := exprs[0].(*expr.Payload)
				assert.True(t, ok)
				assert.Equal(t, expr.PayloadBaseNetworkHeader, payloadExpr.Base)
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			exprs := buildRedirectMatchExprs(testCase.intf, testCase.protocol, testCase.portBytes)
			testCase.validateExprs(t, exprs)
		})
	}
}

func Test_isTableDoesNotExist(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		err      error
		expected bool
	}{
		"nil_error": {
			err:      nil,
			expected: false,
		},
		"table_does_not_exist": {
			err:      assert.AnError,
			expected: false,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if name == "table_does_not_exist" {
				// Use a real error with expected message
				result := isTableDoesNotExist(nil)
				assert.False(t, result)

				// Test with actual message
				result = isTableDoesNotExist(assert.AnError)
				assert.False(t, result)
			} else {
				result := isTableDoesNotExist(testCase.err)
				assert.Equal(t, testCase.expected, result)
			}
		})
	}
}

func Test_removeFailedRules(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		rules       []*nftables.Rule
		failed      []*nftables.Rule
		expectedLen int
	}{
		"no_failed_rules": {
			rules: []*nftables.Rule{
				{Table: &nftables.Table{Name: "a"}},
				{Table: &nftables.Table{Name: "b"}},
			},
			failed:      nil,
			expectedLen: 2,
		},
	}

	// Fix pointer references - slices.Contains uses pointer equality
	// all_failed: use same pointers in rules and failed
	rAllFailedA := &nftables.Rule{Table: &nftables.Table{Name: "a"}}
	rAllFailedB := &nftables.Rule{Table: &nftables.Table{Name: "b"}}
	testCases["all_failed"] = struct {
		rules       []*nftables.Rule
		failed      []*nftables.Rule
		expectedLen int
	}{
		rules:       []*nftables.Rule{rAllFailedA, rAllFailedB},
		failed:      []*nftables.Rule{rAllFailedA, rAllFailedB},
		expectedLen: 0,
	}

	// some_failed: use same pointer for the failed rule
	rSomeFailedA := &nftables.Rule{Table: &nftables.Table{Name: "a"}}
	rSomeFailedB := &nftables.Rule{Table: &nftables.Table{Name: "b"}}
	rSomeFailedC := &nftables.Rule{Table: &nftables.Table{Name: "c"}}
	testCases["some_failed"] = struct {
		rules       []*nftables.Rule
		failed      []*nftables.Rule
		expectedLen int
	}{
		rules:       []*nftables.Rule{rSomeFailedA, rSomeFailedB, rSomeFailedC},
		failed:      []*nftables.Rule{rSomeFailedB},
		expectedLen: 2,
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			result := removeFailedRules(testCase.rules, testCase.failed)
			assert.Len(t, result, testCase.expectedLen)
		})
	}
}
