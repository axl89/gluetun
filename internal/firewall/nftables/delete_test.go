package nftables

import (
	"strconv"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_deleteRule(t *testing.T) {
	t.Parallel()

	conn, err := nftables.New()
	require.NoError(t, err)
	table := conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   "test_filter",
	})
	chain := conn.AddChain(&nftables.Chain{
		Name:     "test_output",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityFilter,
	})

	testCases := map[string]struct {
		setupRules     func(t *testing.T, firewall *Firewall)
		ruleToDelete   func(firewall *Firewall) *nftables.Rule
		expectError    bool
		expectErrorIs  error
		expectRulesLen int
	}{
		"rule not found": {
			setupRules: func(_ *testing.T, _ *Firewall) {
				// No rules added
			},
			ruleToDelete: func(_ *Firewall) *nftables.Rule {
				return &nftables.Rule{
					Table: table,
					Chain: chain,
					Exprs: []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}},
				}
			},
			expectError:    true,
			expectErrorIs:  errRuleToDeleteNotFound,
			expectRulesLen: 0,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			firewall := &Firewall{rules: []*nftables.Rule{}}
			testCase.setupRules(t, firewall)
			ruleToDelete := testCase.ruleToDelete(firewall)

			err := firewall.deleteRule(conn, ruleToDelete)

			if testCase.expectError {
				require.Error(t, err)
				if testCase.expectErrorIs != nil {
					assert.ErrorIs(t, err, testCase.expectErrorIs)
				}
			} else {
				assert.NoError(t, err)
			}

			assert.Len(t, firewall.rules, testCase.expectRulesLen)
		})
	}
}

//nolint:paralleltest
func Test_deleteRule_withFlushing(t *testing.T) {
	// Not parallel: requires root access for nftables handle assignment.
	t.Skip("requires root access for nftables handle assignment")

	conn, err := nftables.New()
	require.NoError(t, err)

	// Create a unique table for this test
	table := conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   "test_filter_del_" + strconv.FormatInt(time.Now().UnixNano(), 10),
	})
	chain := conn.AddChain(&nftables.Chain{
		Name:     "test_output",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityFilter,
	})

	// Clean up after test
	t.Cleanup(func() {
		conn.FlushRuleset()
	})

	// Add some rules and flush to get handles
	// Use valid expressions: Meta type match + Verdict (like "meta nfproto ipv4 accept")
	rules := make([]*nftables.Rule, 3)
	for i := range rules {
		nfprotoVal := uint16(2) // ip
		if i > 0 {
			nfprotoVal = uint16(10) // ipv6
		}
		rules[i] = conn.AddRule(&nftables.Rule{
			Table: table,
			Chain: chain,
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x00, byte(nfprotoVal)}},
				&expr.Verdict{Kind: expr.VerdictAccept},
			},
		})
	}
	err = conn.Flush()
	require.NoError(t, err)

	firewall := &Firewall{rules: rules}

	// Delete middle rule
	err = firewall.deleteRule(conn, rules[1])
	require.NoError(t, err)
	assert.Len(t, firewall.rules, 2)

	// Delete first rule
	err = firewall.deleteRule(conn, rules[0])
	require.NoError(t, err)
	assert.Len(t, firewall.rules, 1)

	// Try to delete a rule that doesn't exist in fw.rules
	nonExistentRule := &nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{&expr.Verdict{Kind: expr.VerdictDrop}},
	}
	err = firewall.deleteRule(conn, nonExistentRule)
	require.Error(t, err)
	assert.ErrorIs(t, err, errRuleToDeleteNotFound)
	assert.Len(t, firewall.rules, 1)
}
