package nftables

import (
	"testing"

	"github.com/google/nftables"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func Test_deleteRule(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		setupFirewall func() *Firewall
		setupMocks    func(ctrl *gomock.Controller, conn *MockConn)
		ruleToFind    *nftables.Rule
		errorContains string
		expectedRules int
	}{
		"rule_found_and_deleted": {
			setupFirewall: func() *Firewall {
				table := &nftables.Table{Name: "filter"}
				chain := &nftables.Chain{Name: "input", Table: table}
				return &Firewall{
					rules: []*nftables.Rule{
						{Table: table, Chain: chain},
					},
				}
			},
			setupMocks: func(_ *gomock.Controller, mockConn *MockConn) {
				table := &nftables.Table{Name: "filter"}
				chain := &nftables.Chain{Name: "input", Table: table}
				rule := &nftables.Rule{Table: table, Chain: chain}
				mockConn.EXPECT().DelRule(rule).Return(nil)
			},
			ruleToFind: func() *nftables.Rule {
				table := &nftables.Table{Name: "filter"}
				chain := &nftables.Chain{Name: "input", Table: table}
				return &nftables.Rule{Table: table, Chain: chain}
			}(),
			expectedRules: 0,
		},
		"rule_not_found": {
			setupFirewall: func() *Firewall {
				return &Firewall{rules: []*nftables.Rule{}}
			},
			setupMocks: func(_ *gomock.Controller, _ *MockConn) {
			},
			ruleToFind: func() *nftables.Rule {
				table := &nftables.Table{Name: "filter"}
				chain := &nftables.Chain{Name: "input", Table: table}
				return &nftables.Rule{Table: table, Chain: chain}
			}(),
			errorContains: "rule not found for removal",
			expectedRules: 0,
		},
		"del_rule_error": {
			setupFirewall: func() *Firewall {
				table := &nftables.Table{Name: "filter"}
				chain := &nftables.Chain{Name: "input", Table: table}
				return &Firewall{
					rules: []*nftables.Rule{
						{Table: table, Chain: chain},
					},
				}
			},
			setupMocks: func(_ *gomock.Controller, mockConn *MockConn) {
				table := &nftables.Table{Name: "filter"}
				chain := &nftables.Chain{Name: "input", Table: table}
				rule := &nftables.Rule{Table: table, Chain: chain}
				mockConn.EXPECT().DelRule(rule).Return(assert.AnError)
			},
			ruleToFind: func() *nftables.Rule {
				table := &nftables.Table{Name: "filter"}
				chain := &nftables.Chain{Name: "input", Table: table}
				return &nftables.Rule{Table: table, Chain: chain}
			}(),
			errorContains: "assert.AnError",
			expectedRules: 1,
		},
		"multiple_rules_deletes_correct_one": {
			setupFirewall: func() *Firewall {
				table := &nftables.Table{Name: "filter"}
				chain := &nftables.Chain{Name: "input", Table: table}
				chain2 := &nftables.Chain{Name: "output", Table: table}
				return &Firewall{
					rules: []*nftables.Rule{
						{Table: table, Chain: chain},
						{Table: table, Chain: chain2},
						{Table: table, Chain: chain},
					},
				}
			},
			setupMocks: func(_ *gomock.Controller, mockConn *MockConn) {
				table := &nftables.Table{Name: "filter"}
				chain := &nftables.Chain{Name: "input", Table: table}
				rule := &nftables.Rule{Table: table, Chain: chain}
				mockConn.EXPECT().DelRule(rule).Return(nil)
			},
			ruleToFind: func() *nftables.Rule {
				table := &nftables.Table{Name: "filter"}
				chain := &nftables.Chain{Name: "input", Table: table}
				return &nftables.Rule{Table: table, Chain: chain}
			}(),
			expectedRules: 2,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			mockConn := NewMockConn(ctrl)

			firewall := testCase.setupFirewall()

			testCase.setupMocks(ctrl, mockConn)

			err := firewall.deleteRule(mockConn, testCase.ruleToFind)

			if testCase.errorContains != "" {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Len(t, firewall.rules, testCase.expectedRules)
		})
	}
}
