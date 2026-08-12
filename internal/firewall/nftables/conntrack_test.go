package nftables

import (
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func Test_AcceptEstablishedRelatedTraffic(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		setupMockConn func() (dialFunc, *MockConn)
		errorContains string
		validateExprs func(t *testing.T, rules []*nftables.Rule)
	}{
		"dial_error": {
			setupMockConn: func() (dialFunc, *MockConn) {
				return func() (conn, error) { return nil, assert.AnError }, nil
			},
			errorContains: "creating nftables connection",
		},
		"flush_error": {
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
		"success_with_correct_expressions": {
			setupMockConn: func() (dialFunc, *MockConn) {
				ctrl := gomock.NewController(t)
				mockConn := NewMockConn(ctrl)

				var rulesAdded []*nftables.Rule

				mockConn.EXPECT().AddTable(gomock.Any()).DoAndReturn(func(table *nftables.Table) *nftables.Table {
					return table
				})
				mockConn.EXPECT().AddChain(gomock.Any()).DoAndReturn(func(chain *nftables.Chain) *nftables.Chain {
					return chain
				}).Times(3)
				mockConn.EXPECT().AddRule(gomock.Any()).DoAndReturn(func(rule *nftables.Rule) *nftables.Rule {
					rulesAdded = append(rulesAdded, rule)
					return rule
				}).Times(2)
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
			err := firewall.AcceptEstablishedRelatedTraffic(ctx)

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

func Test_AcceptEstablishedRelatedTraffic_expression_structure(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	mockConn := NewMockConn(ctrl)

	var rulesAdded []*nftables.Rule
	var chainsAdded []*nftables.Chain

	mockConn.EXPECT().AddTable(gomock.Any()).DoAndReturn(func(table *nftables.Table) *nftables.Table {
		return table
	})
	mockConn.EXPECT().AddChain(gomock.Any()).DoAndReturn(func(chain *nftables.Chain) *nftables.Chain {
		chainsAdded = append(chainsAdded, chain)
		return chain
	}).Times(3)
	mockConn.EXPECT().AddRule(gomock.Any()).DoAndReturn(func(rule *nftables.Rule) *nftables.Rule {
		rulesAdded = append(rulesAdded, rule)
		return rule
	}).Times(2)
	mockConn.EXPECT().Flush().Return(nil)

	dialFunc := func() (conn, error) { return mockConn, nil }

	firewall := &Firewall{dialFunc: dialFunc}

	ctx := t.Context()
	err := firewall.AcceptEstablishedRelatedTraffic(ctx)
	assert.NoError(t, err)

	assert.Len(t, chainsAdded, 3)
	assert.Len(t, rulesAdded, 2)

	// Verify input chain rule
	assert.Equal(t, chainsAdded[0].Name, "input")
	assert.Equal(t, chainsAdded[0], rulesAdded[0].Chain)

	// Verify output chain rule
	assert.Equal(t, chainsAdded[2].Name, "output")
	assert.Equal(t, chainsAdded[2], rulesAdded[1].Chain)

	// Verify expression structure for first rule (input)
	exprs := rulesAdded[0].Exprs
	assert.Len(t, exprs, 4)

	// Ct state expression
	ctExpr, ok := exprs[0].(*expr.Ct)
	assert.True(t, ok, "expected Ct expression")
	assert.Equal(t, expr.CtKeySTATE, ctExpr.Key)
	assert.Equal(t, uint32(1), ctExpr.Register)

	// Bitwise expression
	bwExpr, ok := exprs[1].(*expr.Bitwise)
	assert.True(t, ok, "expected Bitwise expression")
	assert.Equal(t, uint32(1), bwExpr.SourceRegister)
	assert.Equal(t, uint32(1), bwExpr.DestRegister)
	assert.Equal(t, uint32(4), bwExpr.Len)
	expectedMask := []byte{byte(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED), 0x00, 0x00, 0x00}
	assert.Equal(t, expectedMask, bwExpr.Mask)

	// Cmp expression
	cmpExpr, ok := exprs[2].(*expr.Cmp)
	assert.True(t, ok, "expected Cmp expression")
	assert.Equal(t, expr.CmpOpNeq, cmpExpr.Op)
	assert.Equal(t, uint32(1), cmpExpr.Register)

	// Verdict expression
	verdictExpr, ok := exprs[3].(*expr.Verdict)
	assert.True(t, ok, "expected Verdict expression")
	assert.Equal(t, expr.VerdictAccept, verdictExpr.Kind)

	// Output rule should have same structure as input rule
	assert.Equal(t, rulesAdded[0].Exprs, rulesAdded[1].Exprs)
}
