//go:build linux

package nftables

import (
	"errors"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func testRule(table *nftables.Table, chain *nftables.Chain, handle uint64) *nftables.Rule {
	return &nftables.Rule{
		Table: table, Chain: chain, Handle: handle,
		Exprs: []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}},
	}
}

// sampleState is the set of tables, chains, and rules used by save/restore tests.
type sampleState struct {
	filterTable     *nftables.Table
	natTable        *nftables.Table
	inputChain      *nftables.Chain
	forwardChain    *nftables.Chain
	outputChain     *nftables.Chain
	preroutingChain *nftables.Chain
	inputRules      []*nftables.Rule
	preroutingRules []*nftables.Rule
}

// buildSampleState creates a filter table (input/forward/output chains) and a
// nat table (prerouting chain), with a couple of rules, for save/restore tests.
func buildSampleState() sampleState {
	filterTable := &nftables.Table{Family: nftables.TableFamilyINet, Name: filterTableName}
	natTable := &nftables.Table{Family: nftables.TableFamilyINet, Name: natTableName}
	inputChain := &nftables.Chain{
		Name: inputChainName, Table: filterTable, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookInput, Priority: nftables.ChainPriorityFilter,
	}
	forwardChain := &nftables.Chain{
		Name: forwardChainName, Table: filterTable, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookForward, Priority: nftables.ChainPriorityFilter,
	}
	outputChain := &nftables.Chain{
		Name: outputChainName, Table: filterTable, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookOutput, Priority: nftables.ChainPriorityFilter,
	}
	preroutingChain := &nftables.Chain{
		Name: preroutingChainName, Table: natTable, Type: nftables.ChainTypeNAT,
		Hooknum: nftables.ChainHookPrerouting, Priority: nftables.ChainPriorityNATDest,
	}

	inputRules := []*nftables.Rule{
		testRule(filterTable, inputChain, 10),
		testRule(filterTable, inputChain, 11),
	}
	preroutingRules := []*nftables.Rule{
		testRule(natTable, preroutingChain, 20),
	}
	return sampleState{
		filterTable:     filterTable,
		natTable:        natTable,
		inputChain:      inputChain,
		forwardChain:    forwardChain,
		outputChain:     outputChain,
		preroutingChain: preroutingChain,
		inputRules:      inputRules,
		preroutingRules: preroutingRules,
	}
}

func Test_saveTables(t *testing.T) {
	t.Parallel()

	state := buildSampleState()
	filterTable := state.filterTable
	natTable := state.natTable
	inputChain := state.inputChain
	forwardChain := state.forwardChain
	outputChain := state.outputChain
	preroutingChain := state.preroutingChain
	inputRules := state.inputRules
	preroutingRules := state.preroutingRules

	ctrl := gomock.NewController(t)
	mockConn := NewMockConn(ctrl)

	mockConn.EXPECT().ListTables().Return([]*nftables.Table{filterTable, natTable}, nil)
	mockConn.EXPECT().ListChains().Return(
		[]*nftables.Chain{inputChain, forwardChain, outputChain, preroutingChain}, nil,
	)
	mockConn.EXPECT().GetRules(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ *nftables.Table, chain *nftables.Chain) ([]*nftables.Rule, error) {
			switch chain.Name {
			case inputChainName:
				return inputRules, nil
			case preroutingChainName:
				return preroutingRules, nil
			default:
				return nil, nil
			}
		},
	).Times(4)

	savedTables, err := saveTables(mockConn)

	assert.NoError(t, err)
	require.Len(t, savedTables, 2)

	assert.Equal(t, filterTable, savedTables[0].table)
	require.Len(t, savedTables[0].chains, 3)
	assert.Equal(t, inputRules, savedTables[0].chains[0].rules)
	assert.Empty(t, savedTables[0].chains[1].rules)
	assert.Empty(t, savedTables[0].chains[2].rules)

	assert.Equal(t, natTable, savedTables[1].table)
	require.Len(t, savedTables[1].chains, 1)
	assert.Equal(t, preroutingRules, savedTables[1].chains[0].rules)
}

func Test_restoreTables(t *testing.T) {
	t.Parallel()

	state := buildSampleState()
	filterTable := state.filterTable
	natTable := state.natTable
	inputChain := state.inputChain
	preroutingChain := state.preroutingChain
	inputRules := state.inputRules
	preroutingRules := state.preroutingRules

	savedTables := []savedTable{
		{
			table: filterTable,
			chains: []savedChain{
				{chain: inputChain, rules: inputRules},
			},
		},
		{
			table: natTable,
			chains: []savedChain{
				{chain: preroutingChain, rules: preroutingRules},
			},
		},
	}

	ctrl := gomock.NewController(t)
	mockConn := NewMockConn(ctrl)

	var restoredChains []*nftables.Chain
	var addedRules []*nftables.Rule

	mockConn.EXPECT().AddTable(gomock.Any()).DoAndReturn(func(table *nftables.Table) *nftables.Table {
		return table
	}).Times(2)
	mockConn.EXPECT().AddChain(gomock.Any()).DoAndReturn(func(chain *nftables.Chain) *nftables.Chain {
		restoredChains = append(restoredChains, chain)
		return chain
	}).Times(2)
	mockConn.EXPECT().FlushChain(gomock.Any()).Times(2)
	mockConn.EXPECT().AddRule(gomock.Any()).DoAndReturn(func(rule *nftables.Rule) *nftables.Rule {
		addedRules = append(addedRules, rule)
		return rule
	}).Times(3)
	mockConn.EXPECT().Flush().Return(nil)

	err := restoreTables(mockConn, savedTables)

	assert.NoError(t, err)

	// Two chains restored (input and prerouting).
	require.Len(t, restoredChains, 2)
	assert.Equal(t, inputChainName, restoredChains[0].Name)
	assert.Equal(t, filterTable, restoredChains[0].Table)
	assert.Equal(t, preroutingChainName, restoredChains[1].Name)
	assert.Equal(t, natTable, restoredChains[1].Table)

	// Three rules re-added (2 input + 1 prerouting), all with handle 0 and
	// pointing at the restored chain.
	require.Len(t, addedRules, 3)
	for i, rule := range addedRules {
		assert.Zero(t, rule.Handle)
		if i < 2 {
			assert.Equal(t, restoredChains[0], rule.Chain)
			assert.Equal(t, inputRules[i].Exprs, rule.Exprs)
		} else {
			assert.Equal(t, restoredChains[1], rule.Chain)
			assert.Equal(t, preroutingRules[i-2].Exprs, rule.Exprs)
		}
	}

	// The saved state must not be mutated, so restore can be called again.
	assert.Equal(t, uint64(10), inputRules[0].Handle)
	assert.Equal(t, inputChain, inputRules[0].Chain)
}

func Test_SaveAndRestore(t *testing.T) {
	t.Parallel()

	state := buildSampleState()
	filterTable := state.filterTable
	inputChain := state.inputChain
	inputRules := state.inputRules

	testCases := map[string]struct {
		restoreFlushError error
		expectWarning     bool
	}{
		"success": {},
		"restore_flush_error_logs_warning": {
			restoreFlushError: errors.New("restore flush failed"),
			expectWarning:     true,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			mockConn := NewMockConn(ctrl)
			mockLogger := NewMockLogger(ctrl)
			f := &Firewall{
				dialFunc: func() (conn, error) { return mockConn, nil },
				logger:   mockLogger,
			}

			// Save phase.
			mockConn.EXPECT().ListTables().Return([]*nftables.Table{filterTable}, nil)
			mockConn.EXPECT().ListChains().Return([]*nftables.Chain{inputChain}, nil)
			mockConn.EXPECT().GetRules(gomock.Any(), gomock.Any()).Return(inputRules, nil)

			// Restore phase (called by the returned restore function).
			mockConn.EXPECT().AddTable(gomock.Any()).DoAndReturn(func(table *nftables.Table) *nftables.Table {
				return table
			})
			mockConn.EXPECT().AddChain(gomock.Any()).DoAndReturn(func(chain *nftables.Chain) *nftables.Chain {
				return chain
			})
			mockConn.EXPECT().FlushChain(gomock.Any())
			mockConn.EXPECT().AddRule(gomock.Any()).DoAndReturn(func(rule *nftables.Rule) *nftables.Rule {
				return rule
			}).Times(2)
			mockConn.EXPECT().Flush().Return(testCase.restoreFlushError)

			if testCase.expectWarning {
				mockLogger.EXPECT().Warnf(gomock.Any(), gomock.Any()).
					Do(func(format string, _ ...any) {
						assert.Contains(t, format, "restoring nftables state")
					})
			}

			restore, err := f.SaveAndRestore(t.Context())
			require.NoError(t, err)
			require.NotNil(t, restore)

			restore(t.Context())
		})
	}
}

// Test_SaveAndRestore_restore_idempotent verifies that the returned restore
// function can be called multiple times without mutating the saved state.
func Test_SaveAndRestore_restore_idempotent(t *testing.T) {
	t.Parallel()

	state := buildSampleState()
	filterTable := state.filterTable
	inputChain := state.inputChain
	inputRules := state.inputRules

	ctrl := gomock.NewController(t)
	mockConn := NewMockConn(ctrl)
	f := &Firewall{dialFunc: func() (conn, error) { return mockConn, nil }}

	// Save phase.
	mockConn.EXPECT().ListTables().Return([]*nftables.Table{filterTable}, nil)
	mockConn.EXPECT().ListChains().Return([]*nftables.Chain{inputChain}, nil)
	mockConn.EXPECT().GetRules(gomock.Any(), gomock.Any()).Return(inputRules, nil)

	// Two restore phases.
	for range 2 {
		mockConn.EXPECT().AddTable(gomock.Any()).DoAndReturn(func(table *nftables.Table) *nftables.Table {
			return table
		})
		mockConn.EXPECT().AddChain(gomock.Any()).DoAndReturn(func(chain *nftables.Chain) *nftables.Chain {
			return chain
		})
		mockConn.EXPECT().FlushChain(gomock.Any())
		mockConn.EXPECT().AddRule(gomock.Any()).DoAndReturn(func(rule *nftables.Rule) *nftables.Rule {
			return rule
		}).Times(2)
		mockConn.EXPECT().Flush().Return(nil)
	}

	restore, err := f.SaveAndRestore(t.Context())
	require.NoError(t, err)

	restore(t.Context())
	restore(t.Context())

	// Saved state is intact after two restores.
	assert.Equal(t, uint64(10), inputRules[0].Handle)
	assert.Equal(t, inputChain, inputRules[0].Chain)
}
