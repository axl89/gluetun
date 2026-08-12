package nftables

import (
	"testing"

	"github.com/google/nftables"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func Test_SaveAndRestore(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		setupFirstConn  func(ctrl *gomock.Controller) dialFunc
		setupSecondConn func(ctrl *gomock.Controller) dialFunc
		setupMockLogger func(ctrl *gomock.Controller) Logger
		errorContains   string
	}{
		"dial_error_on_save": {
			setupFirstConn: func(_ *gomock.Controller) dialFunc {
				return func() (conn, error) { return nil, assert.AnError }
			},
			errorContains: "creating nftables connection",
		},
		"save_error_list_tables": {
			setupFirstConn: func(ctrl *gomock.Controller) dialFunc {
				mockConn := NewMockConn(ctrl)
				mockConn.EXPECT().ListTables().Return(nil, assert.AnError)
				return func() (conn, error) { return mockConn, nil }
			},
			errorContains: "saving nftables state",
		},
		"success_save_and_restore_no_tables": {
			setupFirstConn: func(ctrl *gomock.Controller) dialFunc {
				mockConn := NewMockConn(ctrl)
				mockConn.EXPECT().ListTables().Return(nil, nil)
				return func() (conn, error) { return mockConn, nil }
			},
			setupSecondConn: func(ctrl *gomock.Controller) dialFunc {
				mockConn := NewMockConn(ctrl)
				mockConn.EXPECT().FlushRuleset()
				mockConn.EXPECT().Flush().Return(nil)
				return func() (conn, error) { return mockConn, nil }
			},
		},
		"success_save_restore_with_tables_and_chains": {
			setupFirstConn: func(ctrl *gomock.Controller) dialFunc {
				mockConn := NewMockConn(ctrl)
				table := &nftables.Table{Name: "filter", Family: nftables.TableFamilyINet}
				chain := &nftables.Chain{Name: "input", Table: table}
				rule := &nftables.Rule{Table: table, Chain: chain}

				mockConn.EXPECT().ListTables().Return([]*nftables.Table{table}, nil)
				mockConn.EXPECT().ListChains().Return([]*nftables.Chain{chain}, nil)
				mockConn.EXPECT().GetRules(table, chain).Return([]*nftables.Rule{rule}, nil)

				return func() (conn, error) { return mockConn, nil }
			},
			setupSecondConn: func(ctrl *gomock.Controller) dialFunc {
				mockConn := NewMockConn(ctrl)

				mockConn.EXPECT().FlushRuleset()
				mockConn.EXPECT().AddTable(gomock.Any()).DoAndReturn(func(t *nftables.Table) *nftables.Table {
					return t
				})
				mockConn.EXPECT().AddChain(gomock.Any()).DoAndReturn(func(c *nftables.Chain) *nftables.Chain {
					return c
				})
				mockConn.EXPECT().AddRule(gomock.Any()).DoAndReturn(func(r *nftables.Rule) *nftables.Rule {
					return r
				})
				mockConn.EXPECT().Flush().Return(nil)

				return func() (conn, error) { return mockConn, nil }
			},
		},
		"restore_warns_on_dial_error": {
			setupFirstConn: func(ctrl *gomock.Controller) dialFunc {
				mockConn := NewMockConn(ctrl)
				mockConn.EXPECT().ListTables().Return(nil, nil)
				return func() (conn, error) { return mockConn, nil }
			},
			setupMockLogger: func(ctrl *gomock.Controller) Logger {
				logger := NewMockLogger(ctrl)
				logger.EXPECT().Warnf(gomock.Any(), gomock.Any())
				return logger
			},
			setupSecondConn: func(_ *gomock.Controller) dialFunc {
				return func() (conn, error) { return nil, assert.AnError }
			},
		},
		"restore_warns_on_restore_error": {
			setupFirstConn: func(ctrl *gomock.Controller) dialFunc {
				mockConn := NewMockConn(ctrl)
				mockConn.EXPECT().ListTables().Return([]*nftables.Table{{Name: "filter"}}, nil)
				mockConn.EXPECT().ListChains().Return(nil, nil)
				return func() (conn, error) { return mockConn, nil }
			},
			setupMockLogger: func(ctrl *gomock.Controller) Logger {
				logger := NewMockLogger(ctrl)
				logger.EXPECT().Warnf(gomock.Any(), gomock.Any())
				return logger
			},
			setupSecondConn: func(ctrl *gomock.Controller) dialFunc {
				mockConn := NewMockConn(ctrl)
				mockConn.EXPECT().FlushRuleset()
				mockConn.EXPECT().AddTable(gomock.Any()).DoAndReturn(func(t *nftables.Table) *nftables.Table {
					return t
				})
				mockConn.EXPECT().Flush().Return(assert.AnError)
				return func() (conn, error) { return mockConn, nil }
			},
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
			} else {
				dialFuncs = append(dialFuncs, firstConn)
			}

			dialFunc := func() (conn, error) {
				if len(dialFuncs) > 0 {
					df := dialFuncs[0]
					dialFuncs = dialFuncs[1:]
					return df()
				}
				return nil, assert.AnError
			}

			var logger Logger
			if testCase.setupMockLogger != nil {
				logger = testCase.setupMockLogger(ctrl)
			} else {
				logger = NewMockLogger(ctrl)
			}
			firewall := &Firewall{logger: logger, dialFunc: dialFunc}

			ctx := t.Context()
			restore, err := firewall.SaveAndRestore(ctx)

			if testCase.errorContains != "" {
				assert.Error(t, err)
				if testCase.errorContains != "" {
					assert.ErrorContains(t, err, testCase.errorContains)
				}
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, restore)

			// Call restore if it should work
			if testCase.setupSecondConn != nil {
				restore(ctx)
			}
		})
	}
}

func Test_saveTables(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		setupConn func(ctrl *gomock.Controller) conn

		errorContains  string
		expectedTables int
	}{
		"list_tables_error": {
			setupConn: func(ctrl *gomock.Controller) conn {
				mockConn := NewMockConn(ctrl)
				mockConn.EXPECT().ListTables().Return(nil, assert.AnError)
				return mockConn
			},
			errorContains: "assert.AnError",
		},
		"empty_tables": {
			setupConn: func(ctrl *gomock.Controller) conn {
				mockConn := NewMockConn(ctrl)
				mockConn.EXPECT().ListTables().Return(nil, nil)
				return mockConn
			},

			expectedTables: 0,
		},
		"table_with_chains_and_rules": {
			setupConn: func(ctrl *gomock.Controller) conn {
				mockConn := NewMockConn(ctrl)
				table := &nftables.Table{Name: "filter", Family: nftables.TableFamilyINet}
				chain := &nftables.Chain{Name: "input", Table: table}
				rule := &nftables.Rule{Table: table, Chain: chain}

				mockConn.EXPECT().ListTables().Return([]*nftables.Table{table}, nil)
				mockConn.EXPECT().ListChains().Return([]*nftables.Chain{chain}, nil)
				mockConn.EXPECT().GetRules(table, chain).Return([]*nftables.Rule{rule}, nil)

				return mockConn
			},

			expectedTables: 1,
		},
		"list_chains_error": {
			setupConn: func(ctrl *gomock.Controller) conn {
				mockConn := NewMockConn(ctrl)
				table := &nftables.Table{Name: "filter", Family: nftables.TableFamilyINet}

				mockConn.EXPECT().ListTables().Return([]*nftables.Table{table}, nil)
				mockConn.EXPECT().ListChains().Return(nil, assert.AnError)

				return mockConn
			},
			errorContains: "assert.AnError",
		},
		"get_rules_error": {
			setupConn: func(ctrl *gomock.Controller) conn {
				mockConn := NewMockConn(ctrl)
				table := &nftables.Table{Name: "filter", Family: nftables.TableFamilyINet}
				chain := &nftables.Chain{Name: "input", Table: table}

				mockConn.EXPECT().ListTables().Return([]*nftables.Table{table}, nil)
				mockConn.EXPECT().ListChains().Return([]*nftables.Chain{chain}, nil)
				mockConn.EXPECT().GetRules(table, chain).Return(nil, assert.AnError)

				return mockConn
			},
			errorContains: "getting rules for chain",
		},
		"filter_chains_by_table": {
			setupConn: func(ctrl *gomock.Controller) conn {
				mockConn := NewMockConn(ctrl)
				filterTable := &nftables.Table{Name: "filter", Family: nftables.TableFamilyINet}
				natTable := &nftables.Table{Name: "nat", Family: nftables.TableFamilyINet}
				filterChain := &nftables.Chain{Name: "input", Table: filterTable}
				natChain := &nftables.Chain{Name: "prerouting", Table: natTable}
				rule := &nftables.Rule{Table: filterTable, Chain: filterChain}

				mockConn.EXPECT().ListTables().Return([]*nftables.Table{filterTable, natTable}, nil)
				mockConn.EXPECT().ListChains().Return([]*nftables.Chain{filterChain, natChain}, nil).Times(2)
				mockConn.EXPECT().GetRules(filterTable, filterChain).Return([]*nftables.Rule{rule}, nil)
				mockConn.EXPECT().GetRules(natTable, natChain).Return(nil, nil)

				return mockConn
			},

			expectedTables: 2,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			conn := testCase.setupConn(ctrl)

			result, err := saveTables(conn)

			if testCase.errorContains != "" {
				assert.Error(t, err)
				if testCase.errorContains != "" {
					assert.ErrorContains(t, err, testCase.errorContains)
				}
			} else {
				assert.NoError(t, err)
				assert.Len(t, result, testCase.expectedTables)
			}
		})
	}
}
