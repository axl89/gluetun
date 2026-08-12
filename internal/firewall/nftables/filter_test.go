package nftables

import (
	"testing"

	"github.com/google/nftables"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func Test_setupFilterWithBaseChains(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		expectedTableFamily nftables.TableFamily
	}{
		"default": {
			expectedTableFamily: nftables.TableFamilyINet,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			mockConn := NewMockConn(ctrl)

			_ = testCase.expectedTableFamily

			mockConn.EXPECT().AddTable(gomock.Any()).DoAndReturn(func(table *nftables.Table) *nftables.Table {
				return table
			})
			mockConn.EXPECT().AddChain(gomock.Any()).DoAndReturn(func(chain *nftables.Chain) *nftables.Chain {
				return chain
			}).Times(3)

			resultTable, resultInputChain, resultForwardChain, resultOutputChain := setupFilterWithBaseChains(mockConn)

			assert.NotNil(t, resultTable)
			assert.Equal(t, "filter", resultTable.Name)
			assert.Equal(t, testCase.expectedTableFamily, resultTable.Family)

			assert.NotNil(t, resultInputChain)
			assert.Equal(t, "input", resultInputChain.Name)
			assert.Equal(t, nftables.ChainTypeFilter, resultInputChain.Type)
			assert.Equal(t, nftables.ChainHookInput, resultInputChain.Hooknum)

			assert.NotNil(t, resultForwardChain)
			assert.Equal(t, "forward", resultForwardChain.Name)
			assert.Equal(t, nftables.ChainTypeFilter, resultForwardChain.Type)
			assert.Equal(t, nftables.ChainHookForward, resultForwardChain.Hooknum)

			assert.NotNil(t, resultOutputChain)
			assert.Equal(t, "output", resultOutputChain.Name)
			assert.Equal(t, nftables.ChainTypeFilter, resultOutputChain.Type)
			assert.Equal(t, nftables.ChainHookOutput, resultOutputChain.Hooknum)
		})
	}
}
