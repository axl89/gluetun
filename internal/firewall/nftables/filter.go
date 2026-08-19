package nftables

import (
	"fmt"

	"github.com/google/nftables"
)

const (
	filterTableName  = "filter"
	inputChainName   = "input"
	forwardChainName = "forward"
	outputChainName  = "output"
)

// getFilterTable returns the inet filter table if it exists.
func getFilterTable(conn conn) (*nftables.Table, bool, error) {
	tables, err := conn.ListTables()
	if err != nil {
		return nil, false, fmt.Errorf("listing tables: %w", err)
	}
	for _, table := range tables {
		if table.Family == nftables.TableFamilyINet && table.Name == filterTableName {
			return table, true, nil
		}
	}
	return nil, false, nil
}

// setupFilterWithBaseChains ensures that the inet filter table and its three
// base chains (input, forward, output) exist, returning them.
// If policy is non-nil, it is applied to each of the base chains, existing or
// newly created.
func setupFilterWithBaseChains(conn conn, policy *nftables.ChainPolicy) (table *nftables.Table,
	inputChain, forwardChain, outputChain *nftables.Chain,
	err error,
) {
	table, found, err := getFilterTable(conn)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if !found {
		table = conn.AddTable(&nftables.Table{
			Family: nftables.TableFamilyINet,
			Name:   filterTableName,
		})
	}

	existingChains := make(map[string]*nftables.Chain)
	if found {
		chains, err := conn.ListChains()
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("listing chains: %w", err)
		}
		for _, chain := range chains {
			if chain.Table.Family == table.Family && chain.Table.Name == table.Name {
				existingChains[chain.Name] = chain
			}
		}
	}

	ensureChain := func(name string, hooknum *nftables.ChainHook) *nftables.Chain {
		if chain, ok := existingChains[name]; ok {
			if policy != nil {
				chain.Policy = policy
				conn.AddChain(chain)
			}
			return chain
		}
		return conn.AddChain(&nftables.Chain{
			Name:     name,
			Table:    table,
			Type:     nftables.ChainTypeFilter,
			Hooknum:  hooknum,
			Priority: nftables.ChainPriorityFilter,
			Policy:   policy,
		})
	}

	inputChain = ensureChain(inputChainName, nftables.ChainHookInput)
	forwardChain = ensureChain(forwardChainName, nftables.ChainHookForward)
	outputChain = ensureChain(outputChainName, nftables.ChainHookOutput)

	return table, inputChain, forwardChain, outputChain, nil
}
