package nftables

import (
	"context"
	"fmt"

	"github.com/google/nftables"
)

// SaveAndRestore saves the current nftables tree and returns a restore
// function that can be called to restore the saved tree.
func (f *Firewall) SaveAndRestore(_ context.Context) (func(context.Context), error) {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	innerRestore, err := f.saveAndRestoreLocked()
	if err != nil {
		return nil, err
	}

	// The caller of the returned restore function does not hold the mutex.
	return func(ctx context.Context) {
		f.mutex.Lock()
		defer f.mutex.Unlock()

		innerRestore(ctx)
	}, nil
}

// saveAndRestoreLocked saves the current nftables tree and returns a restore
// function. Callers MUST hold the mutex, and the returned restore function
// requires it to be held as well.
func (f *Firewall) saveAndRestoreLocked() (restore func(context.Context), err error) {
	conn, err := f.dialFunc()
	if err != nil {
		return nil, fmt.Errorf("creating nftables connection: %w", err)
	}

	tables, err := saveTables(conn)
	if err != nil {
		return nil, fmt.Errorf("saving nftables state: %w", err)
	}

	return func(ctx context.Context) {
		f.restoreTablesLocked(ctx, tables)
	}, nil
}

// restoreTablesLocked restores the saved nftables tree, logging a warning on
// failure. Callers MUST hold the mutex.
func (f *Firewall) restoreTablesLocked(_ context.Context, tables []savedTable) {
	conn, err := f.dialFunc()
	if err != nil {
		f.logger.Warnf("creating nftables connection for restore: %s", err)
		return
	}
	if err := restoreTables(conn, tables); err != nil {
		f.logger.Warnf("restoring nftables state: %s", err)
	}
}

type tableKey struct {
	family nftables.TableFamily
	name   string
}

type savedTable struct {
	table  *nftables.Table
	chains []savedChain
}

type savedChain struct {
	chain *nftables.Chain
	rules []*nftables.Rule
}

// saveTables saves the state of all the tables, their chains, and their rules.
func saveTables(conn conn) ([]savedTable, error) {
	tables, err := conn.ListTables()
	if err != nil {
		return nil, fmt.Errorf("listing tables: %w", err)
	}

	chains, err := conn.ListChains()
	if err != nil {
		return nil, fmt.Errorf("listing chains: %w", err)
	}

	chainsByTable := make(map[tableKey][]*nftables.Chain, len(tables))
	for _, chain := range chains {
		key := tableKey{family: chain.Table.Family, name: chain.Table.Name}
		chainsByTable[key] = append(chainsByTable[key], chain)
	}

	savedTables := make([]savedTable, 0, len(tables))
	for _, table := range tables {
		savedTable := savedTable{table: table}
		key := tableKey{family: table.Family, name: table.Name}
		for _, chain := range chainsByTable[key] {
			rules, err := conn.GetRules(table, chain)
			if err != nil {
				return nil, fmt.Errorf("getting rules for chain %s in table %s: %w",
					chain.Name, table.Name, err)
			}
			savedTable.chains = append(savedTable.chains, savedChain{chain: chain, rules: rules})
		}
		savedTables = append(savedTables, savedTable)
	}

	return savedTables, nil
}

// restoreTables re-adds all the saved tables, chains, and rules, the way
// iptables-restore does: the rules of each saved chain are replaced by the
// saved ones, while other tables and chains are left untouched.
func restoreTables(conn conn, savedTables []savedTable) error {
	for _, savedTable := range savedTables {
		table := conn.AddTable(savedTable.table)
		for _, savedChain := range savedTable.chains {
			// Make a copy so that the saved state is not mutated, allowing the
			// restore to be called multiple times.
			chain := *savedChain.chain
			chain.Table = table
			restoredChain := conn.AddChain(&chain)
			conn.FlushChain(restoredChain)

			for _, rule := range savedChain.rules {
				ruleCopy := *rule
				ruleCopy.Handle = 0 // append, not replace at the saved handle
				ruleCopy.Table = table
				ruleCopy.Chain = restoredChain
				conn.AddRule(&ruleCopy)
			}
		}
	}

	return conn.Flush()
}
