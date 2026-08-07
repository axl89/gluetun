package nftables

import (
	"runtime/debug"
	"sync"

	"github.com/google/nftables"
)

type Firewall struct {
	logger    Logger
	buildInfo *debug.BuildInfo

	// rules are only rules added and tracked for later removal.
	// Not all rules added are tracked for removal.
	rules []*nftables.Rule
	mutex sync.Mutex
}

func New(logger Logger, buildInfo *debug.BuildInfo) *Firewall {
	return &Firewall{
		logger:    logger,
		buildInfo: buildInfo,
	}
}
