package nftables

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/google/nftables"
)

const (
	iptablesCommand      = "iptables-nft"
	iptablesFallbackCmd  = "iptables"
	ip6tablesCommand     = "ip6tables-nft"
	ip6tablesFallbackCmd = "ip6tables"
)

func IsSupported() bool {
	conn, err := nftables.New()
	if err != nil {
		return false
	}
	_, err = conn.ListTable("filter")
	return err == nil
}

// Version obtains the version of the installed nftables.
func (f *Firewall) Version(ctx context.Context) (string, error) {
	const emptyVersionError = "nft version string is empty"
	cmd := exec.CommandContext(ctx, "nft", "-v")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("running nft -v: %w", err)
	}
	outputStr := strings.TrimSpace(string(output))
	words := strings.Fields(outputStr)
	if len(words) == 0 {
		return "", errors.New(emptyVersionError) //nolint:err113
	}
	return words[0], nil
}

// findIptablesCommand finds the available iptables-nft or iptables command.
func findIptablesCommand() (string, error) {
	if path, err := exec.LookPath(iptablesCommand); err == nil {
		return path, nil
	}
	if path, err := exec.LookPath(iptablesFallbackCmd); err == nil {
		return path, nil
	}
	return "", fmt.Errorf("iptables command not found: %s or %s", iptablesCommand, iptablesFallbackCmd) //nolint:err113
}

// findIP6tablesCommand finds the available ip6tables-nft or ip6tables command.
func findIP6tablesCommand() (string, error) {
	if path, err := exec.LookPath(ip6tablesCommand); err == nil {
		return path, nil
	}
	if path, err := exec.LookPath(ip6tablesFallbackCmd); err == nil {
		return path, nil
	}
	return "", fmt.Errorf("ip6tables command not found: %s or %s", ip6tablesCommand, ip6tablesFallbackCmd) //nolint:err113
}

// RunUserPostRules reads and executes custom iptables-style rules from a file.
// Since iptables-nft is nftables under the hood, we delegate to it for rule
// parsing compatibility with user-written iptables rules.
func (f *Firewall) RunUserPostRules(ctx context.Context, filepath string) error {
	file, err := os.OpenFile(filepath, os.O_RDONLY, 0)
	if os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return fmt.Errorf("opening user rules file: %w", err)
	}
	content, err := io.ReadAll(file)
	if err != nil {
		_ = file.Close()
		return fmt.Errorf("reading user rules file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("closing user rules file: %w", err)
	}
	lines := strings.Split(string(content), "\n")

	iptablesCmd, err := findIptablesCommand()
	if err != nil {
		f.logger.Warnf("iptables-nft not available, skipping user post-rules for IPv4")
	}
	ip6tablesCmd, err := findIP6tablesCommand()
	if err != nil {
		f.logger.Warnf("ip6tables-nft not available, IPv6 user post-rules will fail")
	}

	for lineNum, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		var cmdName string
		var ruleArgs string
		switch {
		case strings.HasPrefix(line, "iptables "):
			cmdName = iptablesCmd
			ruleArgs = strings.TrimPrefix(line, "iptables ")
		case strings.HasPrefix(line, "iptables-nft "):
			cmdName = iptablesCmd
			ruleArgs = strings.TrimPrefix(line, "iptables-nft ")
		case strings.HasPrefix(line, "iptables-legacy "):
			cmdName = iptablesCmd
			ruleArgs = strings.TrimPrefix(line, "iptables-legacy ")
		case strings.HasPrefix(line, "ip6tables "):
			cmdName = ip6tablesCmd
			ruleArgs = strings.TrimPrefix(line, "ip6tables ")
		case strings.HasPrefix(line, "ip6tables-nft "):
			cmdName = ip6tablesCmd
			ruleArgs = strings.TrimPrefix(line, "ip6tables-nft ")
		case strings.HasPrefix(line, "ip6tables-legacy "):
			cmdName = ip6tablesCmd
			ruleArgs = strings.TrimPrefix(line, "ip6tables-legacy ")
		default:
			continue
		}

		if cmdName == "" {
			continue
		}

		args := strings.Fields(ruleArgs)
		if len(args) == 0 {
			continue
		}

		cmd := exec.CommandContext(ctx, cmdName, args...)
		output, err := cmd.CombinedOutput()
		if err != nil {
			outputStr := strings.TrimSpace(string(output))
			return fmt.Errorf("running user rule on line %d (%s %s): %w: %s",
				lineNum+1, cmdName, ruleArgs, err, outputStr)
		}
	}

	return nil
}
