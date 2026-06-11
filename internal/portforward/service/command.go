package service

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/qdm12/gluetun/internal/command"
)

func runCommand(ctx context.Context, cmder Cmder, logger Logger,
	commandTemplate string, ports []uint16, vpnInterface string,
) (err error) {
	portStrings := make([]string, len(ports))
	for i, port := range ports {
		portStrings[i] = fmt.Sprint(int(port))
	}
	portsString := strings.Join(portStrings, ",")
	commandString := strings.ReplaceAll(commandTemplate, "{{PORTS}}", portsString)
	var firstPort string
	if len(portStrings) > 0 {
		firstPort = portStrings[0]
	}
	commandString = strings.ReplaceAll(commandString, "{{PORT}}", firstPort)
	commandString = strings.ReplaceAll(commandString, "{{VPN_INTERFACE}}", vpnInterface)
	args, err := command.Split(commandString)
	if err != nil {
		return fmt.Errorf("parsing command: %w", err)
	}

	cmd := exec.CommandContext(ctx, args[0], args[1:]...) // #nosec G204
	stdout, stderr, waitError, err := cmder.Start(cmd)
	if err != nil {
		return err
	}

	streamDone := make(chan struct{})
	go streamLines(streamDone, logger, stdout, stderr)

	err = <-waitError
	<-streamDone
	return err
}

func streamLines(done chan<- struct{}, logger Logger,
	stdout, stderr <-chan string,
) {
	defer close(done)

	for {
		select {
		case line, ok := <-stdout:
			if ok {
				logger.Info(line)
			}
			if stderr == nil {
				return
			}
			stdout = nil
		case line, ok := <-stderr:
			if ok {
				logger.Error(line)
			}
			if stdout == nil {
				return
			}
			stderr = nil
		}
	}
}
