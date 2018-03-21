// gonmap - Wrapper around Nmap
// Copyright (c) 2017, 2018, DCSO GmbH

// Package gonmap port scanning is implemented through the PortScan type.
package gonmap

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"os/exec"
	"strings"
)

// portScanProtocols are the protocols we support when doing port scans
// with Nmap. The values in the map represent the Nmap options.
var portScanProtocols = map[string]string{
	"tcp": "-sT",
	"udp": "-sU",
}

// PortScan holds information for running the port scan and provides
// functionality to run and get the result.
type PortScan struct {
	target    string
	protocols map[string]struct{}
	result    NmapRun
	Nmap
}

// NewPortScan creates a new PortScan using a target and protocols. A target
// can be either an IP address or a hostname. `protocols` should be a slice
// of strings containing 'tcp' or 'udp' or both.
func NewPortScan(target string, protocols []string) (*PortScan, error) {
	n := &PortScan{
		target:    target,
		protocols: make(map[string]struct{}),
	}
	err := n.SetProtocols(protocols)
	if err != nil {
		return nil, err
	}
	return n, nil
}

// Target returns the target.
func (n *PortScan) Target() string {
	return n.target
}

// Protocols returns a slice of strings containing the protocols used for
// performing the port scan.
func (n *PortScan) Protocols() []string {
	r := []string{}
	for p := range n.protocols {
		r = append(r, p)
	}
	return r
}

// SetProtocols sets the protocol or protocols for performing the port scan.
func (n *PortScan) SetProtocols(protocols []string) error {
	// List of supported protocols

	for _, p := range protocols {
		p = strings.ToLower(p)
		if portScanProtocols[p] == "" {
			return fmt.Errorf("Invalid protocol %s", p)
		}
		n.protocols[p] = struct{}{}
	}
	return nil
}

// unmarschalXML calls `xml.Unmarshal` to process the result of Nmap. The result
// is stored.
func (n *PortScan) unmarschalXML(xmldoc []byte) error {
	return xml.Unmarshal(xmldoc, &n.result)
}

// Run executes the port scan. The result is stored and can be retrieved using
// the `Result()` function.
func (n *PortScan) Run() error {
	cmdArgs := []string{"-oX", "-"}
	for p := range n.protocols {
		cmdArgs = append(cmdArgs, portScanProtocols[p])
	}
	cmdArgs = append(cmdArgs, n.target)
	cmd := exec.Command(nmapBin, cmdArgs...)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Run()
	// nmap does not set exit code on scan failures

	n.unmarschalXML(stdout.Bytes())
	if len(n.result.Hosts) == 0 {
		// if host is not mentioned in XML, it means we could not use it
		return fmt.Errorf("failed scanning target '%s'", n.target)
	}
	return nil
}

// Result returns the results after running the port scan.
func (n *PortScan) Result() NmapRun {
	return n.result
}
