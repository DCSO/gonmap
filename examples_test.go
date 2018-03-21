// DCSO gonmap - Wrapper around Nmap
// Copyright (c) 2017, 2018, DCSO GmbH

package gonmap_test

import (
	"fmt"
	"os"

	"github.com/DCSO/gonmap"
)

func ExamplePortScan() {
	scan, err := gonmap.NewPortScan("localhost", []string{"tcp"})
	if err != nil {
		fmt.Printf("nmap failed: %s", err)
		os.Exit(1)
	}
	scan.Run()

	f := "%5d/%s %-15s %s\n"
	ft := "%9s %-15s %s\n"
	for _, host := range scan.Result().Hosts {
		fmt.Printf("Nmap scan report for %s\n", host.Address.Address)
		fmt.Printf(ft, "PORT", "STATE", "SERVICE")
		for _, p := range host.Ports {
			fmt.Printf(f, p.Port, p.Protocol, p.Status.State, p.Service.Name)
		}
	}
}
