gonmap - Wrapper around Nmap
============================

Copyright (c) 2017, 2018, DCSO Deutsche Cyber-Sicherheitsorganisation GmbH

gonmap is a wrapper around the Nmap tool. It uses the XML output capability
of Nmap to retrieve results and make them available in Go.

Implemented capabilities
------------------------

* Simple port scanner for 1 host using either TCP or UDP.

Dependencies
------------

gonmap requires the Nmap tool to be available in the user's $PATH.

Quick start
-----------

```
import (
	"fmt"
	"os"

	"github.com/DCSO/gonmap"
)

func main() {
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
```

Possible output of the above example:

```
Nmap scan report for 127.0.0.1
     PORT STATE           SERVICE
   22/tcp open            ssh
   80/tcp open            http
 3306/tcp open            mysql
 5000/tcp open            upnp
 5432/tcp open            postgresql
```

License
-------

This project is licensed under a 3-clause BSD-like license.
