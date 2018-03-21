// gonmap - Wrapper around Nmap
// Copyright (c) 2017, 2018, DCSO GmbH

package gonmap

import (
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"
)

var xmlSimplePortScan = `
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<?xml-stylesheet href="file:///usr/bin/../share/nmap/nmap.xsl" type="text/xsl"?>
<!-- Nmap 7.01 scan initiated Tue Jan 10 13:53:18 2017 as: nmap -oX - -sT -p 20-800 localhost -->
<nmaprun scanner="nmap" args="nmap -oX - -sT -p 20-800 localhost" start="1484052798" startstr="Tue Jan 10 13:53:18 2017" version="7.01" xmloutputversion="1.04">
    <scaninfo type="connect" protocol="tcp" numservices="781" services="20-800"/>
    <verbose level="0"/>
    <debugging level="0"/>
    <host starttime="1484052798" endtime="1484052798"><status state="up" reason="syn-ack" reason_ttl="0"/>
        <address addr="127.0.0.1" addrtype="ipv4"/>
        <hostnames>
            <hostname name="localhost" type="user"/>
            <hostname name="localhost" type="PTR"/>
        </hostnames>
        <ports>
            <extraports state="closed" count="779">
                <extrareasons reason="conn-refused" count="779"/>
            </extraports>
            <port protocol="tcp" portid="22"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="ssh" method="table" conf="3"/></port>
            <port protocol="tcp" portid="80"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="http" method="table" conf="3"/></port>
        </ports>
        <times srtt="38" rttvar="26" to="100000"/>
    </host>
    <runstats><finished time="1484052798" timestr="Tue Jan 10 13:53:18 2017" elapsed="0.05" summary="Nmap done at Tue Jan 10 13:53:18 2017; 1 IP address (1 host up) scanned in 0.05 seconds" exit="success"/><hosts up="1" down="0" total="1"/>
    </runstats>
</nmaprun>
`

func TestNewPortScan(t *testing.T) {
	n, _ := NewPortScan("localhost", []string{"tcp"})
	if n.target != "localhost" {
		t.Error("target not initialized correctly")
	}

	exp := map[string]struct{}{"tcp": {}}
	if reflect.DeepEqual(exp, n.protocols) != true {
		t.Error("protocols not initialized correctly")
	}

	// incorrect protocol
	n, err := NewPortScan("localhost", []string{"foo", "bar"})
	if err == nil {
		t.Error("accepted unsupported protocol")
	}
}

func TestPortScanTarget(t *testing.T) {
	n, _ := NewPortScan("example.com", []string{"tcp"})
	if n.Target() != "example.com" {
		t.Fatal("target not initialized correctly")
	}
}

func TestPortScanProtocols(t *testing.T) {
	exp := []string{"tcp"}
	n, _ := NewPortScan("127.0.0.1", exp)
	if reflect.DeepEqual(exp, n.Protocols()) != true {
		t.Error("protocols not initialized correctly")
	}

	exp = []string{"udp", "tcp"}
	n, _ = NewPortScan("127.0.0.1", exp)
	if reflect.DeepEqual(exp, n.Protocols()) != true {
		t.Error("protocols not initialized correctly")
	}
}

func TestPortScanResult(t *testing.T) {
	n, _ := NewPortScan("localhost", []string{"tcp"})
	n.unmarschalXML([]byte(xmlSimplePortScan))

	run := n.Result()
	if run.Args != "nmap -oX - -sT -p 20-800 localhost" {
		t.Fatal("nmaprun args not corect")
	}

	if len(run.Hosts) != 1 {
		t.Fatalf("number of hosts not 1, was %d", len(run.Hosts))
	}
	host := run.Hosts[0]

	if host.Status.State != "up" {
		t.Fatalf("host state not 'up', was '%s'", host.Status.State)
	}

	if host.Address.Address != "127.0.0.1" {
		t.Fatalf("host has incorrect address, was '%s'", host.Address.Address)
	}

	if host.Address.Type != "ipv4" {
		t.Fatalf("host has incorrect type, was '%s'", host.Address.Type)
	}

	ports := host.Ports
	if len(ports) != 2 {
		t.Fatalf("number of scanned ports not 2, was %d", len(ports))
	}

	if ports[0].Port != 22 {
		t.Errorf("first port not 22, was %d", ports[0].Port)
	}

	if ports[1].Port != 80 {
		t.Errorf("second port not 80, was %d", ports[0].Port)
	}
	status := ports[1].Status
	service := ports[1].Service

	if status.State != "open" {
		t.Errorf("port 80 not state 'open', was '%s'", status.State)
	}

	if service.Name != "http" {
		t.Errorf("port 80 not service 'http', was '%s'", service.Name)
	}

	finishedTime := time.Unix(run.Stats.Finished.Time, 0).String()
	exp := "2017-01-10 13:53:18 +0100 CET"
	if finishedTime != exp {
		t.Errorf("finished time not %s, was %s", exp, finishedTime)
	}
}

func TestPortScanRunTcp(t *testing.T) {
	n, _ := NewPortScan("localhost", []string{"tcp"})
	n.Run()
	run := n.Result()

	if len(run.Hosts) != 1 {
		t.Fatalf("number of hosts not 1, was %d", len(run.Hosts))
	}
	host := run.Hosts[0]

	if host.Status.State != "up" {
		t.Fatalf("host state not 'up', was '%s'", host.Status.State)
	}
}

func TestPortScanRunInvalidTarget(t *testing.T) {
	// some invalid target
	n, err := NewPortScan("999.999.999.999", []string{"tcp"})
	err = n.Run()
	if err == nil {
		t.Error("no error with invalid target")
	}
}

func TestPortScanRunUdp(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("test requires root privileges")
	}
	n, _ := NewPortScan("localhost", []string{"udp"})
	n.Run()
	run := n.Result()
	fmt.Printf("args: %s", run.Args)

	if len(run.Hosts) != 1 {
		t.Fatalf("number of hosts not 1, was %d", len(run.Hosts))
	}
	host := run.Hosts[0]

	if host.Status.State != "up" {
		t.Fatalf("host state not 'up', was '%s'", host.Status.State)
	}
}
