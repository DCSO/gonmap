// gonmap - Wrapper around Nmap
// Copyright (c) 2017, 2018, DCSO GmbH

// Package gonmap is a wrapper around the Nmap tool. It uses the XML output
// capability of Nmap to retrieve results and make them available in Go.
package gonmap

import "encoding/xml"

const (
	nmapBin = "nmap"
)

type Nmap interface {
	Result() NmapRun
	Run() error
	Target() string
}

type NmapRunState struct {
	XMLName   xml.Name `xml:"state"`
	State     string   `xml:"state,attr"`
	Reason    string   `xml:"reason,attr"`
	ReasonTTL int      `xml:"reason_ttl,attr"`
}

type NmapRunStatus struct {
	XMLName   xml.Name `xml:"status"`
	State     string   `xml:"state,attr"`
	Reason    string   `xml:"reason,attr"`
	ReasonTTL int      `xml:"reason_ttl,attr"`
}

type NmapRunPortService struct {
	XMLName xml.Name `xml:"service"`
	Name    string   `xml:"name,attr"`
	Method  string   `xml:"method,attr"`
	Conf    int      `xml:"conf,attr"`
}

type NmapRunPort struct {
	XMLName  xml.Name           `xml:"port"`
	Protocol string             `xml:"protocol,attr"`
	Port     int                `xml:"portid,attr"`
	Status   NmapRunState       `xml:"state"`
	Service  NmapRunPortService `xml:"service"`
}

type NmapRunHostAddress struct {
	XMLName xml.Name `xml:"address"`
	Address string   `xml:"addr,attr"`
	Type    string   `xml:"addrtype,attr"`
}

type NmapRunHost struct {
	XMLName xml.Name           `xml:"host"`
	Ports   []NmapRunPort      `xml:"ports>port"`
	Address NmapRunHostAddress `xml:"address"`
	Status  NmapRunStatus      `xml:"status"`
}

type NmapRunStatsFinished struct {
	XMLName xml.Name `xml:"finished"`
	Time    int64    `xml:"time,attr"`
	Elapsed float32  `xml:"elapsed,attr"`
}

type NmapRunStats struct {
	XMLName  xml.Name             `xml:"runstats"`
	Finished NmapRunStatsFinished `xml:"finished"`
}

type NmapRun struct {
	XMLName xml.Name      `xml:"nmaprun"`
	Version string        `xml:"version"`
	Args    string        `xml:"args,attr"`
	Start   int64         `xml:"start,attr"`
	Hosts   []NmapRunHost `xml:"host"`
	Stats   NmapRunStats  `xml:"runstats"`
}
