/*

Copyright (C) 2018-2019 Critical Research Corporation

DNS Remote Ping
===============

Use a rumble DNS server to identify hosts reachable by an open resolver.

Usage:

$ rumble-dnsrp -quiet 192.168.0.3 192.168.30.0/24
192.168.30.29              alive via 192.168.0.3:53                60ms       code:2
192.168.30.34              alive via 192.168.0.3:53                69ms       code:2
192.168.30.143             alive via 192.168.0.3:53               267ms       code:2

*/

package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/hdm/rumble-tools/pkg/rnd"

	"github.com/miekg/dns"
)

var (
	port      = flag.Int("port", 53, "port number to send queries to")
	threads   = flag.Int("threads", runtime.NumCPU(), "number of parallel threads")
	subdomain = flag.String("subdomain", "v1.nxdomain.us", "subdomain handled by rumble-dns")
	quiet     = flag.Bool("quiet", false, "quiet mode, only show positive results")
	help      = flag.Bool("help", false, "show usage information")
	h         = flag.Bool("h", false, "show usage information")
)

func main() {

	flag.Parse()

	if len(flag.Args()) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <resolver> <cidrs>\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}

	if *help || *h {
		flag.Usage()
		os.Exit(1)
	}

	rnd.SeedMathRand()
	rnd.RandomizeObfuscationKeys()

	dst := flag.Args()[0]
	resolver := net.JoinHostPort(dst, fmt.Sprintf("%d", *port))

	cidrs := flag.Args()[1:]

	wg := new(sync.WaitGroup)
	ipc := make(chan string)
	stp := make(chan int)

	helperDomain := rnd.EnsureTrailingDot(*subdomain)
	for i := 0; i < *threads; i++ {
		go remoteSense(wg, ipc, resolver, helperDomain)
		wg.Add(1)
	}

	for _, cidr := range cidrs {
		err := rnd.AddressesFromCIDR(cidr, ipc, stp)
		if err != nil {
			fmt.Printf("input: %s\n", err)
			continue
		}
	}
	close(ipc)
	wg.Wait()
}

func remoteSense(wg *sync.WaitGroup, ipc chan string, resolver string, helperDomain string) {
	for addr := range ipc {
		c := new(dns.Client)
		m := &dns.Msg{
			Question: make([]dns.Question, 1),
		}
		m.RecursionDesired = true

		ip := net.ParseIP(addr)
		if ip == nil {
			fmt.Printf("invalid address: %s\n", addr)
			continue
		}

		tracerBytes := make([]byte, 28)
		copy(tracerBytes[0:4], rnd.ObfuscationKey32Bytes[:])
		copy(tracerBytes[4:20], rnd.XorBytesWithBytes(ip, rnd.ObfuscationKey32Bytes[:]))
		copy(tracerBytes[20:28], rnd.XorBytesWithBytes(rnd.TimestampToBytes(time.Now().UTC()), rnd.ObfuscationKey32Bytes[:]))

		tracerName := fmt.Sprintf("%.8x.s0%s.%s", rand.Uint32(), hex.EncodeToString(tracerBytes), helperDomain)

		m.Question[0] = dns.Question{Name: tracerName, Qtype: dns.TypeA, Qclass: dns.ClassINET}
		start := time.Now().UTC()
		in, _, err := c.Exchange(m, resolver)

		valid := false
		rstr := ""
		if err != nil {
			rstr = "error:" + err.Error()
		} else {
			if in.MsgHdr.Rcode == 2 {
				valid = true
			}

			rstr = fmt.Sprintf("code:%d", in.MsgHdr.Rcode)
		}

		diff := time.Now().UTC().Sub(start) / time.Millisecond

		if !valid {
			if !*quiet {
				fmt.Printf("%-20s unreachable via %-25s %6dms      %s\n", addr, resolver, diff, rstr)
			}
		} else {
			fmt.Printf("%-20s       alive via %-25s %6dms       %s\n", addr, resolver, diff, rstr)
		}
	}
	wg.Done()
}
