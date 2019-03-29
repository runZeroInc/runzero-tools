/*

Copyright (C) 2018-2019 Critical Research Corporation

DNS Remote Sensing
==================

Use the v1.nxdomain.us rumble DNS server to identify hosts reachable by an open resolver.

Usage:

$ go run main.go <target-resolver> 127.0.0.1 255.255.255.255 192.168.0.1 192.168.0.9 192.168.0.254 8.8.8.8 8.8.8.7
2018/08/30 13:32:54        127.0.0.1           120ms    << Valid DNS (localhost of resolver)
2018/08/30 13:32:54  255.255.255.255            59ms    << Invalid address rejected by bind (broadcast)
2018/08/30 13:32:54      192.168.0.1            81ms    << Valid DNS server
2018/08/30 13:32:54      192.168.0.9            59ms    << Live local host, but no DNS service
2018/08/30 13:32:56    192.168.0.254          2013ms    << Timeout, no response
2018/08/30 13:32:56          8.8.8.8            81ms    << Valid DNS server
2018/08/30 13:32:58          8.8.8.7          2005ms    << Timeout, no response

*/

package main

import (
	"encoding/hex"
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

var helperDomain = "v1.nxdomain.us."

func main() {

	if len(os.Args) < 3 {
		fmt.Printf("%s <resolver> <cidrs>\n", os.Args[0])
		os.Exit(1)
	}

	rnd.SeedMathRand()
	rnd.RandomizeObfuscationKeys()

	dst := os.Args[1]
	resolver := net.JoinHostPort(dst, "53")

	cidrs := os.Args[2:]

	wg := new(sync.WaitGroup)
	ipc := make(chan string)
	stp := make(chan int)

	for i := 0; i < runtime.NumCPU(); i++ {
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
		if err != nil {
			fmt.Printf("%16s\t%10dms\tTIMEOUT\n", addr, time.Now().UTC().Sub(start)/time.Millisecond)
		} else {
			fmt.Printf("%16s\t%10dms\t%3d\n", addr, time.Now().UTC().Sub(start)/time.Millisecond, in.MsgHdr.Rcode)
		}
	}
	wg.Done()
}
