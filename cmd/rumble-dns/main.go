// Copyright 2018-2019 Critical Research Corporation
//
//
// Derived from reflect.go via github.com/miekg/exdns
//

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"runtime/pprof"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/hdm/rumble-tools/pkg/rnd"

	log "github.com/sirupsen/logrus"

	"github.com/miekg/dns"
)

// encodedClientSubnet is used to decode CNAME-encoded subnet data
type encodedClientSubnet struct {
	Family  uint16
	Code    uint16
	Netmask uint8
	Scope   uint8
	Address [16]byte
}

var (
	cpuprofile = flag.String("cpuprofile", "", "write cpu profile to file")
	compress   = flag.Bool("compress", false, "compress replies")
	tsig       = flag.String("tsig", "", "use MD5 hmac tsig: keyname:base64")
	cpu        = flag.Int("cpu", 0, "number of cores to use")
	port       = flag.Int("port", 53, "port number to listen on")
	subdomain  = flag.String("subdomain", "v1.nxdomain.us", "subdomain handled by rumble-dns")
)

var helperDomain string

func handleReflect(w dns.ResponseWriter, r *dns.Msg) {
	var (
		v4   bool
		rr   dns.RR
		port string
		a    net.IP
	)

	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = *compress
	if ip, ok := w.RemoteAddr().(*net.UDPAddr); ok {
		port = strconv.Itoa(ip.Port) + "/udp"
		a = ip.IP
		v4 = a.To4() != nil
	}
	if ip, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		port = strconv.Itoa(ip.Port) + "/tcp"
		a = ip.IP
		v4 = a.To4() != nil
	}

	if len(r.Question) == 0 {
		log.Printf("%s:%s requested no questions", a, port)
		return
	}

	log.Printf("%s:%s requested %s (type:%d/class:%d) with XID %d", a, port, r.Question[0].Name, r.Question[0].Qtype, r.Question[0].Qclass, r.Id)

	prefix := strings.ToLower(r.Question[0].Name[0:2])
	switch prefix {
	// T0: Return the source address of the resolver in the response
	//     Handles A, AAAA, and TXT query types.
	case "t0":
		decodeAndLogTracer(a.String(), port, r)

		if v4 {
			rr = &dns.A{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   a.To4(),
			}
		} else {
			rr = &dns.AAAA{
				Hdr:  dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
				AAAA: a,
			}
		}

		t := &dns.TXT{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassCHAOS, Ttl: 60},
			Txt: []string{fmt.Sprintf("%s:%s", a.String(), port)},
		}

		switch r.Question[0].Qtype {
		case dns.TypeTXT:
			m.Answer = append(m.Answer, t)
			m.Extra = append(m.Extra, rr)
		default:
			fallthrough
		case dns.TypeAAAA, dns.TypeA:
			m.Answer = append(m.Answer, rr)
			m.Extra = append(m.Extra, t)
		}

	// E0: Return an encoded EDNS0 Client Subnet field as a CNAME
	case "e0":
		dk, ok := decodeAndLogTracer(a.String(), port, r)
		o := r.IsEdns0()
		if ok && o != nil {
			for _, s := range o.Option {
				switch s.(type) {
				case *dns.EDNS0_SUBNET:
					subnet := s.(*dns.EDNS0_SUBNET)

					// Get the decode key as a set of bytes
					dkb := make([]byte, 4)
					binary.BigEndian.PutUint32(dkb, dk)

					// Use a helper struct to encode the fields
					csInfo := encodedClientSubnet{
						Family:  subnet.Family,
						Netmask: subnet.SourceNetmask,
						Scope:   subnet.SourceScope,
						Code:    subnet.Code,
					}

					// Store the address if the length is right
					if len([]byte(subnet.Address)) == 16 {
						copy(csInfo.Address[:], subnet.Address)
					}

					buf := new(bytes.Buffer)
					binary.Write(buf, binary.BigEndian, csInfo)

					rr = &dns.CNAME{
						Hdr:    dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
						Target: fmt.Sprintf("c0%.8x%s.%s", dk, hex.EncodeToString(rnd.XorBytesWithBytes(buf.Bytes(), dkb)), helperDomain),
					}
					m.Answer = append(m.Answer, rr)
				}
			}
		}
		if len(m.Answer) == 0 {
			m.Rcode = 3
		}

	// A0: Return an A or AAAA pointing to the encoded address
	case "a0":
		rr, err := decodeAndLogAddress(a.String(), port, strings.ToLower(r.Question[0].Name), r)
		if err != nil {
			log.Printf("%s:%s returned error for %s: %s", a, port, r.Question[0].Name, err)
			return
		}

		m.Answer = append(m.Answer, rr)

	default:
		// S0 and <something>.S0 : Return a NS record for the encoded addresses
		if idx := strings.Index(strings.ToLower(r.Question[0].Name), "s0"); idx != -1 {

			// Create an A0 query pointing to the target address
			nsName := "a" + strings.ToLower(string(r.Question[0].Name[idx+1:]))
			m.Authoritative = true
			rr = &dns.NS{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60},
				Ns:  nsName,
			}
			m.Ns = append(m.Ns, rr)

			// Append the matching A or AAAA record
			rr, err := decodeAndLogAddress(a.String(), port, nsName, r)
			if err != nil {
				log.Printf("%s:%s returned error for %s: %s", a, port, nsName, err)
				return
			}
			m.Extra = append(m.Extra, rr)

		}
	}

	if r.IsTsig() != nil {
		if w.TsigStatus() == nil {
			m.SetTsig(r.Extra[len(r.Extra)-1].(*dns.TSIG).Hdr.Name, dns.HmacMD5, 300, time.Now().UTC().Unix())
		} else {
			log.Printf("%s:%s triggered tsig error for %s: %s", a, port, r.Question[0].Name, w.TsigStatus().Error())
		}
	}

	err := w.WriteMsg(m)
	if err != nil {
		log.Printf("%s:%s triggered error for %s: %s", a, port, r.Question[0].Name, err)
	}
}

func decodeAndLogTracer(ip string, port string, r *dns.Msg) (uint32, bool) {
	var tracerDecodeKey uint32
	encodedName := strings.SplitN(r.Question[0].Name[2:], ".", 2)
	encodedBytes, err := hex.DecodeString(encodedName[0])
	if err != nil {
		log.Printf("%s:%s requested invalid tracer name %s wth XID %d (%s)", ip, port, r.Question[0].Name, r.Id, err)
		return tracerDecodeKey, false
	}

	// [XXXX] [AAAABBBBCCCCDDDD] [YYYYZZZZ]
	if len(encodedBytes) != 28 {
		log.Printf("%s:%s requested invalid tracer name length %s wth XID %d", ip, port, r.Question[0].Name, r.Id)
		return tracerDecodeKey, false
	}

	tracerDecodeKey = binary.BigEndian.Uint32(encodedBytes[0:4])
	decodedBytes := rnd.XorBytesWithBytes(encodedBytes[4:], encodedBytes[0:4])
	tracerIP := net.IP(decodedBytes[0:16])
	tracerTS := binary.BigEndian.Uint64(decodedBytes[16:24])

	log.Printf("%s:%s requested trace %s (type:%d/class:%d) with XID %d (ip:%s ts:%s)",
		ip, port, r.Question[0].Name, r.Question[0].Qtype, r.Question[0].Qclass, r.Id,
		tracerIP.String(), time.Unix(0, int64(tracerTS)).UTC().String(),
	)
	return tracerDecodeKey, true
}

func decodeAndLogAddress(ip string, port string, qname string, r *dns.Msg) (dns.RR, error) {
	encodedName := strings.SplitN(qname, ".", 2)

	if len(encodedName) != 2 {
		return &dns.A{}, fmt.Errorf("invalid subdomain name (dots=%d)", len(encodedName))
	}

	if len(encodedName[0]) != 58 {
		return &dns.A{}, fmt.Errorf("invalid subdomain length (%d)", len(encodedName[0]))
	}

	encodedBytes, err := hex.DecodeString(encodedName[0][2:])
	if err != nil {
		return &dns.A{}, fmt.Errorf("invalid subdomain name (%s)", err)
	}

	// [XXXX] [AAAABBBBCCCCDDDD] [YYYYZZZZ]
	if len(encodedBytes) != 28 {
		return &dns.A{}, fmt.Errorf("invalid subdomain name length (%d): #%v", len(encodedBytes), encodedBytes)
	}

	decodedBytes := rnd.XorBytesWithBytes(encodedBytes[4:], encodedBytes[0:4])
	tracerIP := net.IP(decodedBytes[0:16])
	tracerTS := binary.BigEndian.Uint64(decodedBytes[16:24])

	log.Printf("%s:%s requested referral %s (type:%d/class:%d) with XID %d (ip:%s ts:%s)",
		ip, port, qname, r.Question[0].Qtype, r.Question[0].Qclass, r.Id,
		tracerIP.String(), time.Unix(0, int64(tracerTS)).UTC().String(),
	)

	// Handle IPv4 referrals
	if tracerIP.To4() != nil {
		return &dns.A{
			Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   tracerIP,
		}, nil
	}

	// Handle IPv6 referrals
	return &dns.AAAA{
		Hdr:  dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
		AAAA: tracerIP,
	}, nil
}

func serveDNS(net, name, secret string, soreuseport bool) {
	switch name {
	case "":
		server := &dns.Server{Addr: fmt.Sprintf("[::]:%d", *port), Net: net, TsigSecret: nil}
		if err := server.ListenAndServe(); err != nil {
			log.Printf("failed to setup the "+net+" server: %s", err.Error())
			os.Exit(1)
		}
	default:
		server := &dns.Server{Addr: fmt.Sprintf(":%d", *port), Net: net, TsigSecret: map[string]string{name: secret}}
		if err := server.ListenAndServe(); err != nil {
			log.Printf("failed to setup the "+net+" server: %s", err.Error())
			os.Exit(1)
		}
	}
}

func main() {
	var name, secret string
	flag.Usage = func() {
		flag.PrintDefaults()
	}
	flag.Parse()

	log.SetFormatter(&log.TextFormatter{
		DisableColors: true,
		FullTimestamp: true,
	})
	log.SetOutput(os.Stdout)

	if *tsig != "" {
		a := strings.SplitN(*tsig, ":", 2)
		name, secret = dns.Fqdn(a[0]), a[1] // fqdn the name, which everybody forgets...
	}
	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	if *cpu != 0 {
		runtime.GOMAXPROCS(*cpu)
	} else {
		runtime.GOMAXPROCS(runtime.NumCPU())
	}

	helperDomain = rnd.EnsureTrailingDot(*subdomain)

	log.Printf("rumble-dns-server starting on port %d", *port)

	dns.HandleFunc(helperDomain, handleReflect)
	go serveDNS("tcp", name, secret, false)
	go serveDNS("udp", name, secret, false)

	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	log.Printf("signal (%s) received, stopping", s)
}
