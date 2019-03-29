package rnd

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/big"
	"math/rand"
	"net"
	"regexp"
	"strings"
)

// IPv42UInt converts IPv4 addresses to unsigned integers
func IPv42UInt(ips string) (uint32, error) {
	ip := net.ParseIP(ips)
	if ip == nil {
		return 0, errors.New("invalid IPv4 address")
	}
	ip = ip.To4()
	return binary.BigEndian.Uint32(ip), nil
}

// IPv42UIntLE converts IPv4 addresses to unsigned integers (little endian)
func IPv42UIntLE(ips string) (uint32, error) {
	ip := net.ParseIP(ips)
	if ip == nil {
		return 0, errors.New("invalid IPv4 address")
	}
	ip = ip.To4()
	return binary.LittleEndian.Uint32(ip), nil
}

// UInt2IPv4 converts unsigned integers to IPv4 addresses
func UInt2IPv4(ipi uint32) string {
	ipb := make([]byte, 4)
	binary.BigEndian.PutUint32(ipb, ipi)
	ip := net.IP(ipb)
	return ip.String()
}

// IPv42Bytes converts an IPv4 address to a byte array
func IPv42Bytes(ips string) ([]byte, error) {
	ipBytes := make([]byte, 4)
	ip := net.ParseIP(ips)
	if ip == nil {
		return ipBytes, errors.New("invalid IPv4 address")
	}
	ip = ip.To4()
	ipInt := binary.BigEndian.Uint32(ip)
	binary.BigEndian.PutUint32(ipBytes, ipInt)
	return ipBytes, nil
}

// Bytes2IPv4 converts a byte array to an IPv4 addresse
func Bytes2IPv4(ipb []byte) string {
	ip := net.IP(ipb)
	return ip.String()
}

// ObfuscationKey32 provides an XOR key for encoding
var ObfuscationKey32 uint32 = 0x50505050

// ObfuscationKey32Bytes are the 32-bit XOR key as a byte array
var ObfuscationKey32Bytes = [4]byte{}

// ObfuscationKey64 provides an XOR key for encoding
var ObfuscationKey64 uint64 = 0x5050505050505050

// ObfuscationKey64Bytes are the 64-bit XOR key as a byte array
var ObfuscationKey64Bytes = [8]byte{}

// ObfuscateIPv4FromBytesToBytes XORs an IPv4 byte array with the obfuscation key
func ObfuscateIPv4FromBytesToBytes(ipb []byte) []byte {
	return ObfuscateBytes4(ipb)
}

// ObfuscateBytes4 XORs a 4-byte array with the obfuscation key
func ObfuscateBytes4(b []byte) []byte {
	resp := make([]byte, 4)
	ival := binary.BigEndian.Uint32(b)
	binary.BigEndian.PutUint32(resp, ival^ObfuscationKey32)
	return resp
}

// ObfuscateBytes8 XORs a 8-byte array with the obfuscation key
func ObfuscateBytes8(b []byte) []byte {
	resp := make([]byte, 8)
	ival := binary.BigEndian.Uint64(b)
	binary.BigEndian.PutUint64(resp, ival^ObfuscationKey64)
	return resp
}

// ObfuscateIPv4FromStringToBytes XORs an IPv4 string with the obfuscation key, returning bytes
func ObfuscateIPv4FromStringToBytes(ip string) []byte {
	ipb, _ := IPv42Bytes(ip)
	return ObfuscateIPv4FromBytesToBytes(ipb)
}

// ObfuscateIPv4FromStringToString XORs an IPv4 string with the obfuscation key, returning a string
func ObfuscateIPv4FromStringToString(ip string) string {
	ipb, _ := IPv42Bytes(ip)
	return Bytes2IPv4(ObfuscateIPv4FromBytesToBytes(ipb))
}

// ObfuscateIPv4FromBytesToString XORs an IPv4 string with the obfuscation key, returning a string
func ObfuscateIPv4FromBytesToString(ipb []byte) string {
	return Bytes2IPv4(ObfuscateIPv4FromBytesToBytes(ipb))
}

// RandomizeObfuscationKeys resets the default obfuscation keys
func RandomizeObfuscationKeys() {
	ObfuscationKey32 = rand.Uint32()
	binary.BigEndian.PutUint32(ObfuscationKey32Bytes[:], ObfuscationKey32)
	ObfuscationKey64 = rand.Uint64()
	binary.BigEndian.PutUint64(ObfuscationKey64Bytes[:], ObfuscationKey64)
}

// MatchIPv6 is a regular expression for validating IPv6 addresses
var MatchIPv6 = regexp.MustCompile(`^((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?$`)

// MatchIPv4 is a regular expression for validating IPv4 addresses
var MatchIPv4 = regexp.MustCompile(`^(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))$`)

// MatchHostname is a regular expression for validating hostnames
var MatchHostname = regexp.MustCompile(`^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$`)

// ValidIP returns a true/false on whether the input is a valid IPv4 or IPv6 address
func ValidIP(addr string) bool {
	return (MatchIPv4.MatchString(addr) || MatchIPv6.MatchString(addr))
}

// ValidIP4 returns a true/false on whether the input is a valid IPv4 address
func ValidIP4(addr string) bool {
	return MatchIPv4.MatchString(addr)
}

// ValidIP6 returns a true/false on whether the input is a valid IPv6 address
func ValidIP6(addr string) bool {
	return MatchIPv6.MatchString(addr)
}

// EgressDestinationIPv4 defines an internet-reachable IPv4 address (currently cloudflare)
var EgressDestinationIPv4 = "1.1.1.1"

// EgressDestinationIPv6 defines an internet-reachable IPv6 address (currently cloudflare)
var EgressDestinationIPv6 = "[2606:4700:4700::1111]"

// GetEgressAddress return the IPv4 or IPv6 address used to route to the specified destination
func GetEgressAddress(dst string) string {
	conn, err := net.Dial("udp", dst+":53")
	if err != nil {
		return "127.0.0.1"
	}

	host, _, err := net.SplitHostPort(conn.LocalAddr().String())
	conn.Close()
	if err != nil {
		return "127.0.0.1"
	}

	bits := strings.Split(host, "%")

	return bits[0]
}

// AddressesFromCIDR parses a CIDR and writes individual IPs to a channel
func AddressesFromCIDR(cidr string, out chan string, quit chan int) error {
	if len(cidr) == 0 {
		return fmt.Errorf("invalid CIDR: empty")
	}

	// We may receive bare IP addresses, add a mask if needed
	if !strings.Contains(cidr, "/") {
		if strings.Contains(cidr, ":") {
			cidr = cidr + "/128"
		} else {
			cidr = cidr + "/32"
		}
	}

	// Parse CIDR into base address + mask
	_, net, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR: %s %s", cidr, err.Error())
	}

	// Verify IPv4 for now
	ip4 := net.IP.To4()
	if ip4 == nil {
		return fmt.Errorf("invalid IPv4 CIDR: %s", cidr)
	}

	netBase, err := IPv42UInt(net.IP.String())
	if err != nil {
		return fmt.Errorf("invalid IPv4: %s %s", cidr, err)
	}

	maskOnes, maskTotal := net.Mask.Size()

	// Does not work for IPv6 due to cast to uint32
	netSize := uint32(math.Pow(2, float64(maskTotal-maskOnes)))
	curBase := netBase
	endBase := netBase + netSize

	// Iterate the range semi-randomly
	randomWalkIPv4Range(curBase, endBase, out, quit)

	return nil
}

// AddressCountFromCIDR parses a CIDR and returns the numnber of included IP addresses
func AddressCountFromCIDR(cidr string) (uint64, error) {
	var count uint64
	if len(cidr) == 0 {
		return count, fmt.Errorf("invalid CIDR: empty")
	}

	// We may receive bare IP addresses, not CIDRs sometimes
	if !strings.Contains(cidr, "/") {
		if strings.Contains(cidr, ":") {
			cidr = cidr + "/128"
		} else {
			cidr = cidr + "/32"
		}
	}

	// Parse CIDR into base address + mask
	_, net, err := net.ParseCIDR(cidr)
	if err != nil {
		return count, fmt.Errorf("invalid CIDR: %s %s", cidr, err.Error())
	}

	// Verify IPv4 for now
	ip4 := net.IP.To4()
	if ip4 == nil {
		return count, fmt.Errorf("invalid IPv4 CIDR: %s", cidr)
	}

	maskOnes, maskTotal := net.Mask.Size()

	// Does not work for IPv6 due to cast to uint32
	netSize := uint64(math.Pow(2, float64(maskTotal-maskOnes)))

	return netSize, nil
}

// findPrimeOverMin returns a prime int64 of at least min
func findPrimeOverMin(min int64) int64 {
	var randomSeed int64
	for i := 0; ; i++ {
		randomSeed = rand.Int63()
		// ProbablyPrime is 100% accurate for inputs less than 2⁶⁴
		if big.NewInt(randomSeed).ProbablyPrime(1) {
			if randomSeed > min {
				return randomSeed
			}
		}
	}
}

// randomWalkIPv4Range iterates over an IPv4 range using a prime, writing IPs to the output channel
func randomWalkIPv4Range(min uint32, max uint32, out chan string, quit chan int) {
	s := int64(max - min)
	p := findPrimeOverMin(int64(s))
	if s == 0 {
		return
	}

	q := p % s
	for v := int64(0); v < s; v++ {
		ip := UInt2IPv4(min + uint32(q))
		select {
		case <-quit:
			return
		case out <- ip:
			q = (q + p) % s
		}
	}
}
