package main

import (
	"encoding/binary"
	"flag"
	"log"
	"math/rand"
	"net"
	"time"

	"google.golang.org/protobuf/proto"

	dnstap "github.com/dnstap/golang-dnstap"
	framestream "github.com/farsightsec/golang-framestream"
	"github.com/miekg/dns"
)

var (
	target = flag.String("target", "localhost:5555", "dnstap target address")
	rate   = flag.Int("rate", 500, "queries per second")
	dur    = flag.Duration("duration", 5*time.Minute, "how long to generate traffic")
)

var domains = []string{
	"google.com.", "facebook.com.", "amazon.com.", "cloudflare.com.",
	"github.com.", "stackoverflow.com.", "reddit.com.", "wikipedia.org.",
	"twitter.com.", "linkedin.com.", "netflix.com.", "apple.com.",
	"microsoft.com.", "youtube.com.", "instagram.com.", "whatsapp.com.",
	"zoom.us.", "slack.com.", "dropbox.com.", "spotify.com.",
	"mail.google.com.", "drive.google.com.", "docs.google.com.",
	"api.github.com.", "cdn.jsdelivr.net.", "unpkg.com.",
	"registry.npmjs.org.", "pypi.org.", "rubygems.org.",
	"evil-malware-c2.xyz.", "xn--suspicious-domain.net.",
	"totallylegit.tk.", "fr33-v1rus.cc.", "notaphish.ru.",
}

var subdomains = []string{
	"www", "api", "cdn", "mail", "app", "dev", "staging", "prod",
	"ns1", "ns2", "mx", "smtp", "imap", "vpn", "admin", "dashboard",
}

var qtypes = []uint16{
	dns.TypeA, dns.TypeAAAA, dns.TypeCNAME, dns.TypeMX,
	dns.TypeTXT, dns.TypeNS, dns.TypeSOA, dns.TypeSRV,
	dns.TypeHTTPS, dns.TypePTR,
}

var rcodes = []int{
	dns.RcodeSuccess, dns.RcodeSuccess, dns.RcodeSuccess, dns.RcodeSuccess,
	dns.RcodeSuccess, dns.RcodeNameError, dns.RcodeServerFailure, dns.RcodeRefused,
}

func randomIP() net.IP {
	return net.IPv4(byte(10+rand.Intn(10)), byte(rand.Intn(256)), byte(rand.Intn(256)), byte(1+rand.Intn(254)))
}

func randomDomain() string {
	d := domains[rand.Intn(len(domains))]
	if rand.Float32() < 0.4 {
		d = subdomains[rand.Intn(len(subdomains))] + "." + d
	}
	return d
}

func buildDNSQuery(qname string, qtype uint16) []byte {
	msg := new(dns.Msg)
	msg.SetQuestion(qname, qtype)
	msg.Id = uint16(rand.Intn(65536))
	wire, _ := msg.Pack()
	return wire
}

func buildDNSResponse(qname string, qtype uint16, rcode int) []byte {
	msg := new(dns.Msg)
	msg.SetQuestion(qname, qtype)
	msg.Response = true
	msg.Rcode = rcode
	msg.Id = uint16(rand.Intn(65536))
	if rcode == dns.RcodeSuccess {
		switch qtype {
		case dns.TypeA:
			msg.Answer = append(msg.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   randomIP(),
			})
		case dns.TypeAAAA:
			msg.Answer = append(msg.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: qname, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
				AAAA: net.ParseIP("2001:db8::1"),
			})
		case dns.TypeMX:
			msg.Answer = append(msg.Answer, &dns.MX{
				Hdr:        dns.RR_Header{Name: qname, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 300},
				Preference: 10,
				Mx:         "mail." + qname,
			})
		}
	}
	wire, _ := msg.Pack()
	return wire
}

func makeDnstapMessage(queryWire, responseWire []byte, srcIP, dstIP net.IP, qtype uint16) []byte {
	nowSec := uint64(time.Now().Unix())
	nowNsec := uint32(time.Now().Nanosecond())
	msgType := dnstap.Message_CLIENT_RESPONSE
	socketFam := dnstap.SocketFamily_INET
	socketProto := dnstap.SocketProtocol_UDP
	srcPort := uint32(1024 + rand.Intn(64000))
	dstPort := uint32(53)

	msg := &dnstap.Dnstap{
		Type: dnstap.Dnstap_MESSAGE.Enum(),
		Message: &dnstap.Message{
			Type:              &msgType,
			SocketFamily:      &socketFam,
			SocketProtocol:    &socketProto,
			QueryAddress:      srcIP.To4(),
			ResponseAddress:   dstIP.To4(),
			QueryPort:         &srcPort,
			ResponsePort:      &dstPort,
			QueryMessage:      queryWire,
			ResponseMessage:   responseWire,
			QueryTimeSec:      &nowSec,
			QueryTimeNsec:     &nowNsec,
			ResponseTimeSec:   &nowSec,
			ResponseTimeNsec:  &nowNsec,
		},
	}

	out, _ := proto.Marshal(msg)
	return out
}

func main() {
	flag.Parse()
	log.Printf("Connecting to %s, rate=%d qps, duration=%s", *target, *rate, *dur)

	conn, err := net.DialTimeout("tcp", *target, 5*time.Second)
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer conn.Close()

	enc, err := framestream.NewEncoder(conn, &framestream.EncoderOptions{
		ContentType:   []byte("protobuf:dnstap.Dnstap"),
		Bidirectional: true,
	})
	if err != nil {
		log.Fatalf("framestream encoder: %v", err)
	}
	defer enc.Close()

	ticker := time.NewTicker(time.Second / time.Duration(*rate))
	defer ticker.Stop()
	deadline := time.After(*dur)

	var count uint64
	dstIP := net.IPv4(10, 0, 0, 53)

	log.Println("Sending dnstap frames...")
	for {
		select {
		case <-deadline:
			log.Printf("Done. Sent %d dnstap messages in %s", count, *dur)
			return
		case <-ticker.C:
			qname := randomDomain()
			qtype := qtypes[rand.Intn(len(qtypes))]
			rcode := rcodes[rand.Intn(len(rcodes))]
			srcIP := randomIP()

			queryWire := buildDNSQuery(qname, qtype)
			responseWire := buildDNSResponse(qname, qtype, rcode)
			frame := makeDnstapMessage(queryWire, responseWire, srcIP, dstIP, qtype)

			if _, err := enc.Write(frame); err != nil {
				log.Fatalf("write frame: %v", err)
			}
			count++
			if count%1000 == 0 {
				log.Printf("Sent %d messages", count)
			}
		}
	}
}

// writeControlFrame writes a Frame Streams control frame
func writeControlFrame(conn net.Conn, frameType uint32, contentType []byte) error {
	// Escape sequence
	if err := binary.Write(conn, binary.BigEndian, uint32(0)); err != nil {
		return err
	}
	bodyLen := 4 // control type
	if contentType != nil {
		bodyLen += 4 + 4 + len(contentType) // field type + field len + field data
	}
	if err := binary.Write(conn, binary.BigEndian, uint32(bodyLen)); err != nil {
		return err
	}
	if err := binary.Write(conn, binary.BigEndian, frameType); err != nil {
		return err
	}
	if contentType != nil {
		if err := binary.Write(conn, binary.BigEndian, uint32(1)); err != nil { // CONTENT_TYPE field
			return err
		}
		if err := binary.Write(conn, binary.BigEndian, uint32(len(contentType))); err != nil {
			return err
		}
		if _, err := conn.Write(contentType); err != nil {
			return err
		}
	}
	return nil
}
