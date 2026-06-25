// Copyright observIQ, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package parser provides functions to parse and enrich network packets.
package parser

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net/http"
	"regexp"
	"strings"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// ProtocolAttributes holds application-layer fields decoded from a single packet.
// Only the *Found field indicates whether the enclosing block was populated.
type ProtocolAttributes struct {
	// DNS
	DNSQuestionName string
	DNSResponseCode string
	DNSIsResponse   bool
	DNSFound        bool

	// HTTP
	HTTPMethod        string
	HTTPURLFull       string
	HTTPServerAddress string
	HTTPStatusCode    int
	HTTPUserAgent     string
	HTTPFound         bool

	// TLS
	TLSServerName string
	TLSVersion    string
	TLSFound      bool

	// SSH
	SSHProtocolVersion string
	SSHSoftwareVersion string
	SSHFound           bool

	// ICMP
	ICMPType  string
	ICMPCode  int
	ICMPFound bool
}

var sshBannerRE = regexp.MustCompile(`SSH-(\d+\.\d+)-(\S+)`)

// EnrichProtocol decodes application-layer protocol information from a packet
// stored as hex in info.HexData and returns the populated ProtocolAttributes.
// Returns nil when HexData is empty or no supported protocol was recognised.
func EnrichProtocol(info *PacketInfo) *ProtocolAttributes {
	if info.HexData == "" {
		return nil
	}

	raw, err := hex.DecodeString(info.HexData)
	if err != nil || len(raw) == 0 {
		return nil
	}

	packet := decodePacket(raw)
	if packet == nil {
		return nil
	}

	attrs := &ProtocolAttributes{}

	// ICMP — handled before port-based checks because ports are not applicable
	if info.Transport == TransportICMP {
		enrichICMP(attrs, packet)
		if attrs.ICMPFound {
			return attrs
		}
	}

	// Port-based dispatch
	switch info.Transport {
	case TransportUDP:
		if info.SrcPort == 53 || info.DstPort == 53 {
			enrichDNSUDP(attrs, packet)
		}
	case TransportTCP:
		switch {
		case info.SrcPort == 53 || info.DstPort == 53:
			enrichDNSTCP(attrs, packet)
		case info.SrcPort == 22 || info.DstPort == 22:
			enrichSSH(attrs, packet)
		case info.SrcPort == 443 || info.DstPort == 443 || isTLSPayload(tcpPayload(packet)):
			enrichTLS(attrs, packet)
		case isHTTPPort(info.SrcPort, info.DstPort) || isHTTPPayload(tcpPayload(packet)):
			enrichHTTP(attrs, packet)
		}
	}

	if !attrs.DNSFound && !attrs.HTTPFound && !attrs.TLSFound && !attrs.SSHFound && !attrs.ICMPFound {
		return nil
	}
	return attrs
}

// decodePacket tries to decode raw bytes as Ethernet, then raw IPv4/IPv6, then
// BSD-loopback (4-byte null header before IP) — gracefully handling synthetic
// test fixtures and loopback captures.
func decodePacket(raw []byte) gopacket.Packet {
	if len(raw) == 0 {
		return nil
	}

	// Try Ethernet first (most common — real captures on physical/virtual NICs)
	p := gopacket.NewPacket(raw, layers.LayerTypeEthernet, gopacket.Default)
	if p.NetworkLayer() != nil {
		return p
	}

	// Raw IPv4 or IPv6 (synthetic test data, some tunnel interfaces)
	switch raw[0] >> 4 {
	case 4:
		p = gopacket.NewPacket(raw, layers.LayerTypeIPv4, gopacket.Default)
		if p.NetworkLayer() != nil {
			return p
		}
	case 6:
		p = gopacket.NewPacket(raw, layers.LayerTypeIPv6, gopacket.Default)
		if p.NetworkLayer() != nil {
			return p
		}
	}

	// BSD loopback (macOS lo0): 4-byte null header before IP frame
	if len(raw) > 4 {
		sub := raw[4:]
		switch sub[0] >> 4 {
		case 4:
			p = gopacket.NewPacket(sub, layers.LayerTypeIPv4, gopacket.Default)
			if p.NetworkLayer() != nil {
				return p
			}
		case 6:
			p = gopacket.NewPacket(sub, layers.LayerTypeIPv6, gopacket.Default)
			if p.NetworkLayer() != nil {
				return p
			}
		}
	}

	return nil
}

// tcpPayload returns the TCP application payload from a decoded packet, or nil.
func tcpPayload(p gopacket.Packet) []byte {
	if appLayer := p.ApplicationLayer(); appLayer != nil {
		return appLayer.Payload()
	}
	if tcpLayer := p.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		return tcpLayer.(*layers.TCP).Payload
	}
	return nil
}

// ---------- ICMP ----------

var icmpv4TypeNames = map[uint8]string{
	0:  "EchoReply",
	3:  "DestinationUnreachable",
	4:  "SourceQuench",
	5:  "Redirect",
	8:  "EchoRequest",
	9:  "RouterAdvertisement",
	10: "RouterSolicitation",
	11: "TimeExceeded",
	12: "ParameterProblem",
	13: "TimestampRequest",
	14: "TimestampReply",
	15: "InformationRequest",
	16: "InformationReply",
	17: "AddressMaskRequest",
	18: "AddressMaskReply",
}

var icmpv6TypeNames = map[uint8]string{
	1:   "DestinationUnreachable",
	2:   "PacketTooBig",
	3:   "TimeExceeded",
	4:   "ParameterProblem",
	128: "EchoRequest",
	129: "EchoReply",
	130: "MulticastListenerQuery",
	131: "MulticastListenerReport",
	132: "MulticastListenerDone",
	133: "RouterSolicitation",
	134: "RouterAdvertisement",
	135: "NeighborSolicitation",
	136: "NeighborAdvertisement",
	137: "Redirect",
}

func enrichICMP(attrs *ProtocolAttributes, p gopacket.Packet) {
	if icmp4 := p.Layer(layers.LayerTypeICMPv4); icmp4 != nil {
		icmp := icmp4.(*layers.ICMPv4)
		t := icmp.TypeCode.Type()
		name, ok := icmpv4TypeNames[t]
		if !ok {
			name = "Unknown"
		}
		attrs.ICMPType = name
		attrs.ICMPCode = int(icmp.TypeCode.Code())
		attrs.ICMPFound = true
		return
	}
	if icmp6 := p.Layer(layers.LayerTypeICMPv6); icmp6 != nil {
		icmp := icmp6.(*layers.ICMPv6)
		t := icmp.TypeCode.Type()
		name, ok := icmpv6TypeNames[t]
		if !ok {
			name = "Unknown"
		}
		attrs.ICMPType = name
		attrs.ICMPCode = int(icmp.TypeCode.Code())
		attrs.ICMPFound = true
	}
}

// ---------- DNS ----------

func enrichDNSUDP(attrs *ProtocolAttributes, p gopacket.Packet) {
	dnsLayer := p.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return
	}
	dns := dnsLayer.(*layers.DNS)
	// Require at least one successfully decoded question
	if len(dns.Questions) == 0 {
		return
	}
	attrs.DNSQuestionName = string(dns.Questions[0].Name)
	attrs.DNSResponseCode = dns.ResponseCode.String()
	attrs.DNSIsResponse = dns.QR
	attrs.DNSFound = true
}

func enrichDNSTCP(attrs *ProtocolAttributes, p gopacket.Packet) {
	payload := tcpPayload(p)
	// DNS over TCP prefixes each message with a 2-byte length field
	if len(payload) < 14 { // 2 (len) + 12 (min DNS header)
		return
	}
	dns := &layers.DNS{}
	if err := dns.DecodeFromBytes(payload[2:], gopacket.NilDecodeFeedback); err != nil {
		return
	}
	if len(dns.Questions) == 0 {
		return
	}
	attrs.DNSQuestionName = string(dns.Questions[0].Name)
	attrs.DNSResponseCode = dns.ResponseCode.String()
	attrs.DNSIsResponse = dns.QR
	attrs.DNSFound = true
}

// ---------- TLS ----------

func isTLSPayload(payload []byte) bool {
	return len(payload) >= 3 && payload[0] == 0x16 && payload[1] == 0x03
}

var tlsVersionNames = map[uint16]string{
	0x0301: "TLS 1.0",
	0x0302: "TLS 1.1",
	0x0303: "TLS 1.2",
	0x0304: "TLS 1.3",
}

func enrichTLS(attrs *ProtocolAttributes, p gopacket.Packet) {
	payload := tcpPayload(p)
	if !isTLSPayload(payload) {
		return
	}
	sni, version, ok := parseTLSClientHello(payload)
	if !ok {
		return
	}
	attrs.TLSServerName = sni
	attrs.TLSVersion = version
	attrs.TLSFound = true
}

// parseTLSClientHello manually parses TLS record + ClientHello to extract SNI
// and the advertised record version. All slice indexing is bounds-checked;
// partial parses return ok=false rather than panic.
func parseTLSClientHello(payload []byte) (sni, version string, ok bool) {
	defer func() {
		if r := recover(); r != nil {
			ok = false
		}
	}()

	// TLS record header: ContentType(1) + RecordVersion(2) + Length(2)
	if len(payload) < 5 {
		return "", "", false
	}
	if payload[0] != 0x16 { // ContentType: Handshake
		return "", "", false
	}
	recordVersion := binary.BigEndian.Uint16(payload[1:3])
	recordLen := int(binary.BigEndian.Uint16(payload[3:5]))

	// Make sure the full record is present
	if len(payload) < 5+recordLen {
		return "", "", false
	}

	hs := payload[5 : 5+recordLen]

	// Handshake header: HandshakeType(1) + Length(3)
	if len(hs) < 4 {
		return "", "", false
	}
	if hs[0] != 0x01 { // HandshakeType: ClientHello
		return "", "", false
	}
	hsLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if len(hs) < 4+hsLen {
		return "", "", false
	}
	hello := hs[4 : 4+hsLen]

	// ClientHello: LegacyVersion(2) + Random(32) + SessionIDLen(1) + SessionID
	offset := 0
	if len(hello) < offset+2 {
		return "", "", false
	}
	offset += 2 // LegacyVersion

	if len(hello) < offset+32 {
		return "", "", false
	}
	offset += 32 // Random

	if len(hello) < offset+1 {
		return "", "", false
	}
	sessionIDLen := int(hello[offset])
	offset++
	if len(hello) < offset+sessionIDLen {
		return "", "", false
	}
	offset += sessionIDLen

	// CipherSuites: Length(2) + Suites
	if len(hello) < offset+2 {
		return "", "", false
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(hello[offset : offset+2]))
	offset += 2
	if len(hello) < offset+cipherSuitesLen {
		return "", "", false
	}
	offset += cipherSuitesLen

	// CompressionMethods: Length(1) + Methods
	if len(hello) < offset+1 {
		return "", "", false
	}
	compMethodsLen := int(hello[offset])
	offset++
	if len(hello) < offset+compMethodsLen {
		return "", "", false
	}
	offset += compMethodsLen

	// Extensions: Length(2) + Extensions list
	if len(hello) < offset+2 {
		// No extensions — return record version only
		ver := tlsVersionNames[recordVersion]
		return "", ver, ver != ""
	}
	extsLen := int(binary.BigEndian.Uint16(hello[offset : offset+2]))
	offset += 2
	if len(hello) < offset+extsLen {
		return "", "", false
	}
	exts := hello[offset : offset+extsLen]

	// Walk extensions looking for SNI (type 0x0000) and supported_versions (0x002b)
	var sniValue string
	var supportedVersion string
	ei := 0
	for ei+4 <= len(exts) {
		extType := binary.BigEndian.Uint16(exts[ei : ei+2])
		extLen := int(binary.BigEndian.Uint16(exts[ei+2 : ei+4]))
		ei += 4
		if ei+extLen > len(exts) {
			break
		}
		extData := exts[ei : ei+extLen]
		ei += extLen

		switch extType {
		case 0x0000: // SNI
			// ServerNameList: Length(2) + entries
			if len(extData) < 5 {
				break
			}
			listLen := int(binary.BigEndian.Uint16(extData[0:2]))
			if listLen < 3 || len(extData) < 2+listLen {
				break
			}
			// NameType(1) + NameLen(2) + Name
			if extData[2] != 0x00 { // host_name
				break
			}
			nameLen := int(binary.BigEndian.Uint16(extData[3:5]))
			if len(extData) < 5+nameLen {
				break
			}
			sniValue = string(extData[5 : 5+nameLen])

		case 0x002b: // supported_versions (TLS 1.3 indicator)
			// In a ClientHello: Length(1) + list of 2-byte versions
			if len(extData) < 3 {
				break
			}
			listLen := int(extData[0])
			if len(extData) < 1+listLen {
				break
			}
			for vi := 1; vi+1 < 1+listLen; vi += 2 {
				v := binary.BigEndian.Uint16(extData[vi : vi+2])
				if v == 0x0304 {
					supportedVersion = "TLS 1.3"
					break
				}
			}
		}
	}

	ver := supportedVersion
	if ver == "" {
		ver = tlsVersionNames[recordVersion]
	}
	if ver == "" && recordVersion != 0 {
		ver = "Unknown"
	}

	return sniValue, ver, true
}

// ---------- SSH ----------

func enrichSSH(attrs *ProtocolAttributes, p gopacket.Packet) {
	payload := tcpPayload(p)
	if len(payload) == 0 {
		return
	}
	// Limit scan to first 256 bytes
	scan := payload
	if len(scan) > 256 {
		scan = scan[:256]
	}
	idx := bytes.Index(scan, []byte("SSH-"))
	if idx < 0 {
		return
	}
	match := sshBannerRE.FindSubmatch(scan[idx:])
	if len(match) < 3 {
		return
	}
	attrs.SSHProtocolVersion = string(match[1])
	attrs.SSHSoftwareVersion = string(match[2])
	attrs.SSHFound = true
}

// ---------- HTTP ----------

func isHTTPPort(src, dst int) bool {
	return src == 80 || dst == 80 || src == 8080 || dst == 8080
}

var httpRequestPrefixes = []string{"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE "}

func isHTTPPayload(payload []byte) bool {
	if len(payload) < 4 {
		return false
	}
	s := string(payload[:min(len(payload), 16)])
	for _, p := range httpRequestPrefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return strings.HasPrefix(s, "HTTP/")
}

func enrichHTTP(attrs *ProtocolAttributes, p gopacket.Packet) {
	payload := tcpPayload(p)
	if len(payload) == 0 {
		return
	}

	// Use recover to shield against stdlib panics on malformed payloads
	func() {
		defer func() { recover() }() //nolint:errcheck

		if bytes.HasPrefix(payload, []byte("HTTP/")) {
			// Try as HTTP response
			resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(payload)), nil)
			if err == nil || resp != nil {
				if resp != nil {
					_ = resp.Body.Close()
					attrs.HTTPStatusCode = resp.StatusCode
					attrs.HTTPFound = true
				}
			}
			return
		}

		// Try as HTTP request
		req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(payload)))
		if err == nil || req != nil {
			if req != nil {
				attrs.HTTPMethod = req.Method
				attrs.HTTPServerAddress = req.Host
				if req.URL != nil {
					uri := req.URL.RequestURI()
					if req.Host != "" {
						attrs.HTTPURLFull = "http://" + req.Host + uri
					} else {
						attrs.HTTPURLFull = uri
					}
				}
				attrs.HTTPUserAgent = req.UserAgent()
				attrs.HTTPFound = true
			}
		}
	}()
}

// min returns the smaller of a and b.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
