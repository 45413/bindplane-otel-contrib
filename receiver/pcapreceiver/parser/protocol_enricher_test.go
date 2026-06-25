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

package parser

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Packet fixture helpers
// ---------------------------------------------------------------------------

// buildIPv4UDPPacket builds a minimal IPv4+UDP packet with the given payload.
// Checksums are zeroed (gopacket doesn't verify them by default).
func buildIPv4UDPPacket(srcIP, dstIP [4]byte, srcPort, dstPort uint16, payload []byte) []byte {
	udpLen := uint16(8 + len(payload))
	ipTotalLen := uint16(20 + int(udpLen))

	b := make([]byte, 0, int(ipTotalLen))

	// IPv4 header (20 bytes, no options)
	b = append(b,
		0x45,                         // Version=4, IHL=5
		0x00,                         // DSCP/ECN
		byte(ipTotalLen>>8), byte(ipTotalLen), // Total Length
		0x00, 0x01, // Identification
		0x40, 0x00, // Flags=DF, Fragment Offset=0
		0x40,       // TTL=64
		0x11,       // Protocol=17 (UDP)
		0x00, 0x00, // Header Checksum (zeroed)
	)
	b = append(b, srcIP[:]...)
	b = append(b, dstIP[:]...)

	// UDP header (8 bytes)
	b = append(b,
		byte(srcPort>>8), byte(srcPort), // Source Port
		byte(dstPort>>8), byte(dstPort), // Destination Port
		byte(udpLen>>8), byte(udpLen), // Length
		0x00, 0x00, // Checksum (zeroed)
	)
	b = append(b, payload...)
	return b
}

// buildIPv4TCPPacket builds a minimal IPv4+TCP packet with the given payload.
func buildIPv4TCPPacket(srcIP, dstIP [4]byte, srcPort, dstPort uint16, flags byte, payload []byte) []byte {
	ipTotalLen := uint16(20 + 20 + len(payload)) // IP + TCP (no options) + payload

	b := make([]byte, 0, int(ipTotalLen))

	// IPv4 header
	b = append(b,
		0x45, 0x00,
		byte(ipTotalLen>>8), byte(ipTotalLen),
		0x00, 0x01,
		0x40, 0x00,
		0x40,       // TTL=64
		0x06,       // Protocol=6 (TCP)
		0x00, 0x00, // Checksum
	)
	b = append(b, srcIP[:]...)
	b = append(b, dstIP[:]...)

	// TCP header (20 bytes, no options)
	b = append(b,
		byte(srcPort>>8), byte(srcPort),
		byte(dstPort>>8), byte(dstPort),
		0x00, 0x00, 0x00, 0x01, // Seq
		0x00, 0x00, 0x00, 0x00, // Ack
		0x50,        // Data offset=5 (20 bytes), reserved=0
		flags,       // Flags (e.g. 0x02=SYN, 0x18=PSH+ACK)
		0xff, 0xff,  // Window
		0x00, 0x00,  // Checksum
		0x00, 0x00,  // Urgent pointer
	)
	b = append(b, payload...)
	return b
}

// buildIPv4ICMPPacket builds a minimal IPv4+ICMPv4 echo-request packet.
func buildIPv4ICMPPacket(srcIP, dstIP [4]byte, icmpType, icmpCode byte) []byte {
	icmpPayload := []byte{0x00, 0x01, 0x00, 0x01, 0xde, 0xad, 0xbe, 0xef} // id=1, seq=1, data
	ipTotalLen := uint16(20 + 8 + len(icmpPayload))

	b := make([]byte, 0, int(ipTotalLen))
	b = append(b,
		0x45, 0x00,
		byte(ipTotalLen>>8), byte(ipTotalLen),
		0x00, 0x01,
		0x40, 0x00,
		0x40,       // TTL=64
		0x01,       // Protocol=1 (ICMP)
		0x00, 0x00, // Checksum
	)
	b = append(b, srcIP[:]...)
	b = append(b, dstIP[:]...)

	// ICMPv4 header (8 bytes)
	b = append(b, icmpType, icmpCode, 0x00, 0x00) // type, code, checksum
	b = append(b, icmpPayload...)
	return b
}

var (
	ip1 = [4]byte{10, 0, 0, 1}
	ip2 = [4]byte{10, 0, 0, 2}
)

// ---------------------------------------------------------------------------
// DNS fixtures
// ---------------------------------------------------------------------------

// dnsQueryPayload is a minimal DNS A query for "example.com" (ID=0x1234).
// Constructed manually: header(12) + question.
var dnsQueryPayload = []byte{
	0x12, 0x34, // Transaction ID
	0x01, 0x00, // Flags: standard query, recursion desired
	0x00, 0x01, // QDCOUNT=1
	0x00, 0x00, // ANCOUNT=0
	0x00, 0x00, // NSCOUNT=0
	0x00, 0x00, // ARCOUNT=0
	// Question: example.com A
	0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', // "example"
	0x03, 'c', 'o', 'm', // "com"
	0x00,       // root label
	0x00, 0x01, // QTYPE=A
	0x00, 0x01, // QCLASS=IN
}

// dnsResponsePayload is a minimal DNS A response for "example.com" → 93.184.216.34.
var dnsResponsePayload = []byte{
	0x12, 0x34, // Transaction ID
	0x81, 0x80, // Flags: response, recursion desired+available
	0x00, 0x01, // QDCOUNT=1
	0x00, 0x01, // ANCOUNT=1
	0x00, 0x00, // NSCOUNT=0
	0x00, 0x00, // ARCOUNT=0
	// Question
	0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
	0x03, 'c', 'o', 'm',
	0x00,
	0x00, 0x01, // QTYPE=A
	0x00, 0x01, // QCLASS=IN
	// Answer RR (pointer to offset 12)
	0xc0, 0x0c, // Name pointer → offset 12
	0x00, 0x01, // TYPE=A
	0x00, 0x01, // CLASS=IN
	0x00, 0x00, 0x00, 0x3c, // TTL=60
	0x00, 0x04, // RDLENGTH=4
	0x5d, 0xb8, 0xd8, 0x22, // 93.184.216.34
}

func TestEnrichProtocol_DNS_Query(t *testing.T) {
	pkt := buildIPv4UDPPacket(ip1, ip2, 12345, 53, dnsQueryPayload)
	info := &PacketInfo{
		Transport:  TransportUDP,
		SrcPort:    12345,
		DstPort:    53,
		HexData:    hex.EncodeToString(pkt),
		SrcAddress: "10.0.0.1",
		DstAddress: "10.0.0.2",
	}
	attrs := EnrichProtocol(info)
	require.NotNil(t, attrs)
	require.True(t, attrs.DNSFound)
	require.Equal(t, "example.com", attrs.DNSQuestionName)
	require.Equal(t, "No Error", attrs.DNSResponseCode)
	require.False(t, attrs.DNSIsResponse)
}

func TestEnrichProtocol_DNS_Response(t *testing.T) {
	pkt := buildIPv4UDPPacket(ip2, ip1, 53, 12345, dnsResponsePayload)
	info := &PacketInfo{
		Transport:  TransportUDP,
		SrcPort:    53,
		DstPort:    12345,
		HexData:    hex.EncodeToString(pkt),
		SrcAddress: "10.0.0.2",
		DstAddress: "10.0.0.1",
	}
	attrs := EnrichProtocol(info)
	require.NotNil(t, attrs)
	require.True(t, attrs.DNSFound)
	require.Equal(t, "example.com", attrs.DNSQuestionName)
	require.True(t, attrs.DNSIsResponse)
}

func TestEnrichProtocol_DNS_Truncated(t *testing.T) {
	// 4-byte DNS payload — too short to decode questions; should not panic
	payload := []byte{0x12, 0x34, 0x01, 0x00}
	pkt := buildIPv4UDPPacket(ip1, ip2, 12345, 53, payload)
	info := &PacketInfo{
		Transport:  TransportUDP,
		SrcPort:    12345,
		DstPort:    53,
		HexData:    hex.EncodeToString(pkt),
		SrcAddress: "10.0.0.1",
		DstAddress: "10.0.0.2",
	}
	// Must not panic; enrichment may or may not succeed depending on gopacket behaviour
	// Either way, the result is handled gracefully
	_ = EnrichProtocol(info)
}

// ---------------------------------------------------------------------------
// HTTP fixtures
// ---------------------------------------------------------------------------

func TestEnrichProtocol_HTTP_Request(t *testing.T) {
	payload := []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: TestClient/1.0\r\n\r\n")
	pkt := buildIPv4TCPPacket(ip1, ip2, 54321, 80, 0x18, payload)
	info := &PacketInfo{
		Transport:  TransportTCP,
		SrcPort:    54321,
		DstPort:    80,
		HexData:    hex.EncodeToString(pkt),
		SrcAddress: "10.0.0.1",
		DstAddress: "10.0.0.2",
	}
	attrs := EnrichProtocol(info)
	require.NotNil(t, attrs)
	require.True(t, attrs.HTTPFound)
	require.Equal(t, "GET", attrs.HTTPMethod)
	require.Equal(t, "example.com", attrs.HTTPServerAddress)
	require.Contains(t, attrs.HTTPURLFull, "/index.html")
	require.Equal(t, "TestClient/1.0", attrs.HTTPUserAgent)
}

func TestEnrichProtocol_HTTP_Response(t *testing.T) {
	payload := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 0\r\n\r\n")
	pkt := buildIPv4TCPPacket(ip2, ip1, 80, 54321, 0x18, payload)
	info := &PacketInfo{
		Transport:  TransportTCP,
		SrcPort:    80,
		DstPort:    54321,
		HexData:    hex.EncodeToString(pkt),
		SrcAddress: "10.0.0.2",
		DstAddress: "10.0.0.1",
	}
	attrs := EnrichProtocol(info)
	require.NotNil(t, attrs)
	require.True(t, attrs.HTTPFound)
	require.Equal(t, 200, attrs.HTTPStatusCode)
}

func TestEnrichProtocol_HTTP_NoPayload(t *testing.T) {
	// TCP SYN to port 80 with no payload — should return nil (no enrichment)
	pkt := buildIPv4TCPPacket(ip1, ip2, 54321, 80, 0x02, nil)
	info := &PacketInfo{
		Transport:  TransportTCP,
		SrcPort:    54321,
		DstPort:    80,
		HexData:    hex.EncodeToString(pkt),
		SrcAddress: "10.0.0.1",
		DstAddress: "10.0.0.2",
	}
	attrs := EnrichProtocol(info)
	// nil or HTTPFound=false — no attributes to surface
	if attrs != nil {
		require.False(t, attrs.HTTPFound)
	}
}

// ---------------------------------------------------------------------------
// TLS fixtures
// ---------------------------------------------------------------------------

// buildMinimalTLSClientHello constructs a minimal TLS 1.2 ClientHello with SNI.
func buildMinimalTLSClientHello(sni string) []byte {
	// Extensions: SNI
	sniBytes := []byte(sni)
	sniExt := make([]byte, 0, 9+len(sniBytes))
	sniExt = append(sniExt, 0x00, 0x00) // ExtType=SNI
	extDataLen := uint16(2 + 1 + 2 + len(sniBytes))
	sniExt = append(sniExt, byte(extDataLen>>8), byte(extDataLen))   // ExtLen
	sniExt = append(sniExt, byte(0), byte(len(sniBytes)+3))          // ServerNameList length
	sniExt = append(sniExt, 0x00)                                     // NameType=host_name
	sniExt = append(sniExt, byte(len(sniBytes)>>8), byte(len(sniBytes))) // NameLen
	sniExt = append(sniExt, sniBytes...)

	extsLen := uint16(len(sniExt))

	// ClientHello body: LegacyVersion(2) + Random(32) + SessionIDLen(1) + CipherSuitesLen(2) + one suite(2) + CompressionsLen(1) + one method(1) + ExtsLen(2) + exts
	hello := make([]byte, 0, 42+2+2+len(sniExt))
	hello = append(hello, 0x03, 0x03)              // LegacyVersion = TLS 1.2
	hello = append(hello, make([]byte, 32)...)      // Random (all zeros for test)
	hello = append(hello, 0x00)                     // SessionID length = 0
	hello = append(hello, 0x00, 0x02)               // CipherSuites length = 2
	hello = append(hello, 0xc0, 0x2b)               // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
	hello = append(hello, 0x01)                     // Compression methods length = 1
	hello = append(hello, 0x00)                     // null compression
	hello = append(hello, byte(extsLen>>8), byte(extsLen)) // Extensions length
	hello = append(hello, sniExt...)

	// Handshake header: HandshakeType(1) + Length(3)
	hsLen := len(hello)
	hs := []byte{
		0x01,                                      // HandshakeType = ClientHello
		byte(hsLen >> 16), byte(hsLen >> 8), byte(hsLen), // Length
	}
	hs = append(hs, hello...)

	// TLS record header
	recLen := uint16(len(hs))
	rec := []byte{
		0x16,                          // ContentType = Handshake
		0x03, 0x01,                    // RecordVersion = TLS 1.0
		byte(recLen >> 8), byte(recLen), // Length
	}
	rec = append(rec, hs...)
	return rec
}

func TestEnrichProtocol_TLS_ClientHello(t *testing.T) {
	tlsPayload := buildMinimalTLSClientHello("example.com")
	pkt := buildIPv4TCPPacket(ip1, ip2, 54321, 443, 0x18, tlsPayload)
	info := &PacketInfo{
		Transport:  TransportTCP,
		SrcPort:    54321,
		DstPort:    443,
		HexData:    hex.EncodeToString(pkt),
		SrcAddress: "10.0.0.1",
		DstAddress: "10.0.0.2",
	}
	attrs := EnrichProtocol(info)
	require.NotNil(t, attrs)
	require.True(t, attrs.TLSFound, "TLS should be detected")
	require.Equal(t, "example.com", attrs.TLSServerName)
	require.NotEmpty(t, attrs.TLSVersion)
}

func TestParseTLSClientHello_Direct(t *testing.T) {
	payload := buildMinimalTLSClientHello("api.example.org")
	sni, version, ok := parseTLSClientHello(payload)
	require.True(t, ok)
	require.Equal(t, "api.example.org", sni)
	require.NotEmpty(t, version)
}

func TestParseTLSClientHello_TooShort(t *testing.T) {
	_, _, ok := parseTLSClientHello([]byte{0x16, 0x03})
	require.False(t, ok)
}

func TestParseTLSClientHello_NotHandshake(t *testing.T) {
	// Application data record, not a Handshake
	payload := []byte{0x17, 0x03, 0x03, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05}
	_, _, ok := parseTLSClientHello(payload)
	require.False(t, ok)
}

func TestEnrichProtocol_TLS_SYN_NoPayload(t *testing.T) {
	// TCP SYN to port 443 with no TLS payload — should not produce TLS attributes
	pkt := buildIPv4TCPPacket(ip1, ip2, 54321, 443, 0x02, nil)
	info := &PacketInfo{
		Transport:  TransportTCP,
		SrcPort:    54321,
		DstPort:    443,
		HexData:    hex.EncodeToString(pkt),
		SrcAddress: "10.0.0.1",
		DstAddress: "10.0.0.2",
	}
	attrs := EnrichProtocol(info)
	// Should return nil (nothing enriched) or TLSFound=false
	if attrs != nil {
		require.False(t, attrs.TLSFound)
	}
}

// ---------------------------------------------------------------------------
// SSH fixtures
// ---------------------------------------------------------------------------

func TestEnrichProtocol_SSH_Banner(t *testing.T) {
	banner := []byte("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")
	pkt := buildIPv4TCPPacket(ip2, ip1, 22, 54321, 0x18, banner)
	info := &PacketInfo{
		Transport:  TransportTCP,
		SrcPort:    22,
		DstPort:    54321,
		HexData:    hex.EncodeToString(pkt),
		SrcAddress: "10.0.0.2",
		DstAddress: "10.0.0.1",
	}
	attrs := EnrichProtocol(info)
	require.NotNil(t, attrs)
	require.True(t, attrs.SSHFound)
	require.Equal(t, "2.0", attrs.SSHProtocolVersion)
	require.Equal(t, "OpenSSH_8.9p1", attrs.SSHSoftwareVersion)
}

func TestEnrichProtocol_SSH_NoPayload(t *testing.T) {
	pkt := buildIPv4TCPPacket(ip1, ip2, 54321, 22, 0x02, nil)
	info := &PacketInfo{
		Transport:  TransportTCP,
		SrcPort:    54321,
		DstPort:    22,
		HexData:    hex.EncodeToString(pkt),
		SrcAddress: "10.0.0.1",
		DstAddress: "10.0.0.2",
	}
	attrs := EnrichProtocol(info)
	if attrs != nil {
		require.False(t, attrs.SSHFound)
	}
}

// ---------------------------------------------------------------------------
// ICMP fixtures
// ---------------------------------------------------------------------------

func TestEnrichProtocol_ICMPv4_EchoRequest(t *testing.T) {
	pkt := buildIPv4ICMPPacket(ip1, ip2, 8, 0) // type=8=EchoRequest, code=0
	info := &PacketInfo{
		Transport:  TransportICMP,
		HexData:    hex.EncodeToString(pkt),
		SrcAddress: "10.0.0.1",
		DstAddress: "10.0.0.2",
	}
	attrs := EnrichProtocol(info)
	require.NotNil(t, attrs)
	require.True(t, attrs.ICMPFound)
	require.Equal(t, "EchoRequest", attrs.ICMPType)
	require.Equal(t, 0, attrs.ICMPCode)
}

func TestEnrichProtocol_ICMPv4_EchoReply(t *testing.T) {
	pkt := buildIPv4ICMPPacket(ip2, ip1, 0, 0) // type=0=EchoReply
	info := &PacketInfo{
		Transport:  TransportICMP,
		HexData:    hex.EncodeToString(pkt),
		SrcAddress: "10.0.0.2",
		DstAddress: "10.0.0.1",
	}
	attrs := EnrichProtocol(info)
	require.NotNil(t, attrs)
	require.True(t, attrs.ICMPFound)
	require.Equal(t, "EchoReply", attrs.ICMPType)
}

func TestEnrichProtocol_ICMPv4_TimeExceeded(t *testing.T) {
	pkt := buildIPv4ICMPPacket(ip2, ip1, 11, 0) // type=11=TimeExceeded
	info := &PacketInfo{
		Transport:  TransportICMP,
		HexData:    hex.EncodeToString(pkt),
		SrcAddress: "10.0.0.2",
		DstAddress: "10.0.0.1",
	}
	attrs := EnrichProtocol(info)
	require.NotNil(t, attrs)
	require.True(t, attrs.ICMPFound)
	require.Equal(t, "TimeExceeded", attrs.ICMPType)
}

// ---------------------------------------------------------------------------
// Edge-case tests
// ---------------------------------------------------------------------------

func TestEnrichProtocol_EmptyHexData(t *testing.T) {
	info := &PacketInfo{Transport: TransportTCP, SrcPort: 80, DstPort: 12345}
	require.Nil(t, EnrichProtocol(info))
}

func TestEnrichProtocol_InvalidHex(t *testing.T) {
	info := &PacketInfo{HexData: "zzz", Transport: TransportTCP}
	require.Nil(t, EnrichProtocol(info))
}

func TestEnrichProtocol_UnknownPort(t *testing.T) {
	// TCP packet on non-standard port with no recognisable payload
	payload := []byte{0xde, 0xad, 0xbe, 0xef}
	pkt := buildIPv4TCPPacket(ip1, ip2, 54321, 9999, 0x18, payload)
	info := &PacketInfo{
		Transport:  TransportTCP,
		SrcPort:    54321,
		DstPort:    9999,
		HexData:    hex.EncodeToString(pkt),
		SrcAddress: "10.0.0.1",
		DstAddress: "10.0.0.2",
	}
	attrs := EnrichProtocol(info)
	require.Nil(t, attrs)
}

func TestEnrichProtocol_FromExistingGoldenICMP(t *testing.T) {
	// Hex from the existing icmp_echo.txt golden fixture (raw IPv4, no Ethernet)
	hexData := "45000054000040004001b6e8c0a80164c0a801010800f7ff04d2000100010203"
	info := &PacketInfo{
		Transport:  TransportICMP,
		HexData:    hexData,
		SrcAddress: "192.168.1.100",
		DstAddress: "192.168.1.1",
	}
	attrs := EnrichProtocol(info)
	require.NotNil(t, attrs)
	require.True(t, attrs.ICMPFound)
	require.Equal(t, "EchoRequest", attrs.ICMPType)
	require.Equal(t, 0, attrs.ICMPCode)
}

func TestEnrichProtocol_MalformedHTTPPayload(t *testing.T) {
	// Starts with "GET " but is otherwise garbage — should not panic
	payload := []byte("GET \x00\x01\x02\x03 garbage\r\n\r\n" + strings.Repeat("x", 100))
	pkt := buildIPv4TCPPacket(ip1, ip2, 54321, 80, 0x18, payload)
	info := &PacketInfo{
		Transport:  TransportTCP,
		SrcPort:    54321,
		DstPort:    80,
		HexData:    hex.EncodeToString(pkt),
		SrcAddress: "10.0.0.1",
		DstAddress: "10.0.0.2",
	}
	require.NotPanics(t, func() {
		EnrichProtocol(info)
	})
}
