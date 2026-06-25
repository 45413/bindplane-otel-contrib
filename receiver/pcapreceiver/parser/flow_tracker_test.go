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
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

func makePacket(srcAddr string, srcPort int, dstAddr string, dstPort int, proto string) *PacketInfo {
	return &PacketInfo{
		SrcAddress: srcAddr,
		SrcPort:    srcPort,
		DstAddress: dstAddr,
		DstPort:    dstPort,
		Transport:  proto,
		Length:     100,
	}
}

func TestFlowTracker_SameFlow(t *testing.T) {
	ft := NewFlowTracker(5 * time.Minute)
	defer ft.Close()

	p := makePacket("10.0.0.1", 1234, "10.0.0.2", 80, "TCP")
	id1 := ft.Track(p)
	id2 := ft.Track(p)
	require.Equal(t, id1, id2, "same 5-tuple should yield same flow ID")
}

func TestFlowTracker_BidirectionalSameFlow(t *testing.T) {
	ft := NewFlowTracker(5 * time.Minute)
	defer ft.Close()

	forward := makePacket("10.0.0.1", 1234, "10.0.0.2", 80, "TCP")
	reverse := makePacket("10.0.0.2", 80, "10.0.0.1", 1234, "TCP")

	id1 := ft.Track(forward)
	id2 := ft.Track(reverse)
	require.Equal(t, id1, id2, "reversed src/dst should map to the same flow ID")
}

func TestFlowTracker_DifferentFlows(t *testing.T) {
	ft := NewFlowTracker(5 * time.Minute)
	defer ft.Close()

	p1 := makePacket("10.0.0.1", 1234, "10.0.0.2", 80, "TCP")
	p2 := makePacket("10.0.0.1", 5678, "10.0.0.2", 443, "TCP")

	id1 := ft.Track(p1)
	id2 := ft.Track(p2)
	require.NotEqual(t, id1, id2, "different 5-tuples should yield different flow IDs")
}

func TestFlowTracker_Eviction(t *testing.T) {
	// Use a very short timeout so eviction fires quickly, but the eviction
	// loop interval is clamped to 30 s — so we manually trigger eviction.
	ft := &FlowTracker{
		flows:   make(map[FlowKey]*FlowState),
		timeout: 100 * time.Millisecond,
		done:    make(chan struct{}),
	}
	// Don't start the background goroutine; drive eviction manually.

	p := makePacket("10.0.0.1", 1234, "10.0.0.2", 80, "TCP")
	id1 := ft.Track(p)

	// Force the LastSeen time into the past
	ft.mu.Lock()
	for _, s := range ft.flows {
		s.LastSeen = time.Now().Add(-200 * time.Millisecond)
	}
	ft.mu.Unlock()

	// Manually evict
	now := time.Now()
	ft.mu.Lock()
	for k, state := range ft.flows {
		if now.Sub(state.LastSeen) >= ft.timeout {
			delete(ft.flows, k)
		}
	}
	ft.mu.Unlock()

	id2 := ft.Track(p)
	require.NotEqual(t, id1, id2, "evicted flow should get a new UUID on next Track")

	close(ft.done) // satisfy goleak if someone adds the check later
}

func TestFlowTracker_Close(t *testing.T) {
	defer goleak.VerifyNone(t)

	ft := NewFlowTracker(5 * time.Minute)
	ft.Close()
	// Give the goroutine a moment to exit
	time.Sleep(10 * time.Millisecond)
}

func TestFlowTracker_Concurrent(t *testing.T) {
	ft := NewFlowTracker(5 * time.Minute)
	defer ft.Close()

	const goroutines = 20
	const iters = 100

	packets := []*PacketInfo{
		makePacket("10.0.0.1", 1234, "10.0.0.2", 80, "TCP"),
		makePacket("10.0.0.2", 80, "10.0.0.1", 1234, "TCP"),
		makePacket("192.168.1.1", 5000, "192.168.1.2", 443, "TCP"),
		makePacket("172.16.0.1", 9999, "172.16.0.2", 53, "UDP"),
	}

	var wg sync.WaitGroup
	for i := range goroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			p := packets[idx%len(packets)]
			for range iters {
				_ = ft.Track(p)
			}
		}(i)
	}
	wg.Wait()
}

func TestFlowTracker_ProtocolIsolation(t *testing.T) {
	ft := NewFlowTracker(5 * time.Minute)
	defer ft.Close()

	tcp := makePacket("10.0.0.1", 1234, "10.0.0.2", 80, "TCP")
	udp := makePacket("10.0.0.1", 1234, "10.0.0.2", 80, "UDP")

	idTCP := ft.Track(tcp)
	idUDP := ft.Track(udp)
	require.NotEqual(t, idTCP, idUDP, "same address/port pair with different protocol should be distinct flows")
}
