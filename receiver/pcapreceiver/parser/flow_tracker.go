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
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// FlowKey identifies a bidirectional network flow. Addresses and ports are
// always stored in canonical order (lower addr/port in Low*) so that packets
// travelling in opposite directions map to the same key.
type FlowKey struct {
	LowAddr  string
	HighAddr string
	LowPort  int
	HighPort int
	Proto    string
}

// FlowState holds per-flow accounting data.
type FlowState struct {
	ID          string
	StartTime   time.Time
	LastSeen    time.Time
	PacketCount int64
	ByteCount   int64
}

// FlowTracker assigns stable UUIDs to network flows and evicts stale ones.
type FlowTracker struct {
	mu      sync.RWMutex
	flows   map[FlowKey]*FlowState
	timeout time.Duration
	done    chan struct{}
}

// NewFlowTracker creates a FlowTracker that evicts flows idle for longer than
// timeout. Minimum effective eviction interval is 30 seconds.
func NewFlowTracker(timeout time.Duration) *FlowTracker {
	ft := &FlowTracker{
		flows:   make(map[FlowKey]*FlowState),
		timeout: timeout,
		done:    make(chan struct{}),
	}
	go ft.evictLoop()
	return ft
}

// Track records a packet belonging to the flow identified by info and returns
// the flow's stable UUID. If the flow is new it is created on the spot.
func (ft *FlowTracker) Track(info *PacketInfo) string {
	key := newFlowKey(info)
	now := time.Now()

	ft.mu.Lock()
	defer ft.mu.Unlock()

	state, exists := ft.flows[key]
	if !exists {
		state = &FlowState{
			ID:        uuid.New().String(),
			StartTime: now,
		}
		ft.flows[key] = state
	}
	state.LastSeen = now
	state.PacketCount++
	state.ByteCount += int64(info.Length)

	return state.ID
}

// Close stops the background eviction goroutine.
func (ft *FlowTracker) Close() {
	close(ft.done)
}

// evictLoop periodically removes flows that have not been seen for ft.timeout.
func (ft *FlowTracker) evictLoop() {
	interval := ft.timeout / 2
	if interval < 30*time.Second {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ft.done:
			return
		case now := <-ticker.C:
			ft.mu.Lock()
			for k, state := range ft.flows {
				if now.Sub(state.LastSeen) >= ft.timeout {
					delete(ft.flows, k)
				}
			}
			ft.mu.Unlock()
		}
	}
}

// newFlowKey builds a canonical FlowKey from a PacketInfo so that A→B and B→A
// produce the same key.
func newFlowKey(info *PacketInfo) FlowKey {
	addrA, portA := info.SrcAddress, info.SrcPort
	addrB, portB := info.DstAddress, info.DstPort

	// Canonicalize: put the lexicographically-lower address in Low*.
	// On tie, use the lower port number.
	cmp := strings.Compare(addrA, addrB)
	if cmp > 0 || (cmp == 0 && portA > portB) {
		addrA, portA, addrB, portB = addrB, portB, addrA, portA
	}

	return FlowKey{
		LowAddr:  addrA,
		LowPort:  portA,
		HighAddr: addrB,
		HighPort: portB,
		Proto:    info.Transport,
	}
}
