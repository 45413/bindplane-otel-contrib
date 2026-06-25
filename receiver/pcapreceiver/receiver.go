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

package pcapreceiver

import (
	"context"
	"fmt"
	"os/exec"

	"github.com/observiq/bindplane-otel-contrib/receiver/pcapreceiver/internal/metadata"
	"github.com/observiq/bindplane-otel-contrib/receiver/pcapreceiver/parser"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/receiver"
	"go.opentelemetry.io/collector/receiver/receiverhelper"
	"go.uber.org/zap"
)

// pcapReceiver receives network packets via tcpdump and emits them as logs
type pcapReceiver struct {
	id          component.ID
	telemetry   component.TelemetrySettings
	metrics     *metadata.TelemetryBuilder
	config      *Config
	logger      *zap.Logger
	consumer    consumer.Logs
	cancel      context.CancelFunc
	cmd         *exec.Cmd          // Used on Unix systems for tcpdump process
	pcapHandle  interface{}        // Used on Windows for go-pcap handle
	obsrecv     *receiverhelper.ObsReport
	flowTracker *parser.FlowTracker // Non-nil when EnableConnectionTracking=true
}

// newReceiver creates a new PCAP receiver
func newReceiver(params receiver.Settings, config *Config, logger *zap.Logger, consumer consumer.Logs, tb *metadata.TelemetryBuilder) (*pcapReceiver, error) {
	obsrecv, err := receiverhelper.NewObsReport(receiverhelper.ObsReportSettings{
		ReceiverID:             params.ID,
		Transport:              "http",
		ReceiverCreateSettings: params,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to set up observer: %w", err)
	}

	return &pcapReceiver{
		id:        params.ID,
		telemetry: params.TelemetrySettings,
		metrics:   tb,
		config:    config,
		logger:    logger,
		consumer:  consumer,
		obsrecv:   obsrecv,
	}, nil
}

// Start and Shutdown methods are platform-specific (see receiver_unix.go and receiver_windows.go)

// truncateString truncates a string to maxLen characters, adding "..." if truncated
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// isTimestampLine checks if a line starts with a timestamp (HH:MM:SS)
func isTimestampLine(line string) bool {
	if len(line) < 8 {
		return false
	}
	// Simple check for timestamp format: HH:MM:SS
	return line[2] == ':' && line[5] == ':'
}

// processPacket parses and emits a packet as an OTel log
func (r *pcapReceiver) processPacket(ctx context.Context, lines []string) {
	// Do not process or emit if shutdown has been initiated
	select {
	case <-ctx.Done():
		return
	default:
	}

	// Parse the packet
	packetInfo, err := parser.ParsePacket(lines)
	if err != nil {
		r.logger.Warn("Failed to parse packet",
			zap.Error(err),
			zap.Int("line_count", len(lines)),
			zap.String("first_line", truncateString(lines[0], 100)))
		return
	}

	r.logger.Debug("Successfully parsed packet",
		zap.String("protocol", packetInfo.Protocol),
		zap.String("transport", packetInfo.Transport),
		zap.String("src", packetInfo.SrcAddress),
		zap.String("dst", packetInfo.DstAddress),
		zap.Int("length", packetInfo.Length))

	// Process the parsed packet info
	r.processPacketInfo(ctx, packetInfo)
}

// processPacketInfo emits a parsed packet as an OTel log (common for both text and binary parsing)
func (r *pcapReceiver) processPacketInfo(ctx context.Context, packetInfo *parser.PacketInfo) {
	// Do not process or emit if shutdown has been initiated
	select {
	case <-ctx.Done():
		return
	default:
	}

	// Create OTel log
	logs := plog.NewLogs()
	resourceLogs := logs.ResourceLogs().AppendEmpty()
	scopeLogs := resourceLogs.ScopeLogs().AppendEmpty()
	logRecord := scopeLogs.LogRecords().AppendEmpty()

	// Set timestamp
	logRecord.SetTimestamp(pcommon.NewTimestampFromTime(packetInfo.Timestamp))
	logRecord.SetObservedTimestamp(pcommon.NewTimestampFromTime(packetInfo.Timestamp))

	// Set body as hex-encoded packet data (with 0x prefix)
	logRecord.Body().SetStr("0x" + packetInfo.HexData)

	// Set attributes if enabled
	if r.config.ParseAttributes {
		attrs := logRecord.Attributes()
		attrs.PutStr("network.type", packetInfo.Protocol)
		// Use packet-specific interface if available (from "any" interface captures), otherwise fall back to configured interface
		if packetInfo.Interface != "" {
			attrs.PutStr("network.interface.name", packetInfo.Interface)
		} else {
			attrs.PutStr("network.interface.name", r.config.Interface)
		}
		attrs.PutStr("network.transport", packetInfo.Transport)
		attrs.PutStr("source.address", packetInfo.SrcAddress)
		attrs.PutStr("destination.address", packetInfo.DstAddress)

		if packetInfo.SrcPort > 0 {
			attrs.PutInt("source.port", int64(packetInfo.SrcPort))
		}
		if packetInfo.DstPort > 0 {
			attrs.PutInt("destination.port", int64(packetInfo.DstPort))
		}

		attrs.PutInt("packet.length", int64(packetInfo.Length))

		// Application-layer protocol enrichment
		if packetInfo.HexData != "" {
			if protoAttrs := parser.EnrichProtocol(packetInfo); protoAttrs != nil {
				setProtocolAttributes(attrs, protoAttrs)
			}
		}

		// Flow / connection tracking
		if r.config.EnableConnectionTracking && r.flowTracker != nil {
			connID := r.flowTracker.Track(packetInfo)
			attrs.PutStr("network.connection.id", connID)
		}
	}

	// Consume the log with observation tracking
	obsCtx := r.obsrecv.StartLogsOp(ctx)
	if err := r.consumer.ConsumeLogs(ctx, logs); err != nil {
		r.obsrecv.EndLogsOp(obsCtx, metadata.Type.String(), logs.LogRecordCount(), err)
		r.logger.Error("Failed to consume packet log",
			zap.Error(err),
			zap.String("protocol", packetInfo.Protocol),
			zap.String("src", packetInfo.SrcAddress),
			zap.String("dst", packetInfo.DstAddress))
		return
	}
	r.obsrecv.EndLogsOp(obsCtx, metadata.Type.String(), logs.LogRecordCount(), nil)

	// Record custom metric for packets captured
	if r.metrics != nil {
		r.metrics.PcapPacketsCaptured.Add(ctx, 1)
	}

	r.logger.Debug("Successfully consumed packet log",
		zap.String("protocol", packetInfo.Protocol),
		zap.String("transport", packetInfo.Transport))
}

// setProtocolAttributes maps ProtocolAttributes fields to OTel log attributes
// following OpenTelemetry semantic conventions.
func setProtocolAttributes(attrs pcommon.Map, p *parser.ProtocolAttributes) {
	if p.DNSFound {
		attrs.PutStr("dns.question.name", p.DNSQuestionName)
		attrs.PutStr("dns.response_code", p.DNSResponseCode)
		attrs.PutBool("dns.is_response", p.DNSIsResponse)
	}
	if p.HTTPFound {
		if p.HTTPMethod != "" {
			attrs.PutStr("http.request.method", p.HTTPMethod)
		}
		if p.HTTPURLFull != "" {
			attrs.PutStr("url.full", p.HTTPURLFull)
		}
		if p.HTTPServerAddress != "" {
			attrs.PutStr("server.address", p.HTTPServerAddress)
		}
		if p.HTTPStatusCode != 0 {
			attrs.PutInt("http.response.status_code", int64(p.HTTPStatusCode))
		}
		if p.HTTPUserAgent != "" {
			attrs.PutStr("user_agent.original", p.HTTPUserAgent)
		}
	}
	if p.TLSFound {
		if p.TLSServerName != "" {
			attrs.PutStr("tls.server.name", p.TLSServerName)
		}
		if p.TLSVersion != "" {
			attrs.PutStr("tls.protocol.version", p.TLSVersion)
		}
	}
	if p.SSHFound {
		if p.SSHProtocolVersion != "" {
			attrs.PutStr("ssh.protocol.version", p.SSHProtocolVersion)
		}
		if p.SSHSoftwareVersion != "" {
			attrs.PutStr("ssh.software.version", p.SSHSoftwareVersion)
		}
	}
	if p.ICMPFound {
		attrs.PutStr("icmp.type", p.ICMPType)
		attrs.PutInt("icmp.code", int64(p.ICMPCode))
	}
}
