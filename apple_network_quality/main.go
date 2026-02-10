// Package main implements an osquery extension table for macOS networkQuality metrics.
// This extension executes the built-in networkQuality command and exposes results via SQL.
//
// Usage:
//
//	SELECT * FROM apple_network_quality;
//
// The networkQuality tool (macOS 12+) measures network throughput and responsiveness
// using Apple's CDN infrastructure.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os/exec"
	"runtime"
	"strconv"
	"time"

	"github.com/osquery/osquery-go"
	"github.com/osquery/osquery-go/plugin/table"
)

var (
	socket   = flag.String("socket", "", "Path to the extensions UNIX domain socket")
	timeout  = flag.Int("timeout", 3, "Seconds to wait for autoloaded extensions")
	interval = flag.Int("interval", 3, "Seconds delay between connectivity checks")
)

// networkQualityResult represents the JSON output from networkQuality -c
type networkQualityResult struct {
	// Throughput in bits per second
	DLThroughput int64 `json:"dl_throughput"`
	ULThroughput int64 `json:"ul_throughput"`

	// Responsiveness in RPM (roundtrips per minute, higher is better)
	// Note: dl_responsiveness and ul_responsiveness may not always be present
	DLResponsiveness float64 `json:"dl_responsiveness"`
	ULResponsiveness float64 `json:"ul_responsiveness"`
	Responsiveness   float64 `json:"responsiveness"`

	// Latency (may not always be present)
	BaseRTT float64 `json:"base_rtt"`

	// Flow counts
	DLFlows int `json:"dl_flows"`
	ULFlows int `json:"ul_flows"`

	// Bytes transferred
	DLBytesTransferred int64 `json:"dl_bytes_transferred"`
	ULBytesTransferred int64 `json:"ul_bytes_transferred"`

	// Test metadata
	InterfaceName string `json:"interface_name"`
	TestEndpoint  string `json:"test_endpoint"`
	StartDate     string `json:"start_date"`
	EndDate       string `json:"end_date"`
	OSVersion     string `json:"os_version"`

	// Latency under load arrays (foreign = to Apple CDN)
	LUDForeignH2ReqResp []float64 `json:"lud_foreign_h2_req_resp,omitempty"`
	LUDForeignTCPHS443  []float64 `json:"lud_foreign_tcp_handshake_443,omitempty"`
	LUDForeignTLSHS     []float64 `json:"lud_foreign_tls_handshake,omitempty"`
	LUDSelfH2ReqResp    []float64 `json:"lud_self_h2_req_resp,omitempty"`

	// Idle latency arrays (older format, may not always be present)
	ILTCPHS443  []float64 `json:"il_tcp_handshake_443,omitempty"`
	ILTLSHS     []float64 `json:"il_tls_handshake,omitempty"`
	ILH2ReqResp []float64 `json:"il_h2_req_resp,omitempty"`

	// Other metadata (network conditions)
	Other otherMetadata `json:"other,omitempty"`
}

// otherMetadata contains network condition details
type otherMetadata struct {
	ECNValues     map[string]int `json:"ecn_values,omitempty"`
	InterfaceType map[string]int `json:"interface-type,omitempty"`
	L4SEnablement map[string]int `json:"l4s_enablement,omitempty"`
	ProtocolsSeen map[string]int `json:"protocols_seen,omitempty"`
	ProxyState    map[string]int `json:"proxy_state,omitempty"`
	RAT           map[string]int `json:"rat,omitempty"`
}

// getFirstKey returns the first (usually only) key from a map
func getFirstKey(m map[string]int) string {
	for k := range m {
		return k
	}
	return ""
}

func main() {
	flag.Parse()
	if *socket == "" {
		log.Fatalln("Missing required --socket argument")
	}

	serverTimeout := osquery.ServerTimeout(
		time.Second * time.Duration(*timeout),
	)
	serverPingInterval := osquery.ServerPingInterval(
		time.Second * time.Duration(*interval),
	)

	server, err := osquery.NewExtensionManagerServer(
		"apple_network_quality",
		*socket,
		serverTimeout,
		serverPingInterval,
	)
	if err != nil {
		log.Fatalf("Error creating extension: %s\n", err)
	}

	server.RegisterPlugin(table.NewPlugin(
		"apple_network_quality",
		networkQualityColumns(),
		generateNetworkQuality,
	))

	if err := server.Run(); err != nil {
		log.Fatal(err)
	}
}

func networkQualityColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		// Throughput (converted to Mbps for readability)
		table.BigIntColumn("dl_throughput_bps"),
		table.BigIntColumn("ul_throughput_bps"),
		table.DoubleColumn("dl_throughput_mbps"),
		table.DoubleColumn("ul_throughput_mbps"),

		// Responsiveness (RPM - roundtrips per minute, higher is better)
		table.DoubleColumn("responsiveness"),

		// Flow counts
		table.IntegerColumn("dl_flows"),
		table.IntegerColumn("ul_flows"),

		// Bytes transferred
		table.BigIntColumn("dl_bytes"),
		table.BigIntColumn("ul_bytes"),

		// Average latency under load metrics (computed from arrays)
		table.DoubleColumn("avg_tcp_handshake_ms"),
		table.DoubleColumn("avg_tls_handshake_ms"),
		table.DoubleColumn("avg_h2_latency_ms"),
		table.DoubleColumn("avg_self_h2_latency_ms"),

		// Network condition metadata
		table.TextColumn("interface_name"),
		table.TextColumn("interface_type"),
		table.TextColumn("protocol"),
		table.TextColumn("proxy_state"),
		table.TextColumn("ecn"),
		table.TextColumn("l4s"),

		// Test metadata
		table.TextColumn("test_endpoint"),
		table.TextColumn("start_date"),
		table.TextColumn("end_date"),
		table.TextColumn("os_version"),
	}
}

func generateNetworkQuality(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	// Only run on macOS
	if runtime.GOOS != "darwin" {
		return []map[string]string{}, nil
	}

	// Check if networkQuality exists (macOS 12+)
	if _, err := exec.LookPath("networkQuality"); err != nil {
		return []map[string]string{}, nil
	}

	// Execute networkQuality with JSON output and 3-second max duration
	// -c: JSON output to stdout
	// -M 3: Maximum test duration of 3 seconds
	cmd := exec.CommandContext(ctx, "/usr/bin/networkQuality", "-c", "-M", "3")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("networkQuality command failed: %v", err)
	}

	var result networkQualityResult
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("failed to parse networkQuality JSON: %v", err)
	}

	// Convert throughput to Mbps
	dlMbps := float64(result.DLThroughput) / 1_000_000
	ulMbps := float64(result.ULThroughput) / 1_000_000

	// Calculate average latencies from arrays (prefer lud_foreign_* over il_*)
	avgTCPHS := averageFloat64(result.LUDForeignTCPHS443)
	if avgTCPHS == 0 {
		avgTCPHS = averageFloat64(result.ILTCPHS443)
	}
	avgTLSHS := averageFloat64(result.LUDForeignTLSHS)
	if avgTLSHS == 0 {
		avgTLSHS = averageFloat64(result.ILTLSHS)
	}
	avgH2 := averageFloat64(result.LUDForeignH2ReqResp)
	if avgH2 == 0 {
		avgH2 = averageFloat64(result.ILH2ReqResp)
	}
	avgSelfH2 := averageFloat64(result.LUDSelfH2ReqResp)

	// Extract network condition metadata from "other" object
	interfaceType := getFirstKey(result.Other.InterfaceType)
	protocol := getFirstKey(result.Other.ProtocolsSeen)
	proxyState := getFirstKey(result.Other.ProxyState)
	ecn := getFirstKey(result.Other.ECNValues)
	l4s := getFirstKey(result.Other.L4SEnablement)

	row := map[string]string{
		// Throughput
		"dl_throughput_bps":  strconv.FormatInt(result.DLThroughput, 10),
		"ul_throughput_bps":  strconv.FormatInt(result.ULThroughput, 10),
		"dl_throughput_mbps": strconv.FormatFloat(dlMbps, 'f', 2, 64),
		"ul_throughput_mbps": strconv.FormatFloat(ulMbps, 'f', 2, 64),

		// Responsiveness
		"responsiveness": strconv.FormatFloat(result.Responsiveness, 'f', 2, 64),

		// Flows
		"dl_flows": strconv.Itoa(result.DLFlows),
		"ul_flows": strconv.Itoa(result.ULFlows),

		// Bytes
		"dl_bytes": strconv.FormatInt(result.DLBytesTransferred, 10),
		"ul_bytes": strconv.FormatInt(result.ULBytesTransferred, 10),

		// Average latencies (under load)
		"avg_tcp_handshake_ms":   strconv.FormatFloat(avgTCPHS, 'f', 2, 64),
		"avg_tls_handshake_ms":   strconv.FormatFloat(avgTLSHS, 'f', 2, 64),
		"avg_h2_latency_ms":      strconv.FormatFloat(avgH2, 'f', 2, 64),
		"avg_self_h2_latency_ms": strconv.FormatFloat(avgSelfH2, 'f', 2, 64),

		// Network condition metadata
		"interface_name": result.InterfaceName,
		"interface_type": interfaceType,
		"protocol":       protocol,
		"proxy_state":    proxyState,
		"ecn":            ecn,
		"l4s":            l4s,

		// Test metadata
		"test_endpoint": result.TestEndpoint,
		"start_date":    result.StartDate,
		"end_date":      result.EndDate,
		"os_version":    result.OSVersion,
	}

	return []map[string]string{row}, nil
}

// averageFloat64 computes the average of a float64 slice, returns 0 if empty
func averageFloat64(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	var sum float64
	for _, v := range vals {
		sum += v
	}
	return sum / float64(len(vals))
}
