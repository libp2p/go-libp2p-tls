// +build openssl

package libp2ptls

import (
	"testing"
)

//////
// Handshake throughput
//////
// Test the handshake latency between an Standard TLS server and an OpenSSL client
func BenchmarkHandshake_StdTLSServer_OpenSSLClient(b *testing.B) {
	var serverTT transportConstructor = NewStdTLSTransport
	var clientTT transportConstructor = NewOpenSSLTransport
	benchmarkHandshake(b, serverTT, clientTT)
}

// Test the handshake latency between an OpenSSL server and a Standard TLS client
func BenchmarkHandshake_OpenSSLServer_StdTLSClient(b *testing.B) {
	var serverTT transportConstructor = NewOpenSSLTransport
	var clientTT transportConstructor = NewStdTLSTransport
	benchmarkHandshake(b, serverTT, clientTT)
}

// Test the handshake latency between an OpenSSL server and an OpenSSL client
func BenchmarkHandshake_OpenSSLServer_OpenSSLClient(b *testing.B) {
	var serverTT transportConstructor = NewOpenSSLTransport
	var clientTT transportConstructor = NewOpenSSLTransport
	benchmarkHandshake(b, serverTT, clientTT)
}

//////
// Connection latency (ping benchmarks)
//////

func BenchmarkLatency_StdTLSServer_OpenSSLClient(b *testing.B) {
	var serverTT transportConstructor = NewStdTLSTransport
	var clientTT transportConstructor = NewOpenSSLTransport
	benchmarkPingLatency(b, serverTT, clientTT)
}

func BenchmarkLatency_OpenSSLServer_StdTLSClient(b *testing.B) {
	var serverTT transportConstructor = NewOpenSSLTransport
	var clientTT transportConstructor = NewStdTLSTransport
	benchmarkPingLatency(b, serverTT, clientTT)
}

func BenchmarkLatency_OpenSSLServer_OpenSSLClient(b *testing.B) {
	var serverTT transportConstructor = NewOpenSSLTransport
	var clientTT transportConstructor = NewOpenSSLTransport
	benchmarkPingLatency(b, serverTT, clientTT)
}

//////
// Connection throughput
//////

func BenchmarkConnections_StdTLSServer_OpenSSLClient(b *testing.B) {
	var serverTT transportConstructor = NewStdTLSTransport
	var clientTT transportConstructor = NewOpenSSLTransport
	benchmarkConnections(b, serverTT, clientTT)
}

func BenchmarkConnections_OpenSSLServer_StdTLSClient(b *testing.B) {
	var serverTT transportConstructor = NewOpenSSLTransport
	var clientTT transportConstructor = NewStdTLSTransport
	benchmarkConnections(b, serverTT, clientTT)
}

func BenchmarkConnections_OpenSSLServer_OpenSSLClient(b *testing.B) {
	var serverTT transportConstructor = NewOpenSSLTransport
	var clientTT transportConstructor = NewOpenSSLTransport
	benchmarkConnections(b, serverTT, clientTT)
}
