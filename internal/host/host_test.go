package host

import (
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"testing/iotest"
	"time"
)

var errBoom = errors.New("boom")

type captureConn struct {
	buf bytes.Buffer
}

func (c *captureConn) Read(b []byte) (int, error)         { return 0, io.EOF }
func (c *captureConn) Write(b []byte) (int, error)        { return c.buf.Write(b) }
func (c *captureConn) Close() error                       { return nil }
func (c *captureConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c *captureConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (c *captureConn) SetDeadline(t time.Time) error      { return nil }
func (c *captureConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *captureConn) SetWriteDeadline(t time.Time) error { return nil }

type errReader struct {
	err error
}

func (r errReader) Read(b []byte) (int, error) { return 0, r.err }

func clientHello(t *testing.T, config *tls.Config) []byte {
	t.Helper()
	conn := &captureConn{}
	_ = tls.Client(conn, config).Handshake()
	hello := conn.buf.Bytes()
	if len(hello) == 0 {
		t.Fatalf("client produced no ClientHello for config %+v", config)
	}
	return hello
}

func versionHello(t *testing.T, version uint16, serverName string) []byte {
	t.Helper()
	return clientHello(t, &tls.Config{
		ServerName: serverName,
		MinVersion: version,
		MaxVersion: version,
	})
}

const (
	ssl30ClientHello = "160300007d010000790300c005fecf52c3343a9cc65c8d518a0b6e418c85b726" +
		"d1c0cf2e193a963b401941000052c014c00a0039003800880087c00fc0050035" +
		"0084c013c00900330032009a009900450044c00ec004002f009600410007c011" +
		"c007c00cc00200050004c012c00800160013c00dc003000a00150012000900ff" +
		"0100"

	sslv2ClientHello = "802e0100020015000000100500800300800100800700c0060040040080020080" +
		"08e561d7b4864cc7beb7c7d9b1d994fa"

	tls10ClientHelloOpenSSL = "16030100930100008f03019ea6cf6440722673ec47b312aad071c9ff59221157" +
		"6d555f7c76a65ced1869e000002ec00ac0140039003800880087c019003a0089" +
		"c009c0130033003200450044c0180034004600350084002f004100ff01000038" +
		"00000010000e00000b6578616d706c652e636f6d000b000403000102000a000c" +
		"000a001d0017001e00180019002300000016000000170000"
)

func decodeHello(t *testing.T, hexHello string) []byte {
	t.Helper()
	hello, err := hex.DecodeString(hexHello)
	if err != nil {
		t.Fatalf("decode hello: %v", err)
	}
	return hello
}

func TestExtractHTTPHostVersions(t *testing.T) {
	tests := []struct {
		name    string
		request string
	}{
		{"HTTP/1.0", "GET / HTTP/1.0\r\nHost: example.com\r\n\r\n"},
		{"HTTP/1.1", "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"},
		{"HTTP/2.0", "GET / HTTP/2.0\r\nHost: example.com\r\n\r\n"},
		{"HTTP/9.9", "GET / HTTP/9.9\r\nHost: example.com\r\n\r\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			host, err := ExtractHTTPHost(strings.NewReader(test.request))
			if err != nil {
				t.Fatalf("ExtractHTTPHost returned error: %v", err)
			}
			if host != "example.com" {
				t.Errorf("host = %q, want %q", host, "example.com")
			}
		})
	}
}

func TestExtractHTTPHostBodies(t *testing.T) {
	tests := []struct {
		name    string
		request string
	}{
		{
			"no body",
			"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
		},
		{
			"content length body",
			"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello",
		},
		{
			"content length body not yet arrived",
			"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\n",
		},
		{
			"content length body partially arrived",
			"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhe",
		},
		{
			"chunked body",
			"POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n" +
				"5\r\nhello\r\n0\r\n\r\n",
		},
		{
			"chunked body not yet arrived",
			"POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n",
		},
		{
			"chunked body partially arrived",
			"POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel",
		},
		{
			"zero content length",
			"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			host, err := ExtractHTTPHost(strings.NewReader(test.request))
			if err != nil {
				t.Fatalf("ExtractHTTPHost returned error: %v", err)
			}
			if host != "example.com" {
				t.Errorf("host = %q, want %q", host, "example.com")
			}
		})
	}
}

func TestExtractHTTPHostRequestTargetForms(t *testing.T) {
	tests := []struct {
		name    string
		request string
		want    string
	}{
		{
			"origin form",
			"GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
			"example.com",
		},
		{
			"absolute form overrides host header",
			"GET http://absolute.example.com/path HTTP/1.1\r\nHost: header.example.com\r\n\r\n",
			"absolute.example.com",
		},
		{
			"absolute form with port",
			"GET http://absolute.example.com:8080/ HTTP/1.1\r\nHost: header.example.com\r\n\r\n",
			"absolute.example.com",
		},
		{
			"authority form",
			"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
			"example.com",
		},
		{
			"asterisk form",
			"OPTIONS * HTTP/1.1\r\nHost: example.com\r\n\r\n",
			"example.com",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			host, err := ExtractHTTPHost(strings.NewReader(test.request))
			if err != nil {
				t.Fatalf("ExtractHTTPHost returned error: %v", err)
			}
			if host != test.want {
				t.Errorf("host = %q, want %q", host, test.want)
			}
		})
	}
}

func TestExtractHTTPHostStripsPort(t *testing.T) {
	tests := []struct {
		name string
		host string
		want string
	}{
		{"no port", "example.com", "example.com"},
		{"with port", "example.com:8080", "example.com"},
		{"ipv4", "192.0.2.1", "192.0.2.1"},
		{"ipv4 with port", "192.0.2.1:8080", "192.0.2.1"},
		{"ipv6", "[2001:db8::1]", "2001:db8::1"},
		{"ipv6 with port", "[2001:db8::1]:8080", "2001:db8::1"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := "GET / HTTP/1.1\r\nHost: " + test.host + "\r\n\r\n"
			host, err := ExtractHTTPHost(strings.NewReader(request))
			if err != nil {
				t.Fatalf("ExtractHTTPHost returned error: %v", err)
			}
			if host != test.want {
				t.Errorf("host = %q, want %q", host, test.want)
			}
		})
	}
}

func TestExtractHTTPHostHeaderNameIsCaseInsensitive(t *testing.T) {
	for _, name := range []string{"Host", "host", "HOST", "hOsT"} {
		t.Run(name, func(t *testing.T) {
			request := "GET / HTTP/1.1\r\n" + name + ": example.com\r\n\r\n"
			host, err := ExtractHTTPHost(strings.NewReader(request))
			if err != nil {
				t.Fatalf("ExtractHTTPHost returned error: %v", err)
			}
			if host != "example.com" {
				t.Errorf("host = %q, want %q", host, "example.com")
			}
		})
	}
}

func TestExtractHTTPHostMethods(t *testing.T) {
	for _, method := range []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "TRACE"} {
		t.Run(method, func(t *testing.T) {
			request := method + " / HTTP/1.1\r\nHost: example.com\r\n\r\n"
			host, err := ExtractHTTPHost(strings.NewReader(request))
			if err != nil {
				t.Fatalf("ExtractHTTPHost returned error: %v", err)
			}
			if host != "example.com" {
				t.Errorf("host = %q, want %q", host, "example.com")
			}
		})
	}
}

func TestExtractHTTPHostWithManyHeaders(t *testing.T) {
	var request strings.Builder
	request.WriteString("GET / HTTP/1.1\r\nHost: example.com\r\n")
	for i := 0; i < 200; i++ {
		request.WriteString("X-Padding: " + strings.Repeat("a", 64) + "\r\n")
	}
	request.WriteString("\r\n")

	host, err := ExtractHTTPHost(strings.NewReader(request.String()))
	if err != nil {
		t.Fatalf("ExtractHTTPHost returned error: %v", err)
	}
	if host != "example.com" {
		t.Errorf("host = %q, want %q", host, "example.com")
	}
}

func TestExtractHTTPHostWithHeaderLargerThanReadBuffer(t *testing.T) {
	request := "GET / HTTP/1.1\r\nHost: example.com\r\nX-Padding: " +
		strings.Repeat("a", 1<<20) + "\r\n\r\n"

	host, err := ExtractHTTPHost(strings.NewReader(request))
	if err != nil {
		t.Fatalf("ExtractHTTPHost returned error: %v", err)
	}
	if host != "example.com" {
		t.Errorf("host = %q, want %q", host, "example.com")
	}
}

func TestExtractHTTPHostFromSlowReader(t *testing.T) {
	request := "GET / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello"

	host, err := ExtractHTTPHost(iotest.OneByteReader(strings.NewReader(request)))
	if err != nil {
		t.Fatalf("ExtractHTTPHost returned error: %v", err)
	}
	if host != "example.com" {
		t.Errorf("host = %q, want %q", host, "example.com")
	}
}

func TestExtractHTTPHostWithoutUsableHost(t *testing.T) {
	tests := []struct {
		name    string
		request string
	}{
		{"HTTP/1.0 without host header", "GET / HTTP/1.0\r\n\r\n"},
		{"HTTP/1.1 without host header", "GET / HTTP/1.1\r\n\r\n"},
		{"empty host header", "GET / HTTP/1.0\r\nHost: \r\n\r\n"},
		{"duplicate host header", "GET / HTTP/1.1\r\nHost: a.example.com\r\nHost: b.example.com\r\n\r\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			host, err := ExtractHTTPHost(strings.NewReader(test.request))
			if err != nil {
				t.Fatalf("ExtractHTTPHost returned error: %v", err)
			}
			if host != "" {
				t.Errorf("host = %q, want %q", host, "")
			}
		})
	}
}

func TestExtractHTTPHostWithMalformedRequest(t *testing.T) {
	tests := []struct {
		name    string
		request string
	}{
		{"request line without version", "GET /\r\nHost: example.com\r\n\r\n"},
		{"request line with one field", "GET\r\nHost: example.com\r\n\r\n"},
		{"unparsable version", "GET / HTTP/x.y\r\nHost: example.com\r\n\r\n"},
		{"version without slash", "GET / HTTP1.1\r\nHost: example.com\r\n\r\n"},
		{"invalid method", "G\x00T / HTTP/1.1\r\nHost: example.com\r\n\r\n"},
		{"invalid request target", "GET ht\x00tp://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"},
		{"malformed header line", "GET / HTTP/1.1\r\nHost example.com\r\n\r\n"},
		{"binary garbage", "\x00\x01\x02\x03 not http at all\r\n\r\n"},
		{"tls client hello", string(versionHello(t, tls.VersionTLS12, "example.com"))},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			host, err := ExtractHTTPHost(strings.NewReader(test.request))
			if err != nil {
				t.Fatalf("ExtractHTTPHost returned error: %v", err)
			}
			if host != "" {
				t.Errorf("host = %q, want %q", host, "")
			}
		})
	}
}

func TestExtractHTTPHostReportsUnderlyingError(t *testing.T) {
	host, err := ExtractHTTPHost(errReader{err: errBoom})
	if !errors.Is(err, errBoom) {
		t.Fatalf("error = %v, want %v", err, errBoom)
	}
	if host != "" {
		t.Errorf("host = %q, want %q", host, "")
	}
}

func TestExtractHTTPHostReportsUnderlyingErrorAfterPartialRequest(t *testing.T) {
	partial := strings.NewReader("GET / HTTP/1.1\r\nHost: exa")

	host, err := ExtractHTTPHost(io.MultiReader(partial, errReader{err: errBoom}))
	if !errors.Is(err, errBoom) {
		t.Fatalf("error = %v, want %v", err, errBoom)
	}
	if host != "" {
		t.Errorf("host = %q, want %q", host, "")
	}
}

func TestExtractHTTPHostIgnoresUnderlyingErrorAfterCompleteRequest(t *testing.T) {
	complete := strings.NewReader("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")

	host, err := ExtractHTTPHost(io.MultiReader(complete, errReader{err: errBoom}))
	if err != nil {
		t.Fatalf("ExtractHTTPHost returned error: %v", err)
	}
	if host != "example.com" {
		t.Errorf("host = %q, want %q", host, "example.com")
	}
}

func TestExtractHTTPHostWithTruncatedRequest(t *testing.T) {
	tests := []struct {
		name    string
		request string
	}{
		{"empty", ""},
		{"partial request line", "GET / HT"},
		{"request line only", "GET / HTTP/1.1\r\n"},
		{"partial header", "GET / HTTP/1.1\r\nHost: exa"},
		{"headers not terminated", "GET / HTTP/1.1\r\nHost: example.com\r\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			host, err := ExtractHTTPHost(strings.NewReader(test.request))
			if !errors.Is(err, io.EOF) {
				t.Fatalf("error = %v, want %v", err, io.EOF)
			}
			if host != "" {
				t.Errorf("host = %q, want %q", host, "")
			}
		})
	}
}

func TestExtractHTTPHostWithDataAndEOFFromSameRead(t *testing.T) {
	request := strings.NewReader("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")

	host, err := ExtractHTTPHost(iotest.DataErrReader(request))
	if !errors.Is(err, io.EOF) {
		t.Fatalf("error = %v, want %v", err, io.EOF)
	}
	if host != "" {
		t.Errorf("host = %q, want %q", host, "")
	}
}

func TestExtractSNIVersions(t *testing.T) {
	tests := []struct {
		name    string
		version uint16
	}{
		{"TLS 1.0", tls.VersionTLS10},
		{"TLS 1.1", tls.VersionTLS11},
		{"TLS 1.2", tls.VersionTLS12},
		{"TLS 1.3", tls.VersionTLS13},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			hello := versionHello(t, test.version, "example.com")
			sni, err := ExtractSNI(bytes.NewReader(hello))
			if err != nil {
				t.Fatalf("ExtractSNI returned error: %v", err)
			}
			if sni != "example.com" {
				t.Errorf("sni = %q, want %q", sni, "example.com")
			}
		})
	}
}

func TestExtractSNIFromRealOpenSSLClientHello(t *testing.T) {
	hello := decodeHello(t, tls10ClientHelloOpenSSL)

	sni, err := ExtractSNI(bytes.NewReader(hello))
	if err != nil {
		t.Fatalf("ExtractSNI returned error: %v", err)
	}
	if sni != "example.com" {
		t.Errorf("sni = %q, want %q", sni, "example.com")
	}
}

func TestExtractSNIServerNames(t *testing.T) {
	names := []string{
		"example.com",
		"a.b.c.d.e.example.com",
		"xn--bcher-kva.example.com",
		strings.Repeat("a", 63) + ".example.com",
		"host-with-dashes.example.com",
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			hello := versionHello(t, tls.VersionTLS13, name)
			sni, err := ExtractSNI(bytes.NewReader(hello))
			if err != nil {
				t.Fatalf("ExtractSNI returned error: %v", err)
			}
			if sni != name {
				t.Errorf("sni = %q, want %q", sni, name)
			}
		})
	}
}

func TestExtractSNIFromSlowReader(t *testing.T) {
	hello := versionHello(t, tls.VersionTLS13, "example.com")

	sni, err := ExtractSNI(iotest.OneByteReader(bytes.NewReader(hello)))
	if err != nil {
		t.Fatalf("ExtractSNI returned error: %v", err)
	}
	if sni != "example.com" {
		t.Errorf("sni = %q, want %q", sni, "example.com")
	}
}

func TestExtractSNIIgnoresTrailingRecords(t *testing.T) {
	hello := versionHello(t, tls.VersionTLS12, "example.com")
	trailing := []byte{0x17, 0x03, 0x03, 0x00, 0x05, 'h', 'e', 'l', 'l', 'o'}

	sni, err := ExtractSNI(bytes.NewReader(append(hello, trailing...)))
	if err != nil {
		t.Fatalf("ExtractSNI returned error: %v", err)
	}
	if sni != "example.com" {
		t.Errorf("sni = %q, want %q", sni, "example.com")
	}
}

func TestExtractSNIWithoutServerNameExtension(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{
			"server name unset",
			clientHello(t, &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS12,
				MaxVersion:         tls.VersionTLS12,
			}),
		},
		{
			"server name is an ipv4 address",
			clientHello(t, &tls.Config{
				ServerName: "192.0.2.1",
				MinVersion: tls.VersionTLS12,
				MaxVersion: tls.VersionTLS12,
			}),
		},
		{
			"server name is an ipv6 address",
			clientHello(t, &tls.Config{
				ServerName: "2001:db8::1",
				MinVersion: tls.VersionTLS12,
				MaxVersion: tls.VersionTLS12,
			}),
		},
		{
			"ssl 3.0 has no extensions",
			decodeHello(t, ssl30ClientHello),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sni, err := ExtractSNI(bytes.NewReader(test.input))
			if err != nil {
				t.Fatalf("ExtractSNI returned error: %v", err)
			}
			if sni != "" {
				t.Errorf("sni = %q, want %q", sni, "")
			}
		})
	}
}

func TestExtractSNIWithMalformedHandshake(t *testing.T) {
	hello := versionHello(t, tls.VersionTLS12, "example.com")

	notClientHello := append([]byte(nil), hello...)
	notClientHello[5] = 0x02

	tests := []struct {
		name  string
		input []byte
	}{
		{"http request", []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")},
		{"sslv2 client hello", decodeHello(t, sslv2ClientHello)},
		{"server hello handshake type", notClientHello},
		{"alert record", []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28}},
		{"record length too large", []byte{0x16, 0x03, 0x01, 0xff, 0xff, 0x01, 0x00, 0x00, 0x00}},
		{"unknown record type", append(
			[]byte{0xff, 0x03, 0x03, 0x00, 0x05},
			bytes.Repeat([]byte{0x00}, 32)...,
		)},
		{"client hello with empty body", []byte{0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sni, err := ExtractSNI(bytes.NewReader(test.input))
			if err != nil {
				t.Fatalf("ExtractSNI returned error: %v", err)
			}
			if sni != "" {
				t.Errorf("sni = %q, want %q", sni, "")
			}
		})
	}
}

func TestExtractSNIReportsUnderlyingError(t *testing.T) {
	sni, err := ExtractSNI(errReader{err: errBoom})
	if !errors.Is(err, errBoom) {
		t.Fatalf("error = %v, want %v", err, errBoom)
	}
	if sni != "" {
		t.Errorf("sni = %q, want %q", sni, "")
	}
}

func TestExtractSNIReportsUnderlyingErrorAfterPartialHello(t *testing.T) {
	hello := versionHello(t, tls.VersionTLS12, "example.com")
	partial := bytes.NewReader(hello[:len(hello)/2])

	sni, err := ExtractSNI(io.MultiReader(partial, errReader{err: errBoom}))
	if !errors.Is(err, errBoom) {
		t.Fatalf("error = %v, want %v", err, errBoom)
	}
	if sni != "" {
		t.Errorf("sni = %q, want %q", sni, "")
	}
}

func TestExtractSNIIgnoresUnderlyingErrorAfterCompleteHello(t *testing.T) {
	hello := versionHello(t, tls.VersionTLS12, "example.com")

	sni, err := ExtractSNI(io.MultiReader(bytes.NewReader(hello), errReader{err: errBoom}))
	if err != nil {
		t.Fatalf("ExtractSNI returned error: %v", err)
	}
	if sni != "example.com" {
		t.Errorf("sni = %q, want %q", sni, "example.com")
	}
}

func TestExtractSNIWithTruncatedHello(t *testing.T) {
	hello := versionHello(t, tls.VersionTLS12, "example.com")
	tests := []struct {
		name  string
		input []byte
	}{
		{"empty", nil},
		{"partial record header", hello[:3]},
		{"record header only", hello[:5]},
		{"partial handshake body", hello[:len(hello)/2]},
		{"one byte short", hello[:len(hello)-1]},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sni, err := ExtractSNI(bytes.NewReader(test.input))
			if !errors.Is(err, io.EOF) {
				t.Fatalf("error = %v, want %v", err, io.EOF)
			}
			if sni != "" {
				t.Errorf("sni = %q, want %q", sni, "")
			}
		})
	}
}

func TestExtractSNIWithDataAndEOFFromSameRead(t *testing.T) {
	hello := versionHello(t, tls.VersionTLS12, "example.com")

	sni, err := ExtractSNI(iotest.DataErrReader(bytes.NewReader(hello)))
	if !errors.Is(err, io.EOF) {
		t.Fatalf("error = %v, want %v", err, io.EOF)
	}
	if sni != "" {
		t.Errorf("sni = %q, want %q", sni, "")
	}
}
