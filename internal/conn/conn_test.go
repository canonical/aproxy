package conn

import (
	"bytes"
	"errors"
	"io"
	stdnet "net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

const testTimeout = 10 * time.Second

type observation struct {
	n   int
	err error
}

type fakeMetrics struct {
	mu     sync.Mutex
	reads  []observation
	writes []observation
}

func (m *fakeMetrics) ObserveRead(n int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reads = append(m.reads, observation{n: n, err: err})
}

func (m *fakeMetrics) ObserveWrite(n int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.writes = append(m.writes, observation{n: n, err: err})
}

func (m *fakeMetrics) readCalls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.reads)
}

func (m *fakeMetrics) writeCalls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.writes)
}

func (m *fakeMetrics) bytesRead() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	total := 0
	for _, o := range m.reads {
		total += o.n
	}
	return total
}

func (m *fakeMetrics) bytesWritten() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	total := 0
	for _, o := range m.writes {
		total += o.n
	}
	return total
}

func tcpPair(t *testing.T) (local, peer *stdnet.TCPConn) {
	t.Helper()
	listener, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	type accepted struct {
		conn stdnet.Conn
		err  error
	}
	accepts := make(chan accepted, 1)
	go func() {
		conn, err := listener.Accept()
		accepts <- accepted{conn: conn, err: err}
	}()

	dialed, err := stdnet.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	result := <-accepts
	if result.err != nil {
		dialed.Close()
		t.Fatalf("accept: %v", result.err)
	}

	local = dialed.(*stdnet.TCPConn)
	peer = result.conn.(*stdnet.TCPConn)
	t.Cleanup(func() {
		local.Close()
		peer.Close()
	})
	if err := local.SetDeadline(time.Now().Add(testTimeout)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	return local, peer
}

func newTestConn(t *testing.T, options ...Option) (*Conn, *stdnet.TCPConn, *fakeMetrics) {
	t.Helper()
	local, peer := tcpPair(t)
	metrics := &fakeMetrics{}
	options = append([]Option{WithMetrics(metrics)}, options...)
	return New(local, options...), peer, metrics
}

func feed(t *testing.T, peer *stdnet.TCPConn, data []byte) {
	t.Helper()
	if _, err := peer.Write(data); err != nil {
		t.Fatalf("feed peer: %v", err)
	}
}

func feedAsync(peer *stdnet.TCPConn, chunks ...[]byte) <-chan error {
	done := make(chan error, 1)
	go func() {
		for _, chunk := range chunks {
			if _, err := peer.Write(chunk); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	return done
}

func drain(t *testing.T, c *Conn, want int) []byte {
	t.Helper()
	out := make([]byte, 0, want)
	buf := make([]byte, want)
	for len(out) < want {
		n, err := c.Read(buf[:want-len(out)])
		if err != nil {
			t.Fatalf("drain: read after %d/%d bytes: %v", len(out), want, err)
		}
		if n == 0 {
			t.Fatalf("drain: read returned 0 bytes without error")
		}
		out = append(out, buf[:n]...)
	}
	return out
}

func forbidSocketRead(t *testing.T, c *Conn) {
	t.Helper()
	if err := c.SetReadDeadline(time.Now().Add(-time.Hour)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
}

func allowSocketRead(t *testing.T, c *Conn) {
	t.Helper()
	if err := c.SetReadDeadline(time.Now().Add(testTimeout)); err != nil {
		t.Fatalf("reset read deadline: %v", err)
	}
}

func mustPanic(t *testing.T, want string, fn func()) {
	t.Helper()
	defer func() {
		r := recover()
		if r == nil {
			t.Fatalf("expected panic containing %q, got none", want)
		}
		msg, ok := r.(string)
		if !ok || !strings.Contains(msg, want) {
			t.Fatalf("expected panic containing %q, got %v", want, r)
		}
	}()
	fn()
}

func repeat(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte('a' + i%26)
	}
	return out
}

func TestReadDuringPrereadBuffersData(t *testing.T) {
	conn, peer, metrics := newTestConn(t)
	payload := []byte("hello world")
	feed(t, peer, payload)

	got := drain(t, conn, len(payload))
	if !bytes.Equal(got, payload) {
		t.Fatalf("got %q, want %q", got, payload)
	}
	if !bytes.Equal(conn.prereadBuf, payload) {
		t.Fatalf("prereadBuf = %q, want %q", conn.prereadBuf, payload)
	}
	if conn.prereadCursor != len(payload) {
		t.Fatalf("prereadCursor = %d, want %d", conn.prereadCursor, len(payload))
	}
	if metrics.bytesRead() != len(payload) {
		t.Fatalf("metrics observed %d bytes, want %d", metrics.bytesRead(), len(payload))
	}
}

func TestReadDuringPrereadAccumulatesAcrossCalls(t *testing.T) {
	conn, peer, _ := newTestConn(t)
	feed(t, peer, []byte("first"))
	drain(t, conn, len("first"))
	feed(t, peer, []byte("second"))
	drain(t, conn, len("second"))

	want := "firstsecond"
	if string(conn.prereadBuf) != want {
		t.Fatalf("prereadBuf = %q, want %q", conn.prereadBuf, want)
	}
	if conn.prereadCursor != len(want) {
		t.Fatalf("prereadCursor = %d, want %d", conn.prereadCursor, len(want))
	}
}

func TestReadTruncatesToRemainingPrereadLimit(t *testing.T) {
	conn, peer, _ := newTestConn(t, WithPrereadLimit(3))
	feed(t, peer, []byte("0123456789"))

	got := drain(t, conn, 3)
	if string(got) != "012" {
		t.Fatalf("got %q, want %q", got, "012")
	}
	if _, err := conn.Read(make([]byte, 16)); !errors.Is(err, ErrPrereadLimitExceeded) {
		t.Fatalf("err = %v, want ErrPrereadLimitExceeded", err)
	}
}

func TestReadSingleCallNeverExceedsLimit(t *testing.T) {
	conn, peer, _ := newTestConn(t, WithPrereadLimit(4))
	feed(t, peer, repeat(64))

	n, err := conn.Read(make([]byte, 64))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if n > 4 {
		t.Fatalf("read returned %d bytes, must not exceed limit 4", n)
	}
}

func TestReadPrereadLimitExceededIsSticky(t *testing.T) {
	conn, peer, metrics := newTestConn(t, WithPrereadLimit(2))
	feed(t, peer, []byte("abcdef"))
	drain(t, conn, 2)

	before := metrics.readCalls()
	bufSnapshot := string(conn.prereadBuf)
	for i := range 3 {
		n, err := conn.Read(make([]byte, 8))
		if !errors.Is(err, ErrPrereadLimitExceeded) {
			t.Fatalf("attempt %d: err = %v, want ErrPrereadLimitExceeded", i, err)
		}
		if n != 0 {
			t.Fatalf("attempt %d: n = %d, want 0", i, n)
		}
	}
	if metrics.readCalls() != before {
		t.Fatalf("socket was read %d extra times", metrics.readCalls()-before)
	}
	if string(conn.prereadBuf) != bufSnapshot {
		t.Fatalf("prereadBuf mutated: %q, want %q", conn.prereadBuf, bufSnapshot)
	}
	if conn.prereadCursor != 2 {
		t.Fatalf("prereadCursor = %d, want 2", conn.prereadCursor)
	}
}

func TestReadPrereadLimitExactBoundary(t *testing.T) {
	const limit = 8
	conn, peer, _ := newTestConn(t, WithPrereadLimit(limit))
	feed(t, peer, repeat(limit))

	got := drain(t, conn, limit)
	if len(got) != limit {
		t.Fatalf("read %d bytes, want %d", len(got), limit)
	}
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, ErrPrereadLimitExceeded) {
		t.Fatalf("err = %v, want ErrPrereadLimitExceeded", err)
	}
}

func TestReadEOFDuringPreread(t *testing.T) {
	conn, peer, metrics := newTestConn(t)
	peer.Close()

	n, err := conn.Read(make([]byte, 8))
	if !errors.Is(err, io.EOF) {
		t.Fatalf("err = %v, want io.EOF", err)
	}
	if n != 0 {
		t.Fatalf("n = %d, want 0", n)
	}
	if conn.prereadBuf != nil && len(conn.prereadBuf) != 0 {
		t.Fatalf("prereadBuf = %q, want empty", conn.prereadBuf)
	}
	if metrics.readCalls() != 1 {
		t.Fatalf("metrics read calls = %d, want 1", metrics.readCalls())
	}
}

func TestReadEOFIsRepeatable(t *testing.T) {
	conn, peer, metrics := newTestConn(t)
	peer.Close()

	for i := range 3 {
		n, err := conn.Read(make([]byte, 8))
		if n != 0 || !errors.Is(err, io.EOF) {
			t.Fatalf("attempt %d: (%d, %v), want (0, io.EOF)", i, n, err)
		}
	}
	if metrics.readCalls() != 3 {
		t.Fatalf("socket read calls = %d, want 3", metrics.readCalls())
	}
}

func TestEOFDoesNotPoisonPrereadBuffer(t *testing.T) {
	conn, peer, _ := newTestConn(t)
	feed(t, peer, []byte("abc"))
	drain(t, conn, 3)
	peer.Close()

	if _, err := conn.Read(make([]byte, 8)); !errors.Is(err, io.EOF) {
		t.Fatalf("err = %v, want io.EOF", err)
	}
	conn.Rewind()
	forbidSocketRead(t, conn)
	got := make([]byte, 8)
	n, err := conn.Read(got)
	if err != nil || string(got[:n]) != "abc" {
		t.Fatalf("replay after EOF = (%q, %v), want (\"abc\", nil)", got[:n], err)
	}
}

func TestBufferReleasedWhenReplayEndsAtEOF(t *testing.T) {
	conn, peer, _ := newTestConn(t)
	feed(t, peer, []byte("abc"))
	drain(t, conn, 3)
	peer.Close()
	conn.EndPreread()

	got := make([]byte, 8)
	n, err := conn.Read(got)
	if err != nil || string(got[:n]) != "abc" {
		t.Fatalf("replay = (%q, %v), want (\"abc\", nil)", got[:n], err)
	}
	if _, err := conn.Read(got); !errors.Is(err, io.EOF) {
		t.Fatalf("err = %v, want io.EOF", err)
	}
	if conn.prereadBuf != nil || conn.prereadCursor != 0 {
		t.Fatalf("buffer not released: buf=%q cursor=%d", conn.prereadBuf, conn.prereadCursor)
	}
}

func TestPrereadLimitMasksEOF(t *testing.T) {
	conn, peer, _ := newTestConn(t, WithPrereadLimit(3))
	feed(t, peer, []byte("abc"))
	drain(t, conn, 3)
	peer.Close()

	if _, err := conn.Read(make([]byte, 8)); !errors.Is(err, ErrPrereadLimitExceeded) {
		t.Fatalf("err = %v, want ErrPrereadLimitExceeded", err)
	}
	conn.EndPreread()
	drain(t, conn, 3)
	if _, err := conn.Read(make([]byte, 8)); !errors.Is(err, io.EOF) {
		t.Fatalf("err = %v, want io.EOF once the limit no longer applies", err)
	}
}

func TestZeroLengthReadCannotDetectEOF(t *testing.T) {
	conn, peer, _ := newTestConn(t)
	conn.EndPreread()
	peer.Close()

	if n, err := conn.Read(nil); n != 0 || err != nil {
		t.Fatalf("Read(nil) = (%d, %v), want (0, nil) even at EOF", n, err)
	}
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("sized read err = %v, want io.EOF", err)
	}
}

func settle() {
	time.Sleep(100 * time.Millisecond)
}

func TestReadStraddlesPrereadLimitInOneCall(t *testing.T) {
	conn, peer, _ := newTestConn(t, WithPrereadLimit(4))
	feed(t, peer, []byte("0123456789"))
	settle()

	got := make([]byte, 64)
	n, err := conn.Read(got)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if n != 4 || string(got[:n]) != "0123" {
		t.Fatalf("read = (%d, %q), want (4, \"0123\")", n, got[:n])
	}
	if _, err := conn.Read(got); !errors.Is(err, ErrPrereadLimitExceeded) {
		t.Fatalf("err = %v, want ErrPrereadLimitExceeded", err)
	}

	conn.EndPreread()
	if replayed := drain(t, conn, 4); string(replayed) != "0123" {
		t.Fatalf("replay = %q, want %q", replayed, "0123")
	}
	if rest := drain(t, conn, 6); string(rest) != "456789" {
		t.Fatalf("remainder = %q, want %q", rest, "456789")
	}
}

func TestReadStraddlesPrereadLimitAcrossCalls(t *testing.T) {
	const limit = 10
	conn, peer, _ := newTestConn(t, WithPrereadLimit(limit))
	feed(t, peer, []byte("abcdefghijKLMNOP"))
	settle()

	var got []byte
	buf := make([]byte, 4)
	for range 3 {
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("read after %d bytes: %v", len(got), err)
		}
		if remaining := limit - len(got); n > remaining {
			t.Fatalf("read %d bytes with only %d left under the limit", n, remaining)
		}
		got = append(got, buf[:n]...)
	}
	if string(got) != "abcdefghij" {
		t.Fatalf("preread = %q, want %q", got, "abcdefghij")
	}
	if _, err := conn.Read(buf); !errors.Is(err, ErrPrereadLimitExceeded) {
		t.Fatalf("err = %v, want ErrPrereadLimitExceeded", err)
	}
	conn.EndPreread()
	if rest := drain(t, conn, 16); string(rest) != "abcdefghijKLMNOP" {
		t.Fatalf("full stream = %q, want %q", rest, "abcdefghijKLMNOP")
	}
}

func TestReadStraddlesReplayAndSocket(t *testing.T) {
	conn, peer, metrics := newTestConn(t)
	feed(t, peer, []byte("HEADER"))
	drain(t, conn, 6)
	conn.EndPreread()

	feed(t, peer, []byte("BODYBODY"))
	settle()

	socketReads := metrics.readCalls()
	got := make([]byte, 64)
	n, err := conn.Read(got)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if n != 6 || string(got[:n]) != "HEADER" {
		t.Fatalf("read = (%d, %q), want (6, \"HEADER\") with no socket bytes mixed in", n, got[:n])
	}
	if metrics.readCalls() != socketReads {
		t.Fatalf("replay call also touched the socket")
	}

	n, err = conn.Read(got)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if n != 8 || string(got[:n]) != "BODYBODY" {
		t.Fatalf("read = (%d, %q), want (8, \"BODYBODY\")", n, got[:n])
	}
}

func TestReadStraddlesReplayWithSmallerCallerBuffer(t *testing.T) {
	conn, peer, _ := newTestConn(t)
	feed(t, peer, []byte("HEADER"))
	drain(t, conn, 6)
	conn.EndPreread()
	feed(t, peer, []byte("BODY"))
	settle()

	buf := make([]byte, 4)
	n, err := conn.Read(buf)
	if err != nil || n != 4 || string(buf[:n]) != "HEAD" {
		t.Fatalf("read = (%d, %q, %v), want (4, \"HEAD\", nil)", n, buf[:n], err)
	}
	n, err = conn.Read(buf)
	if err != nil || n != 2 || string(buf[:n]) != "ER" {
		t.Fatalf("read = (%d, %q, %v), want (2, \"ER\", nil)", n, buf[:n], err)
	}
	n, err = conn.Read(buf)
	if err != nil || n != 4 || string(buf[:n]) != "BODY" {
		t.Fatalf("read = (%d, %q, %v), want (4, \"BODY\", nil)", n, buf[:n], err)
	}
}

func TestReadStraddlesReplayAndLimitTogether(t *testing.T) {
	const limit = 6
	conn, peer, _ := newTestConn(t, WithPrereadLimit(limit))
	feed(t, peer, []byte("abcdWXYZ"))
	settle()

	first := drain(t, conn, 4)
	if string(first) != "abcd" {
		t.Fatalf("preread = %q, want %q", first, "abcd")
	}

	conn.Rewind()
	got := make([]byte, 64)
	n, err := conn.Read(got)
	if err != nil || n != 4 || string(got[:n]) != "abcd" {
		t.Fatalf("replay = (%d, %q, %v), want (4, \"abcd\", nil)", n, got[:n], err)
	}

	n, err = conn.Read(got)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if n != limit-4 || string(got[:n]) != "WX" {
		t.Fatalf("read = (%d, %q), want (2, \"WX\")", n, got[:n])
	}
	if _, err := conn.Read(got); !errors.Is(err, ErrPrereadLimitExceeded) {
		t.Fatalf("err = %v, want ErrPrereadLimitExceeded", err)
	}

	conn.EndPreread()
	if rest := drain(t, conn, 8); string(rest) != "abcdWXYZ" {
		t.Fatalf("full stream = %q, want %q", rest, "abcdWXYZ")
	}
}

func TestPrereadStraddleInvariants(t *testing.T) {
	payload := repeat(64)
	cases := []struct {
		name     string
		limit    int
		readSize int
	}{
		{"read-larger-than-limit", 5, 64},
		{"limit-not-multiple-of-read", 10, 4},
		{"read-not-multiple-of-limit", 7, 5},
		{"single-byte-limit", 1, 16},
		{"single-byte-reads", 9, 1},
		{"limit-just-under-payload", 63, 16},
		{"limit-equals-payload", 64, 10},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			local, peer := tcpPair(t)
			conn := New(local, WithPrereadLimit(tc.limit))
			go func() {
				<-feedAsync(peer, payload)
				peer.Close()
			}()

			consumed := 0
			buf := make([]byte, tc.readSize)
			for {
				n, err := conn.Read(buf)
				if errors.Is(err, ErrPrereadLimitExceeded) {
					break
				}
				if err != nil {
					t.Fatalf("read after %d bytes: %v", consumed, err)
				}
				if remaining := tc.limit - consumed; n > remaining {
					t.Fatalf("read %d bytes with only %d left under the limit", n, remaining)
				}
				consumed += n
			}
			if consumed != tc.limit {
				t.Fatalf("preread consumed %d bytes, want exactly %d", consumed, tc.limit)
			}

			conn.EndPreread()
			full, err := io.ReadAll(conn)
			if err != nil {
				t.Fatalf("read all: %v", err)
			}
			if !bytes.Equal(full, payload) {
				t.Fatalf("stream corrupted at the limit boundary: got %d bytes, want %d",
					len(full), len(payload))
			}
		})
	}
}

func TestZeroLengthReadDuringPrereadSkipsSocket(t *testing.T) {
	conn, _, metrics := newTestConn(t)
	forbidSocketRead(t, conn)

	n, err := conn.Read(nil)
	if n != 0 || err != nil {
		t.Fatalf("Read(nil) = (%d, %v), want (0, nil)", n, err)
	}
	n, err = conn.Read(make([]byte, 0))
	if n != 0 || err != nil {
		t.Fatalf("Read(empty) = (%d, %v), want (0, nil)", n, err)
	}
	if metrics.readCalls() != 0 {
		t.Fatalf("socket was read %d times, want 0", metrics.readCalls())
	}
}

func TestZeroLengthReadDuringPrereadIgnoresExhaustedLimit(t *testing.T) {
	conn, peer, _ := newTestConn(t, WithPrereadLimit(2))
	feed(t, peer, []byte("ab"))
	drain(t, conn, 2)

	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, ErrPrereadLimitExceeded) {
		t.Fatalf("err = %v, want ErrPrereadLimitExceeded", err)
	}
	if n, err := conn.Read(nil); n != 0 || err != nil {
		t.Fatalf("Read(nil) = (%d, %v), want (0, nil)", n, err)
	}
}

func TestZeroLengthReadAfterPrereadReachesSocket(t *testing.T) {
	conn, _, metrics := newTestConn(t)
	conn.EndPreread()

	n, err := conn.Read(nil)
	if n != 0 || err != nil {
		t.Fatalf("Read(nil) = (%d, %v), want (0, nil)", n, err)
	}
	if metrics.readCalls() != 1 {
		t.Fatalf("socket read calls = %d, want 1", metrics.readCalls())
	}
}

func TestZeroLengthReadAfterPrereadDetectsLocalClose(t *testing.T) {
	conn, _, _ := newTestConn(t)
	conn.EndPreread()
	if err := conn.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	_, err := conn.Read(nil)
	if !errors.Is(err, stdnet.ErrClosed) {
		t.Fatalf("err = %v, want net.ErrClosed", err)
	}
}

func TestZeroLengthReadAfterPrereadDoesNotConsumeReplay(t *testing.T) {
	conn, peer, _ := newTestConn(t)
	feed(t, peer, []byte("keepme"))
	drain(t, conn, 6)
	conn.EndPreread()

	if n, err := conn.Read(nil); n != 0 || err != nil {
		t.Fatalf("Read(nil) = (%d, %v), want (0, nil)", n, err)
	}
	if conn.prereadCursor != 0 {
		t.Fatalf("prereadCursor = %d, want 0", conn.prereadCursor)
	}
	forbidSocketRead(t, conn)
	got := make([]byte, 6)
	n, err := conn.Read(got)
	if err != nil || n != 6 || string(got) != "keepme" {
		t.Fatalf("replay = (%d, %q, %v), want (6, \"keepme\", nil)", n, got[:n], err)
	}
}

func TestRewindReplaysWithoutTouchingSocket(t *testing.T) {
	conn, peer, metrics := newTestConn(t)
	payload := []byte("replay-me")
	feed(t, peer, payload)
	drain(t, conn, len(payload))

	socketReads := metrics.readCalls()
	conn.Rewind()
	forbidSocketRead(t, conn)

	got := make([]byte, len(payload))
	n, err := conn.Read(got)
	if err != nil {
		t.Fatalf("replay read: %v", err)
	}
	if n != len(payload) || !bytes.Equal(got[:n], payload) {
		t.Fatalf("replay = (%d, %q), want (%d, %q)", n, got[:n], len(payload), payload)
	}
	if metrics.readCalls() != socketReads {
		t.Fatalf("replay hit the socket %d times", metrics.readCalls()-socketReads)
	}
}

func TestRewindReplaysInChunks(t *testing.T) {
	conn, peer, _ := newTestConn(t)
	payload := []byte("abcdefgh")
	feed(t, peer, payload)
	drain(t, conn, len(payload))

	conn.Rewind()
	forbidSocketRead(t, conn)

	var got []byte
	buf := make([]byte, 3)
	for range 3 {
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("chunked replay: %v", err)
		}
		got = append(got, buf[:n]...)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("chunked replay = %q, want %q", got, payload)
	}
}

func TestRewindReplayIsShortAndNeverCombinesWithSocket(t *testing.T) {
	conn, peer, metrics := newTestConn(t)
	feed(t, peer, []byte("abc"))
	drain(t, conn, 3)

	feed(t, peer, []byte("defghij"))
	time.Sleep(50 * time.Millisecond)

	conn.Rewind()
	socketReads := metrics.readCalls()
	got := make([]byte, 64)
	n, err := conn.Read(got)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if n != 3 || string(got[:n]) != "abc" {
		t.Fatalf("read = (%d, %q), want (3, \"abc\")", n, got[:n])
	}
	if metrics.readCalls() != socketReads {
		t.Fatalf("replay call also read the socket")
	}
	rest := drain(t, conn, 7)
	if string(rest) != "defghij" {
		t.Fatalf("post-replay = %q, want %q", rest, "defghij")
	}
}

func TestRewindThenReadBeyondBufferResumesFromSocket(t *testing.T) {
	conn, peer, _ := newTestConn(t)
	feed(t, peer, []byte("12345"))
	drain(t, conn, 5)
	conn.Rewind()

	replayed := drain(t, conn, 5)
	if string(replayed) != "12345" {
		t.Fatalf("replayed %q, want %q", replayed, "12345")
	}
	feed(t, peer, []byte("67890"))
	fresh := drain(t, conn, 5)
	if string(fresh) != "67890" {
		t.Fatalf("fresh %q, want %q", fresh, "67890")
	}
	if string(conn.prereadBuf) != "1234567890" {
		t.Fatalf("prereadBuf = %q, want %q", conn.prereadBuf, "1234567890")
	}
}

func TestRewindPartialThenAppendKeepsBufferConsistent(t *testing.T) {
	conn, peer, _ := newTestConn(t)
	feed(t, peer, []byte("abcd"))
	drain(t, conn, 4)

	conn.Rewind()
	if got := drain(t, conn, 2); string(got) != "ab" {
		t.Fatalf("partial replay = %q, want %q", got, "ab")
	}
	if got := drain(t, conn, 2); string(got) != "cd" {
		t.Fatalf("rest of replay = %q, want %q", got, "cd")
	}
	feed(t, peer, []byte("ef"))
	if got := drain(t, conn, 2); string(got) != "ef" {
		t.Fatalf("fresh = %q, want %q", got, "ef")
	}
	if string(conn.prereadBuf) != "abcdef" {
		t.Fatalf("prereadBuf = %q, want %q", conn.prereadBuf, "abcdef")
	}
}

func TestRewindTwice(t *testing.T) {
	conn, peer, _ := newTestConn(t)
	feed(t, peer, []byte("xyz"))
	drain(t, conn, 3)

	for range 2 {
		conn.Rewind()
		forbidSocketRead(t, conn)
		got := make([]byte, 3)
		n, err := conn.Read(got)
		if err != nil || string(got[:n]) != "xyz" {
			t.Fatalf("replay = (%q, %v), want (\"xyz\", nil)", got[:n], err)
		}
		allowSocketRead(t, conn)
	}
}

func TestRewindReplayCountsAgainstPrereadLimit(t *testing.T) {
	const limit = 6
	conn, peer, _ := newTestConn(t, WithPrereadLimit(limit))
	feed(t, peer, repeat(limit))
	drain(t, conn, limit)

	conn.Rewind()
	if got := drain(t, conn, limit); len(got) != limit {
		t.Fatalf("replayed %d bytes, want %d", len(got), limit)
	}
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, ErrPrereadLimitExceeded) {
		t.Fatalf("err = %v, want ErrPrereadLimitExceeded", err)
	}
}

func TestRewindOnEmptyBufferIsNoop(t *testing.T) {
	conn, peer, _ := newTestConn(t)
	conn.Rewind()
	feed(t, peer, []byte("ok"))
	if got := drain(t, conn, 2); string(got) != "ok" {
		t.Fatalf("got %q, want %q", got, "ok")
	}
}

func TestRewindAfterEndPrereadPanics(t *testing.T) {
	conn, _, _ := newTestConn(t)
	conn.EndPreread()
	mustPanic(t, "rewind", func() { conn.Rewind() })
}

func TestEndPrereadReplaysFromStartWithoutRewind(t *testing.T) {
	conn, peer, metrics := newTestConn(t)
	payload := []byte("GET / HTTP/1.1\r\n")
	feed(t, peer, payload)
	drain(t, conn, len(payload))

	conn.EndPreread()
	socketReads := metrics.readCalls()
	forbidSocketRead(t, conn)

	got := make([]byte, len(payload))
	n, err := conn.Read(got)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if n != len(payload) || !bytes.Equal(got[:n], payload) {
		t.Fatalf("replay = (%d, %q), want (%d, %q)", n, got[:n], len(payload), payload)
	}
	if metrics.readCalls() != socketReads {
		t.Fatalf("replay after EndPreread hit the socket")
	}
}

func TestEndPrereadIsIdempotent(t *testing.T) {
	conn, peer, _ := newTestConn(t)
	feed(t, peer, []byte("abc"))
	drain(t, conn, 3)

	conn.EndPreread()
	if got := drain(t, conn, 2); string(got) != "ab" {
		t.Fatalf("replay = %q, want %q", got, "ab")
	}
	conn.EndPreread()
	if conn.prereadCursor != 2 {
		t.Fatalf("prereadCursor = %d, want 2", conn.prereadCursor)
	}
	if got := drain(t, conn, 1); string(got) != "c" {
		t.Fatalf("remaining replay = %q, want %q", got, "c")
	}
}

func TestEndPrereadWithoutBufferedData(t *testing.T) {
	conn, peer, _ := newTestConn(t)
	conn.EndPreread()
	feed(t, peer, []byte("direct"))
	if got := drain(t, conn, 6); string(got) != "direct" {
		t.Fatalf("got %q, want %q", got, "direct")
	}
}

func TestBufferReleasedAfterReplayDrained(t *testing.T) {
	conn, peer, _ := newTestConn(t)
	feed(t, peer, []byte("12345"))
	drain(t, conn, 5)
	conn.EndPreread()

	if got := drain(t, conn, 5); string(got) != "12345" {
		t.Fatalf("replay = %q, want %q", got, "12345")
	}
	if conn.prereadBuf == nil {
		t.Fatal("prereadBuf released too early")
	}
	feed(t, peer, []byte("xyz"))
	if got := drain(t, conn, 3); string(got) != "xyz" {
		t.Fatalf("fresh = %q, want %q", got, "xyz")
	}
	if conn.prereadBuf != nil {
		t.Fatalf("prereadBuf = %q, want nil after drain", conn.prereadBuf)
	}
	if conn.prereadCursor != 0 {
		t.Fatalf("prereadCursor = %d, want 0", conn.prereadCursor)
	}
}

func TestReadAfterPrereadIgnoresLimit(t *testing.T) {
	conn, peer, _ := newTestConn(t, WithPrereadLimit(4))
	feed(t, peer, []byte("abcd"))
	drain(t, conn, 4)
	conn.EndPreread()

	if got := drain(t, conn, 4); string(got) != "abcd" {
		t.Fatalf("replay = %q, want %q", got, "abcd")
	}
	payload := repeat(4096)
	fed := feedAsync(peer, payload)
	if got := drain(t, conn, len(payload)); !bytes.Equal(got, payload) {
		t.Fatal("post-preread stream corrupted")
	}
	if err := <-fed; err != nil {
		t.Fatalf("feed: %v", err)
	}
}

func TestReplayPrecedesEOF(t *testing.T) {
	conn, peer, _ := newTestConn(t)
	feed(t, peer, []byte("last"))
	drain(t, conn, 4)
	conn.EndPreread()
	peer.Close()

	got := make([]byte, 64)
	n, err := conn.Read(got)
	if err != nil {
		t.Fatalf("replay must not be lost to EOF: %v", err)
	}
	if string(got[:n]) != "last" {
		t.Fatalf("replay = %q, want %q", got[:n], "last")
	}
	if _, err := conn.Read(got); !errors.Is(err, io.EOF) {
		t.Fatalf("err = %v, want io.EOF", err)
	}
}

func TestStreamIntegrity(t *testing.T) {
	conn, peer, _ := newTestConn(t)
	header := []byte("HEADER:example.com\n")
	body := repeat(8192)

	go func() {
		<-feedAsync(peer, header, body)
		peer.Close()
	}()

	sniffed := drain(t, conn, len(header))
	if !bytes.Equal(sniffed, header) {
		t.Fatalf("sniffed %q, want %q", sniffed, header)
	}
	conn.EndPreread()

	full, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read all: %v", err)
	}
	want := append(append([]byte{}, header...), body...)
	if !bytes.Equal(full, want) {
		t.Fatalf("stream corrupted: got %d bytes, want %d", len(full), len(want))
	}
}

func TestReadFullAcrossReplayBoundary(t *testing.T) {
	conn, peer, _ := newTestConn(t)
	feed(t, peer, []byte("abc"))
	drain(t, conn, 3)
	conn.EndPreread()
	feed(t, peer, []byte("def"))

	got := make([]byte, 6)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read full: %v", err)
	}
	if string(got) != "abcdef" {
		t.Fatalf("got %q, want %q", got, "abcdef")
	}
}

func TestMetricsNotDoubleCountedOnReplay(t *testing.T) {
	conn, peer, metrics := newTestConn(t)
	payload := []byte("counted-once")
	feed(t, peer, payload)
	drain(t, conn, len(payload))

	observed := metrics.bytesRead()
	if observed != len(payload) {
		t.Fatalf("observed %d bytes, want %d", observed, len(payload))
	}
	conn.EndPreread()
	drain(t, conn, len(payload))
	if metrics.bytesRead() != observed {
		t.Fatalf("replay double-counted: %d bytes observed, want %d", metrics.bytesRead(), observed)
	}
}

func TestMetricsObserveErrors(t *testing.T) {
	conn, peer, metrics := newTestConn(t)
	peer.Close()
	if _, err := conn.Read(make([]byte, 4)); !errors.Is(err, io.EOF) {
		t.Fatalf("err = %v, want io.EOF", err)
	}
	metrics.mu.Lock()
	defer metrics.mu.Unlock()
	if len(metrics.reads) != 1 {
		t.Fatalf("read observations = %d, want 1", len(metrics.reads))
	}
	if !errors.Is(metrics.reads[0].err, io.EOF) {
		t.Fatalf("observed err = %v, want io.EOF", metrics.reads[0].err)
	}
}

func TestNilMetricsIsSafe(t *testing.T) {
	local, peer := tcpPair(t)
	conn := New(local)
	feed(t, peer, []byte("nometrics"))
	if got := drain(t, conn, 9); string(got) != "nometrics" {
		t.Fatalf("got %q, want %q", got, "nometrics")
	}
	conn.EndPreread()
	if _, err := conn.Write([]byte("out")); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func TestWriteDuringPrereadPanics(t *testing.T) {
	conn, _, _ := newTestConn(t)
	mustPanic(t, "write while in preread", func() { conn.Write([]byte("nope")) })
}

func TestWriteAfterEndPreread(t *testing.T) {
	conn, peer, metrics := newTestConn(t)
	conn.EndPreread()

	payload := []byte("response")
	n, err := conn.Write(payload)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("wrote %d bytes, want %d", n, len(payload))
	}
	if metrics.writeCalls() != 1 || metrics.bytesWritten() != len(payload) {
		t.Fatalf("write metrics = (%d calls, %d bytes), want (1, %d)",
			metrics.writeCalls(), metrics.bytesWritten(), len(payload))
	}
	got := make([]byte, len(payload))
	if err := peer.SetReadDeadline(time.Now().Add(testTimeout)); err != nil {
		t.Fatalf("peer deadline: %v", err)
	}
	if _, err := io.ReadFull(peer, got); err != nil {
		t.Fatalf("peer read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("peer got %q, want %q", got, payload)
	}
}

func TestReadFromPanics(t *testing.T) {
	conn, _, _ := newTestConn(t)
	mustPanic(t, "not supported", func() { conn.ReadFrom(bytes.NewReader([]byte("x"))) })
}

func TestWriteToPanics(t *testing.T) {
	conn, _, _ := newTestConn(t)
	mustPanic(t, "not supported", func() { conn.WriteTo(io.Discard) })
}

func TestIOCopyUsesWriteTo(t *testing.T) {
	conn, _, _ := newTestConn(t)
	conn.EndPreread()
	mustPanic(t, "not supported", func() { io.Copy(io.Discard, conn) })
}

func TestNewConnDefaults(t *testing.T) {
	local, _ := tcpPair(t)
	conn := New(local)
	if conn.prereadLimit != defaultPrereadLimit {
		t.Fatalf("prereadLimit = %d, want %d", conn.prereadLimit, defaultPrereadLimit)
	}
	if conn.prereadEnd.Load() {
		t.Fatal("prereadEnd must start false")
	}
	if conn.prereadCursor != 0 || conn.prereadBuf != nil {
		t.Fatal("preread state must start empty")
	}
	if conn.TCPConn != local {
		t.Fatal("TCPConn not wired through")
	}
}

func TestWithPrereadLimit(t *testing.T) {
	local, _ := tcpPair(t)
	conn := New(local, WithPrereadLimit(123))
	if conn.prereadLimit != 123 {
		t.Fatalf("prereadLimit = %d, want 123", conn.prereadLimit)
	}
}

func TestWithPrereadLimitRejectsNonPositive(t *testing.T) {
	for _, n := range []int{0, -1, -1024} {
		mustPanic(t, "invalid preread limit", func() { WithPrereadLimit(n) })
	}
}

func TestWithMetrics(t *testing.T) {
	local, _ := tcpPair(t)
	metrics := &fakeMetrics{}
	conn := New(local, WithMetrics(metrics))
	if conn.metrics != ConnMetrics(metrics) {
		t.Fatal("metrics not wired through")
	}
}

func TestOptionsAppliedInOrder(t *testing.T) {
	local, _ := tcpPair(t)
	conn := New(local, WithPrereadLimit(10), WithPrereadLimit(20))
	if conn.prereadLimit != 20 {
		t.Fatalf("prereadLimit = %d, want 20 (last option wins)", conn.prereadLimit)
	}
}

func TestWriteNotBlockedByBlockedRead(t *testing.T) {
	conn, peer, _ := newTestConn(t)
	conn.EndPreread()

	reading := make(chan struct{})
	go func() {
		defer close(reading)
		conn.Read(make([]byte, 4))
	}()
	time.Sleep(100 * time.Millisecond)

	done := make(chan error, 1)
	go func() {
		_, err := conn.Write([]byte("ping"))
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("write: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Write blocked behind a blocked Read")
	}

	feed(t, peer, []byte("data"))
	select {
	case <-reading:
	case <-time.After(testTimeout):
		t.Fatal("reader never woke up")
	}
}

func TestConcurrentReadWrite(t *testing.T) {
	conn, peer, _ := newTestConn(t)
	conn.EndPreread()

	var wg sync.WaitGroup
	stop := make(chan struct{})

	wg.Add(1)
	go func() {
		defer wg.Done()
		io.Copy(io.Discard, peer)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := conn.Write([]byte("payload")); err != nil {
				return
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 32)
		for {
			select {
			case <-stop:
				return
			default:
			}
			conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
			if _, err := conn.Read(buf); err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
				return
			}
		}
	}()

	time.Sleep(300 * time.Millisecond)
	close(stop)
	conn.Close()
	peer.Close()
	wg.Wait()
}

func TestConcurrentReadsDuringPreread(t *testing.T) {
	conn, peer, _ := newTestConn(t, WithPrereadLimit(1024))
	payload := repeat(512)
	feedAsync(peer, payload)

	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 64)
			conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			for range 4 {
				if _, err := conn.Read(buf); err != nil {
					return
				}
			}
		}()
	}
	wg.Wait()

	if len(conn.prereadBuf) > 1024 {
		t.Fatalf("prereadBuf grew to %d, beyond limit 1024", len(conn.prereadBuf))
	}
	if conn.prereadCursor > len(conn.prereadBuf) {
		t.Fatalf("cursor %d beyond buffer %d", conn.prereadCursor, len(conn.prereadBuf))
	}
}
