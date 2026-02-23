package helpers

import (
	"bytes"
	"net"
	"time"
)

// MockConn implements net.Conn for testing readers and protocol modules.
type MockConn struct {
	ReadBuf  *bytes.Buffer
	WriteBuf *bytes.Buffer
	Closed   bool
}

func NewMockConn(readData []byte) *MockConn {
	return &MockConn{
		ReadBuf:  bytes.NewBuffer(readData),
		WriteBuf: &bytes.Buffer{},
	}
}

func (m *MockConn) Read(b []byte) (int, error)         { return m.ReadBuf.Read(b) }
func (m *MockConn) Write(b []byte) (int, error)        { return m.WriteBuf.Write(b) }
func (m *MockConn) Close() error                       { m.Closed = true; return nil }
func (m *MockConn) LocalAddr() net.Addr                { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345} }
func (m *MockConn) RemoteAddr() net.Addr               { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 80} }
func (m *MockConn) SetDeadline(t time.Time) error      { return nil }
func (m *MockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *MockConn) SetWriteDeadline(t time.Time) error { return nil }
