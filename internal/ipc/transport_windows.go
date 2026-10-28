//go:build windows

package ipc

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/privometry/privometry-oss/internal/platform"
)

// On Windows the daemon listens on a named pipe whose access list admits only
// the user, and refuses remote clients. Clients check that the pipe belongs
// to the user before sending anything, so another account cannot stand up a
// pipe of the same name and collect hook payloads.

const pipeBuffer = 64 << 10

type pipeAddr string

func (pipeAddr) Network() string  { return "pipe" }
func (a pipeAddr) String() string { return string(a) }

func checkPipeName(addr string) error {
	if !strings.HasPrefix(addr, `\\.\pipe\`) {
		return fmt.Errorf("ipc: %q is not a local named pipe", addr)
	}
	return nil
}

func dial(addr string, timeout time.Duration) (net.Conn, error) {
	if err := checkPipeName(addr); err != nil {
		return nil, err
	}
	name, err := windows.UTF16PtrFromString(addr)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(timeout)
	for {
		// SECURITY_IDENTIFICATION: the server may learn who connects, but not act as them.
		h, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING,
			windows.FILE_FLAG_OVERLAPPED|windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
		if err == nil {
			if err := checkServer(h, addr); err != nil {
				windows.CloseHandle(h)
				return nil, err
			}
			return &pipeConn{h: h, addr: pipeAddr(addr)}, nil
		}
		// Every instance is busy: the daemon makes the next one as soon as it accepts.
		if !errors.Is(err, windows.ERROR_PIPE_BUSY) {
			return nil, &net.OpError{Op: "dial", Net: "pipe", Addr: pipeAddr(addr), Err: err}
		}
		if time.Now().After(deadline) {
			return nil, &net.OpError{Op: "dial", Net: "pipe", Addr: pipeAddr(addr), Err: os.ErrDeadlineExceeded}
		}
		time.Sleep(time.Millisecond)
	}
}

// checkServer refuses a pipe that another account created.
func checkServer(h windows.Handle, addr string) error {
	user, err := platform.UserSID()
	if err != nil {
		return err
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("ipc: cannot read the owner of %s: %w", addr, err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("ipc: cannot read the owner of %s: %w", addr, err)
	}
	if !platform.TrustedOwner(owner, user) {
		return fmt.Errorf("ipc: %s belongs to %s, not you; refusing to talk to it", addr, owner.String())
	}
	return nil
}

// Listen creates the daemon's pipe. If the pipe already exists, another
// daemon is listening (or someone holds the name), and Listen fails.
func Listen(addr string) (net.Listener, error) {
	if err := checkPipeName(addr); err != nil {
		return nil, err
	}
	user, err := platform.UserSID()
	if err != nil {
		return nil, err
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;GA;;;" + user.String() + ")")
	if err != nil {
		return nil, err
	}
	name, err := windows.UTF16PtrFromString(addr)
	if err != nil {
		return nil, err
	}
	l := &pipeListener{addr: pipeAddr(addr), name: name,
		sa: &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}}
	h, err := l.instance(true)
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) || errors.Is(err, windows.ERROR_PIPE_BUSY) {
		return nil, fmt.Errorf("ipc: another daemon is listening on %s", addr)
	}
	if err != nil {
		return nil, err
	}
	l.next = h
	return l, nil
}

type pipeListener struct {
	addr pipeAddr
	name *uint16
	sa   *windows.SecurityAttributes

	mu        sync.Mutex
	next      windows.Handle // the instance the next client connects to
	accepting bool
	closed    bool
}

func (l *pipeListener) instance(first bool) (windows.Handle, error) {
	flags := uint32(windows.PIPE_ACCESS_DUPLEX | windows.FILE_FLAG_OVERLAPPED)
	if first {
		flags |= windows.FILE_FLAG_FIRST_PIPE_INSTANCE
	}
	return windows.CreateNamedPipe(l.name, flags,
		windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT|windows.PIPE_REJECT_REMOTE_CLIENTS,
		windows.PIPE_UNLIMITED_INSTANCES, pipeBuffer, pipeBuffer, 0, l.sa)
}

func (l *pipeListener) Accept() (net.Conn, error) {
	ev, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(ev)
	ov := &windows.Overlapped{HEvent: ev}

	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil, net.ErrClosed
	}
	h := l.next
	// Started under the lock, so Close either sees it pending and cancels it,
	// or runs first and this returns ErrClosed above.
	err = windows.ConnectNamedPipe(h, ov)
	l.accepting = true
	l.mu.Unlock()

	if errors.Is(err, windows.ERROR_IO_PENDING) {
		var n uint32
		err = windows.GetOverlappedResult(h, ov, &n, true)
	}
	if errors.Is(err, windows.ERROR_PIPE_CONNECTED) {
		err = nil // the client connected between CreateNamedPipe and ConnectNamedPipe
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	l.accepting = false
	if l.closed {
		windows.CloseHandle(h)
		l.next = windows.InvalidHandle
		return nil, net.ErrClosed
	}
	next, nerr := l.instance(false)
	if nerr != nil {
		windows.CloseHandle(h)
		l.next = windows.InvalidHandle
		l.closed = true
		return nil, nerr
	}
	l.next = next
	if err != nil {
		// That client went away before it was served; the next one gets a fresh instance.
		windows.CloseHandle(h)
		return nil, &net.OpError{Op: "accept", Net: "pipe", Addr: l.addr, Err: err}
	}
	return &pipeConn{h: h, addr: l.addr}, nil
}

func (l *pipeListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	if l.accepting {
		windows.CancelIoEx(l.next, nil) // Accept closes the handle
	} else if l.next != windows.InvalidHandle {
		windows.CloseHandle(l.next)
		l.next = windows.InvalidHandle
	}
	return nil
}

func (l *pipeListener) Addr() net.Addr { return l.addr }

// pipeConn is one connected pipe instance with overlapped reads and writes,
// so deadlines can cancel them.
type pipeConn struct {
	h    windows.Handle
	addr pipeAddr

	mu       sync.Mutex
	deadline time.Time
	once     sync.Once
}

func (c *pipeConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	n, err := c.io(b, false)
	if errors.Is(err, windows.ERROR_BROKEN_PIPE) || errors.Is(err, windows.ERROR_PIPE_NOT_CONNECTED) {
		return n, io.EOF
	}
	if errors.Is(err, windows.ERROR_MORE_DATA) {
		err = nil // byte mode never splits messages, but take what arrived
	}
	return n, err
}

func (c *pipeConn) Write(b []byte) (int, error) {
	written := 0
	for written < len(b) {
		n, err := c.io(b[written:], true)
		written += n
		if err != nil {
			if errors.Is(err, windows.ERROR_BROKEN_PIPE) || errors.Is(err, windows.ERROR_NO_DATA) || errors.Is(err, windows.ERROR_PIPE_NOT_CONNECTED) {
				return written, io.ErrClosedPipe
			}
			return written, err
		}
	}
	return written, nil
}

func (c *pipeConn) io(b []byte, write bool) (int, error) {
	c.mu.Lock()
	deadline := c.deadline
	c.mu.Unlock()
	wait := uint32(windows.INFINITE)
	if !deadline.IsZero() {
		d := time.Until(deadline)
		if d <= 0 {
			return 0, os.ErrDeadlineExceeded
		}
		wait = uint32((d + time.Millisecond - 1) / time.Millisecond)
	}
	ev, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(ev)
	ov := &windows.Overlapped{HEvent: ev}
	var n uint32
	if write {
		err = windows.WriteFile(c.h, b, &n, ov)
	} else {
		err = windows.ReadFile(c.h, b, &n, ov)
	}
	if errors.Is(err, windows.ERROR_IO_PENDING) {
		if r, _ := windows.WaitForSingleObject(ev, wait); r == uint32(windows.WAIT_TIMEOUT) {
			windows.CancelIoEx(c.h, ov)
			windows.GetOverlappedResult(c.h, ov, &n, true) // wait for the cancel before ov goes away
			return int(n), os.ErrDeadlineExceeded
		}
		err = windows.GetOverlappedResult(c.h, ov, &n, false)
	}
	return int(n), err
}

// Close closes the handle without DisconnectNamedPipe, which would throw
// away a reply the client has not read yet.
func (c *pipeConn) Close() error {
	c.once.Do(func() { windows.CloseHandle(c.h) })
	return nil
}

func (c *pipeConn) LocalAddr() net.Addr  { return c.addr }
func (c *pipeConn) RemoteAddr() net.Addr { return c.addr }

func (c *pipeConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	return nil
}

func (c *pipeConn) SetReadDeadline(t time.Time) error  { return c.SetDeadline(t) }
func (c *pipeConn) SetWriteDeadline(t time.Time) error { return c.SetDeadline(t) }
