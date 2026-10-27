package engine

import (
	"os"
	"sync"

	"golang.zx2c4.com/wireguard/tun"
)

// chanTUN is an in-memory tun.Device: the virtual plaintext endpoint
// of one wireguard-go device. It is the standard extension point of
// wireguard-go (its own tun/netstack and tun/tuntest do the same);
// no kernel TUN device and no network namespace are involved.
//
// Direction, in wireguard-go's terms:
//
//   - Read returns packets the device should encrypt and send to
//     its peer. The pump feeds it plaintext packets from the front.
//   - Write receives decrypted packets arriving from the peer. The
//     pump's write handler forwards them toward the front.
type chanTUN struct {
	name   string
	mtu    int
	in     chan []byte // pump -> device (Read side)
	events chan tun.Event
	closed chan struct{}
	once   sync.Once

	// onWrite is called for every packet the device writes
	// (decrypted, from the peer). Set before the device starts.
	onWrite func(pkt []byte)
}

func newChanTUN(name string, mtu int) *chanTUN {
	t := &chanTUN{
		name:   name,
		mtu:    mtu,
		in:     make(chan []byte, 128),
		events: make(chan tun.Event, 1),
		closed: make(chan struct{}),
	}
	t.events <- tun.EventUp
	return t
}

// enqueue hands one plaintext packet to the device's Read side.
// Returns false when the queue is full or the TUN is closed (the
// pump counts that as a drop).
func (t *chanTUN) enqueue(pkt []byte) bool {
	select {
	case <-t.closed:
		return false
	default:
	}
	select {
	case t.in <- pkt:
		return true
	case <-t.closed:
		return false
	default:
		return false
	}
}

func (t *chanTUN) File() *os.File { return nil }

func (t *chanTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case <-t.closed:
		return 0, os.ErrClosed
	case pkt := <-t.in:
		n := copy(bufs[0][offset:], pkt)
		sizes[0] = n
		return 1, nil
	}
}

func (t *chanTUN) Write(bufs [][]byte, offset int) (int, error) {
	for _, buf := range bufs {
		select {
		case <-t.closed:
			return 0, os.ErrClosed
		default:
		}
		if t.onWrite != nil && len(buf) > offset {
			pkt := make([]byte, len(buf)-offset)
			copy(pkt, buf[offset:])
			t.onWrite(pkt)
		}
	}
	return len(bufs), nil
}

func (t *chanTUN) MTU() (int, error)     { return t.mtu, nil }
func (t *chanTUN) Name() (string, error) { return t.name, nil }

func (t *chanTUN) Events() <-chan tun.Event { return t.events }

func (t *chanTUN) BatchSize() int { return 1 }

func (t *chanTUN) Close() error {
	t.once.Do(func() {
		close(t.closed)
		close(t.events)
	})
	return nil
}
