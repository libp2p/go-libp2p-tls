package libp2ptls

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"

	ci "github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/sec"
)

type conn struct {
	*tls.Conn

	localPeer peer.ID
	privKey   ci.PrivKey

	remotePeer   peer.ID
	remotePubKey ci.PubKey
}

var _ sec.SecureConn = &conn{}

func (c *conn) LocalPeer() peer.ID {
	return c.localPeer
}

func (c *conn) LocalPrivateKey() ci.PrivKey {
	return c.privKey
}

func (c *conn) RemotePeer() peer.ID {
	return c.remotePeer
}

func (c *conn) RemotePublicKey() ci.PubKey {
	return c.remotePubKey
}

const (
	recordTypeHandshake byte = 22
	versionTLS13             = 0x0304
	maxCiphertextTLS13       = 16384 + 256 // maximum ciphertext length in TLS 1.3
	maxHandshake             = 65536       // maximum handshake we support (protocol max is 16 MB)
)

var errSimultaneousConnect = errors.New("detected TCP simultaneous connect")

type teeConn struct {
	net.Conn
	buf *bytes.Buffer
}

func newTeeConn(c net.Conn, buf *bytes.Buffer) net.Conn {
	return &teeConn{Conn: c, buf: buf}
}

func (c *teeConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.buf.Write(b[:n])
	return n, err
}

type wrappedConn struct {
	net.Conn

	hasReadFirstMessage bool
	raw                 bytes.Buffer // contains a copy of every byte of the first handshake message we read from the wire

	hand bytes.Buffer // used to store the first handshake message until we've completely read it

}

func newWrappedConn(c net.Conn) net.Conn {
	wc := &wrappedConn{}
	wc.Conn = newTeeConn(c, &wc.raw)
	return wc
}

func (c *wrappedConn) Read(b []byte) (int, error) {
	if c.hasReadFirstMessage {
		return c.Conn.Read(b)
	}

	// We read the first handshake message, and it was not a ClientHello.
	// We now need to feed all the bytes we read from the wire into the TLS stack,
	// so it can proceed with the handshake.
	if c.raw.Len() > 0 {
		n, err := c.raw.Read(b)
		if err == io.EOF || c.raw.Len() == 0 {
			c.hasReadFirstMessage = true
			err = nil
		}
		return n, err
	}

	mes, err := c.readFirstHandshakeMessage()
	if err != nil {
		return 0, err
	}

	switch mes[0] {
	case 1: // ClientHello
		return 0, errSimultaneousConnect
	case 2: // ServerHello
		return c.Read(b)
	default:
		return 0, fmt.Errorf("unexpected message type: %d", mes[0])
	}
}

func (c *wrappedConn) readFirstHandshakeMessage() ([]byte, error) {
	for c.hand.Len() < 4 {
		if err := c.readRecord(); err != nil {
			return nil, err
		}
	}
	data := c.hand.Bytes()
	n := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if n > maxHandshake {
		return nil, fmt.Errorf("tls: handshake message of length %d bytes exceeds maximum of %d bytes", n, maxHandshake)
	}
	for c.hand.Len() < 4+n {
		if err := c.readRecord(); err != nil {
			return nil, err
		}
	}
	return c.hand.Next(4 + n), nil
}

func (c *wrappedConn) readRecord() error {
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(c.Conn, hdr); err != nil {
		return err
	}
	if hdr[0] != recordTypeHandshake {
		return errors.New("expected a handshake record")
	}
	n := int(hdr[3])<<8 | int(hdr[4])
	if n > maxCiphertextTLS13 {
		return fmt.Errorf("oversized record received with length %d", n)
	}
	_, err := io.CopyN(&c.hand, c.Conn, int64(n))
	return err
}
