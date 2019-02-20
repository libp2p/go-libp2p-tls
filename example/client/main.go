package main

import (
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"time"

	ic "github.com/libp2p/go-libp2p-crypto"
	peer "github.com/libp2p/go-libp2p-peer"
	libp2ptls "github.com/libp2p/go-libp2p-tls"
)

func main() {
	if err := startClient(); err != nil {
		panic(err)
	}
}

func startClient() error {
	port := flag.Int("p", 5533, "port")
	peerIDString := flag.String("id", "", "peer ID")
	keyType := flag.String("key", "ecdsa", "rsa, ecdsa, ed25519 or secp256k1")
	flag.Parse()

	var priv ic.PrivKey
	var err error
	switch *keyType {
	case "rsa":
		fmt.Printf("Generated new peer with an RSA key.")
		priv, _, err = ic.GenerateRSAKeyPair(2048, rand.Reader)
	case "ecdsa":
		fmt.Printf("Generated new peer with an ECDSA key.")
		priv, _, err = ic.GenerateECDSAKeyPair(rand.Reader)
	case "ed25519":
		fmt.Printf("Generated new peer with an Ed25519 key.")
		priv, _, err = ic.GenerateEd25519Key(rand.Reader)
	case "secp256k1":
		fmt.Printf("Generated new peer with an Secp256k1 key.")
		priv, _, err = ic.GenerateSecp256k1Key(rand.Reader)
	default:
		return fmt.Errorf("unknown key type: %s", *keyType)
	}
	if err != nil {
		return err
	}

	peerID, err := peer.IDB58Decode(*peerIDString)
	if err != nil {
		return err
	}

	id, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		return err
	}
	fmt.Printf(" Peer ID: %s\n", id.Pretty())
	tp, err := libp2ptls.New(priv)
	if err != nil {
		return err
	}

	remoteAddr := fmt.Sprintf("localhost:%d", *port)
	fmt.Printf("Dialing %s\n", remoteAddr)
	conn, err := net.Dial("tcp", remoteAddr)
	if err != nil {
		return err
	}
	fmt.Printf("Dialed raw connection to %s\n", conn.RemoteAddr())

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sconn, err := tp.SecureOutbound(ctx, conn, peerID)
	if err != nil {
		return err
	}
	fmt.Printf("Authenticated server: %s\n", sconn.RemotePeer().Pretty())
	data, err := ioutil.ReadAll(sconn)
	if err != nil {
		return err
	}
	fmt.Printf("Received message from server: %s\n", string(data))
	return nil
}
