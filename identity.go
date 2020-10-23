package libp2ptls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"

	ic "github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"
)

const certValidityPeriod = 100 * 365 * 24 * time.Hour // ~100 years
const certificatePrefix = "libp2p-tls-handshake:"
const alpn string = "libp2p"

var extensionID = getPrefixedExtensionID([]int{1, 1})

// getExtensionString returns libp2p's object id in string format.
func getExtensionString(inputs []int) string {
	out := ""
	for i, input := range inputs {
		out += fmt.Sprintf("%d", input)
		if i != len(inputs)-1 {
			out += "."
		}
	}
	return out
}

func validateRemote(pubKey ic.PubKey, remote peer.ID) error {
	if remote != "" && !remote.MatchesPublicKey(pubKey) {
		peerID, err := peer.IDFromPublicKey(pubKey)
		if err != nil {
			peerID = peer.ID(fmt.Sprintf("(not determined: %s)", err.Error()))
		}
		return fmt.Errorf("peer IDs don't match: expected %s, got %s", remote, peerID)
	}
	return nil
}

func unmarshalExtensionPublicKey(value []byte, certKeyPub []byte) (ic.PubKey, error) {
	var sk signedKey
	if _, err := asn1.Unmarshal(value, &sk); err != nil {
		return nil, fmt.Errorf("unmarshalling signed certificate failed: %s", err)
	}
	pubKey, err := ic.UnmarshalPublicKey(sk.PubKey)
	if err != nil {
		return nil, fmt.Errorf("unmarshalling public key failed: %s", err)
	}
	valid, err := pubKey.Verify(append([]byte(certificatePrefix), certKeyPub...), sk.Signature)
	if err != nil {
		return nil, fmt.Errorf("signature verification failed: %s", err)
	}
	if !valid {
		return nil, errors.New("signature invalid")
	}
	return pubKey, nil
}

type signedKey struct {
	PubKey    []byte
	Signature []byte
}

// certificateConfig contains config to create certificate.
type certificateConfig struct {
	// Certificate Private and Public key pair.
	certKey *ecdsa.PrivateKey
	// Custom Extenstion value. It contains public key and signature.
	extensionValue []byte
	// Certificate's serial number.
	serialNumber *big.Int
}

// newCertificateConfig returns certificateConfig.
func newCertificateConfig(sk ic.PrivKey) (*certificateConfig, error) {
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	keyBytes, err := ic.MarshalPublicKey(sk.GetPublic())
	if err != nil {
		return nil, err
	}
	certKeyPub, err := x509.MarshalPKIXPublicKey(certKey.Public())
	if err != nil {
		return nil, err
	}
	signature, err := sk.Sign(append([]byte(certificatePrefix), certKeyPub...))
	if err != nil {
		return nil, err
	}
	value, err := asn1.Marshal(signedKey{
		PubKey:    keyBytes,
		Signature: signature,
	})
	if err != nil {
		return nil, err
	}

	sn, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return nil, err
	}
	return &certificateConfig{
		serialNumber:   sn,
		extensionValue: value,
		certKey:        certKey,
	}, nil
}

