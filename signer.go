package gopiv

import (
	"crypto"
	"encoding/asn1"
	"errors"
	"io"

	"github.com/ebfe/scard"
)

type pivCardSigner struct {
	sCard *scard.Card
	algorithm KeyAlgorithm
	key KeyReference
	publicKey crypto.PublicKey
}

func (s *pivCardSigner) Public() crypto.PublicKey {
	return s.publicKey
}

func (s *pivCardSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	digestReq := append([]byte{0x81}, append(getAsn1MultiByteLength(len(digest)), digest...)...)
	reqReq := []byte{0x82, 0x00}
	req := append([]byte{0x7C}, append(getAsn1MultiByteLength(len(digestReq) + len(reqReq)), append(digestReq, reqReq...)...)...)

	res, err := sendApdu(s.sCard, isoInterindustryCla, pivGeneralAuthenticateINS, byte(s.algorithm), byte(s.key), req)	
	if err != nil {
		return nil, err
	}

	if !res.IsSuccess() {
		return nil, res.Error()
	}

	var dynamicAuthTemplate asn1.RawValue
	_, err = asn1.Unmarshal(res.data, &dynamicAuthTemplate)
	if err != nil || dynamicAuthTemplate.Tag != 0x1c {
		return nil, errors.New("Received invalid signature response from card")
	}

	var sig asn1.RawValue
	_, err = asn1.Unmarshal(dynamicAuthTemplate.Bytes, &sig)
	if err != nil || sig.Tag != 0x02 {
		return nil, errors.New("Received invalid signature response from card")
	}

	return sig.Bytes, nil
}
