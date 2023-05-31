package gopiv

import (
	"bytes"
	"crypto"
	"crypto/des"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"

	"github.com/ebfe/scard"
)

const (
	isoInterindustryCla byte = 0x00

	iso7816selectINS byte = 0xA4
	pivGetDataINS byte = 0xCB
	pivGetRespINS byte = 0xC0
	pivVerifyINS byte = 0x20
	pivChangeReferenceDataINS byte = 0x24
	pivResetRetryCounterINS byte = 0x2C
	pivGenerateKeyPairINS byte = 0x47
	pivGeneralAuthenticateINS byte = 0x87
	pivPutDataINS byte = 0xDB
)

var pkcs15HashPrefixes = map[crypto.Hash][]byte{
	crypto.MD5:       {0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10},
	crypto.SHA1:      {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14},
	crypto.SHA224:    {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c},
	crypto.SHA256:    {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA384:    {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA512:    {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
	crypto.MD5SHA1:   {},
	crypto.RIPEMD160: {0x30, 0x20, 0x30, 0x08, 0x06, 0x06, 0x28, 0xcf, 0x06, 0x03, 0x00, 0x31, 0x04, 0x14},
}

type GenericPivCard struct {
	sCard *scard.Card
	applicationLabel string
}

func (p *GenericPivCard) GetApplicationLabel() string {
	return p.applicationLabel
}

func (p *GenericPivCard) GetVersion() (string, error) {
	return "", errors.New("Not supported")
}

func (p *GenericPivCard) GetSerialNumber() (int32, error) {
	return 0, errors.New("Not supported")
}

func (p *GenericPivCard) GetUUID() ([]byte, error) {
	res, err := sendApdu(p.sCard, isoInterindustryCla, pivGetDataINS, 0x3F, 0xFF, []byte{0x5C, 0x03, 0x5F, 0xC1, 0x07})
	if err != nil {
		return nil, err
	}

	if !res.IsSuccess() {
		return nil, res.Error()
	}

	var ccc asn1.RawValue
	_, err = asn1.Unmarshal(res.data, &ccc)
	if err != nil {
		return nil, err
	}
	if ccc.Tag != 19 {
		return nil, errors.New("Received malformed response from card")
	}

	var cardIdentifier asn1.RawValue
	_, err = asn1.Unmarshal(ccc.Bytes, &cardIdentifier)
	if err != nil {
		return nil, err
	}
	if cardIdentifier.Tag != 16 {
		return nil, errors.New("Received malformed response from card")
	}

	return cardIdentifier.Bytes, nil
}

func (p *GenericPivCard) SetManagementKey(newManagementKey []byte) error {
	return errors.New("Not supported")
}

func (p *GenericPivCard) GetCertificate(slot Slot) (*x509.Certificate, error) {
	res, err := sendApdu(p.sCard, isoInterindustryCla, pivGetDataINS, 0x3F, 0xFF, append([]byte{0x5C, byte(len(slot))}, slot...))
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(res.statusWord, []byte{0x90, 0x00}) {
		return nil, res.Error()
	}

	obj, err := parseBerTlv(res.data)
	if err != nil {
		return nil, err
	}

	cert, err := parseBerTlv(obj.Bytes)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(cert.Bytes)
}

func (p *GenericPivCard) Authenticate(withKey KeyReference, value string) error {
	paddedPin := []byte(value)
	for i := 0; i < 8 - len(value); i++ {
		paddedPin = append(paddedPin, 0xFF)
	}

	res, err := sendApdu(p.sCard, isoInterindustryCla, pivVerifyINS, 0x00, byte(withKey), paddedPin)
	if err != nil {
		return err
	}

	if !res.IsSuccess() {
		return res.Error()
	}

	return nil
}

type KeyReferenceAuthenticationStatus struct {
	Key KeyReference
	Authenticated bool
	RemainingAttempts *int
}
func (p *GenericPivCard) GetAuthenticationStatus(forKey KeyReference) (*KeyReferenceAuthenticationStatus, error) {
	res, err := sendApdu(p.sCard, isoInterindustryCla, pivVerifyINS, 0x00, byte(forKey), nil)
	if err != nil {
		return nil, err
	}

	if res.statusWord[0] == 0x63 && res.statusWord[1] >= 0xC0 && res.statusWord[1] <= 0xCF {
		remainingAttempts := int(res.statusWord[1] - 0xC0)
		return &KeyReferenceAuthenticationStatus{
			Key: forKey,
			Authenticated: false,
			RemainingAttempts: &remainingAttempts,
		}, nil
	}

	if res.IsSuccess() {
		return &KeyReferenceAuthenticationStatus{
			Key: forKey,
			Authenticated: true,
			RemainingAttempts: nil,
		}, nil
	}

	return nil, res.Error()
}

func (p *GenericPivCard) DeAuthenticate(key KeyReference) error {
	res, err := sendApdu(p.sCard, isoInterindustryCla, pivVerifyINS, 0xFF, byte(key), nil)
	if err != nil {
		return err
	}

	if !res.IsSuccess() {
		return res.Error()
	}

	return nil
}

func (p *GenericPivCard) ChangeAuthenticationData(key KeyReference, currentValue, newValue string) error {
	paddedCurrent := []byte(currentValue)
	for i := 0; i < 8 - len(currentValue); i++ {
		paddedCurrent = append(paddedCurrent, 0xFF)
	}

	paddedNew := []byte(newValue)
	for i := 0; i < 8 - len(newValue); i++ {
		paddedNew = append(paddedNew, 0xFF)
	}

	res, err := sendApdu(p.sCard, isoInterindustryCla, pivChangeReferenceDataINS, 0x00, byte(key), append(paddedCurrent, paddedNew...))
	if err != nil {
		return err
	}

	if !res.IsSuccess() {
		return res.Error()
	}

	return nil
}

func (p *GenericPivCard) UnblockPIN(puk, newPin string) error {
	paddedPin := []byte(newPin)
	for i := 0; i < 8 - len(newPin); i++ {
		paddedPin = append(paddedPin, 0xFF)
	}

	res, err := sendApdu(p.sCard, isoInterindustryCla, pivResetRetryCounterINS, 0x00, byte(CardholderPIN), append([]byte(puk), paddedPin...))
	if err != nil {
		return err
	}

	if !res.IsSuccess() {
		return res.Error()
	}

	return nil
}

func (p *GenericPivCard) GetAdminAuthenticationWitness() ([]byte, error) {
	res, err := sendApdu(p.sCard, isoInterindustryCla, pivGeneralAuthenticateINS, byte(ThreeDesKey), byte(ManagementKey), []byte{0x7C, 0x02, 0x80, 0x00})
	if err != nil {
		return nil, err
	}

	if !res.IsSuccess() {
		return nil, res.Error()
	}

	var dynamicAuthTemplate asn1.RawValue
	_, err = asn1.Unmarshal(res.data, &dynamicAuthTemplate)
	if err != nil {
		return nil, err
	}

	var witness asn1.RawValue
	_, err = asn1.Unmarshal(dynamicAuthTemplate.Bytes, &witness)
	if err != nil {
		return nil, err
	}

	return witness.Bytes, nil
}

func (p *GenericPivCard) MutuallyAdminAuthenticateWithChallenge(decryptedWitness, challenge []byte) ([]byte, error) {
	decryptedWitnessReq := append([]byte{0x80, byte(len(decryptedWitness))}, decryptedWitness...)
	challengeReq := append([]byte{0x81, byte(len(challenge))}, challenge...)
	reqReq := []byte{0x82, 0x00}
	req := append(decryptedWitnessReq, append(challengeReq, reqReq...)...)

	res, err := sendApdu(p.sCard, isoInterindustryCla, pivGeneralAuthenticateINS, byte(ThreeDesKey), byte(ManagementKey), append([]byte{0x7C, byte(len(req))}, req...))	
	if err != nil {
		return nil, err	
	}

	if !res.IsSuccess() {
		return nil, res.Error()
	}

	var dynamicAuthTemplate asn1.RawValue
	_, err = asn1.Unmarshal(res.data, &dynamicAuthTemplate)
	if err != nil {
		return nil, err
	}

	var encryptedChallenge asn1.RawValue
	_, err = asn1.Unmarshal(dynamicAuthTemplate.Bytes, &encryptedChallenge)
	if err != nil {
		return nil, err
	}

	return encryptedChallenge.Bytes, nil
}

func (p *GenericPivCard) AdminAuthenticate(managementKey []byte) error {
	encryptedWitness, err := p.GetAdminAuthenticationWitness()	
	if err != nil {
		return err
	}

	cipher, err := des.NewTripleDESCipher(managementKey)
	if err != nil {
		return err
	}

	decryptedWitness := make([]byte, 8)
	cipher.Decrypt(decryptedWitness, encryptedWitness)

	challenge := make([]byte, 8)
	_, err = rand.Read(challenge)
	if err != nil {
		return err
	}

	encryptedChallenge, err := p.MutuallyAdminAuthenticateWithChallenge(decryptedWitness, challenge)
	if err != nil {
		return err
	}

	decryptedChallenge := make([]byte, 8)
	cipher.Decrypt(decryptedChallenge, encryptedChallenge)

	if !bytes.Equal(challenge, decryptedChallenge) {
		return errors.New("Challenge response from card invalid")
	}

	return nil
}

func (p *GenericPivCard) GeneratePrivateKey(key KeyReference, algorithm KeyAlgorithm) (crypto.Signer, error) {
	res, err := sendApdu(p.sCard, isoInterindustryCla, pivGenerateKeyPairINS, 0x00, byte(key), []byte{0xAC, 0x03, 0x80, 0x01, byte(algorithm)})
	if err != nil {
		return nil, err
	}

	if !res.IsSuccess() {
		return nil, res.Error()
	}

	var obj asn1.RawValue
	_, err = asn1.Unmarshal(res.data, &obj)
	if err != nil || obj.Tag != 0x49 {
		return nil, errors.New("Received malformed response from card")
	}
	
	var publicKey crypto.PublicKey
	if algorithm == RsaKey {
		var modulus asn1.RawValue
		rest, err := asn1.Unmarshal(obj.Bytes, &modulus)
		if err != nil || modulus.Tag != 0x01 {
			return nil, errors.New("Received malformed response from card")
		}
		
		var exponent asn1.RawValue
		_, err = asn1.Unmarshal(rest, &exponent)
		if err != nil || exponent.Tag != 0x02 {
			return nil, errors.New("Received malformed response from card")
		}

		n := (&big.Int{}).SetBytes(modulus.Bytes)
		e := (&big.Int{}).SetBytes(exponent.Bytes)

		if !e.IsInt64() {
			return nil, errors.New("Received invalid key from card")	
		}

		publicKey = &rsa.PublicKey{
			N: n, 
			E: int(e.Int64()),
		} 
	} else {
		var point asn1.RawValue
		_, err = asn1.Unmarshal(obj.Bytes, &point)
		if err != nil || point.Tag != 0x06 || point.Bytes[0] != 0x04 {
			return nil, errors.New("Received malformed response from card")
		}

		var curve elliptic.Curve
		if algorithm == EllipticP256 {
			curve = elliptic.P256()
		} else if algorithm == EllipticP384 {
			curve = elliptic.P384()	
		} else {
			return nil, errors.New("Invalid key algorithm")
		}

		pointLength := curve.Params().BitSize / 8
		uncompressedKeyEncodingLength := (pointLength * 2) + 1
		if len(point.Bytes) != uncompressedKeyEncodingLength {
			return nil, errors.New("Received invalid key from card")	
		}

		x := (&big.Int{}).SetBytes(point.Bytes[1:1+pointLength])
		y := (&big.Int{}).SetBytes(point.Bytes[1+pointLength:uncompressedKeyEncodingLength])

		publicKey = &ecdsa.PublicKey{
			Curve: curve, 
			X: x, 
			Y: y,
		}
	}

	if publicKey == nil {
		return nil, errors.New("Received invalid key from card")
	}

	return &genericPivSigner{
		sCard: p.sCard,
		algorithm: algorithm,
		key: key,
		publicKey: publicKey,
	}, nil
}

func (p *GenericPivCard) LoadCertificate(slot Slot, cert []byte) error {
	slotReq := append([]byte{0x5C, 0x03}, slot...)
	pivCertObj := append([]byte{0x70}, append(getAsn1MultiByteLength(len(cert)), cert...)...)
	pivCertInfo := []byte{0x71, 0x01, 0x00, 0xFE, 0x00}
	certReq := append([]byte{0x53}, append(getAsn1MultiByteLength(len(pivCertObj) + len(pivCertInfo)), append(pivCertObj, pivCertInfo...)...)...)
	req := append(slotReq, certReq...)
	res, err := sendApdu(p.sCard, isoInterindustryCla, pivPutDataINS, 0x3F, 0xFF, req)
	if err != nil {
		return err
	}
	
	if !res.IsSuccess() {
		return res.Error()
	}

	return nil
}

func getAsn1MultiByteLength(length int) []byte {
	if length < 0x80 {
		return []byte{byte(length)}
	} else if length < 0x100 {
		return []byte{0x81, byte(length)}
	} else {
		return []byte{0x82, byte(length >> 8), byte(length)}
	}
}

func (p *GenericPivCard) GetSigner(key KeyReference) (crypto.Signer, error) {
	slot := keyReferenceToSlot(key)

	cert, err := p.GetCertificate(slot)
	if err != nil {
		return nil, err
	}

	var publicKey crypto.PublicKey
	var algorithm KeyAlgorithm
	switch key := cert.PublicKey.(type) {
		case *ecdsa.PublicKey:
			if key.Params().BitSize == 256 {
				publicKey = key
				algorithm = EllipticP256
			} else if key.Params().BitSize == 384 {
				publicKey = key
				algorithm = EllipticP384
			}
		case *rsa.PublicKey:
			publicKey = key
			algorithm = RsaKey
	}

	if publicKey == nil {
		return nil, errors.New("Slot has unknown public key type")
	}

	return &genericPivSigner{
		sCard: p.sCard,
		algorithm: algorithm,
		key: key,
		publicKey: publicKey,
	}, nil
}

type genericPivSigner struct {
	sCard *scard.Card
	algorithm KeyAlgorithm
	key KeyReference
	publicKey crypto.PublicKey
}

func (s *genericPivSigner) Public() crypto.PublicKey {
	return s.publicKey
}

func (s *genericPivSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	var processedDigest []byte
	if ecKey, ok := s.publicKey.(*ecdsa.PublicKey); ok {
		truncateBytes := (ecKey.Params().BitSize + 7) / 8
		if len(digest) > truncateBytes {
			processedDigest = digest[:truncateBytes]
		} else {
			processedDigest = digest
		}
	} else if rsaKey, ok := s.publicKey.(*rsa.PublicKey); ok {
		hashFunc := opts.HashFunc()	
		if hashFunc.Size() != len(digest) {
			return nil, errors.New("Digest length doesn't match hash function")
		}

		if o, ok := opts.(*rsa.PSSOptions); ok {
			salt, err := pssNewSalt(rand, rsaKey, hashFunc, o)
			if err != nil {
				return nil, err
			}

			encodedDigest, err := pssEMSAPSSEncode(digest, rsaKey, salt, hashFunc.New())
			if err != nil {
				return nil, err
			}

			processedDigest = encodedDigest
		} else {
			p, ok := pkcs15HashPrefixes[hashFunc]
			if !ok {
				return nil, errors.New("Unknown hash function")
			}

			prefixedDigest := append(p, digest...)

			paddingLen := rsaKey.Size() - 3 - len(prefixedDigest)
			if paddingLen < 0 {
				return nil, errors.New("Message exceeds maximum length")
			}

			padding := make([]byte, paddingLen)
			for i := range(padding) {
				padding[i] = 0xFF
			}

			processedDigest = append(append([]byte{0x00, 0x01}, padding...), append([]byte{0x00}, prefixedDigest...)...)
		}
	}

	digestReq := append([]byte{0x81}, append(getAsn1MultiByteLength(len(processedDigest)), processedDigest...)...)
	reqReq := []byte{0x82, 0x00}
	req := append([]byte{0x7C}, append(getAsn1MultiByteLength(len(digestReq) + len(reqReq)), append(reqReq, digestReq...)...)...)

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
