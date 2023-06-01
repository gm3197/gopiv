package gopiv

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"log"

	"github.com/ebfe/scard"
)

type Slot []byte

type KeyReference byte

type KeyAlgorithm byte

var (
	pivAID = []byte{0xa0, 0x00, 0x00, 0x03, 0x08}

	AuthenticationSlot Slot = []byte{0x5F, 0xC1, 0x05}
	CardAuthenticationSlot Slot = []byte{0x5F, 0xC1, 0x01}
	DigitalSignatureSlot Slot = []byte{0x5F, 0xC1, 0x0A}
	KeyManagementSlot Slot = []byte{0x5F, 0xC1, 0x0B}

	debug = false
)

const (
	CardholderPIN KeyReference = 0x80
	PinUnblockingKey KeyReference = 0x81
	AuthenticationKey KeyReference = 0x9A
	ManagementKey KeyReference = 0x9B
	DigitalSignatureKey KeyReference = 0x9C
	KeyManagementKey KeyReference = 0x9D
	CardAuthenticationKey KeyReference = 0x9E

	Rsa2048Key KeyAlgorithm = 0x07
	EllipticP256 KeyAlgorithm = 0x11
	EllipticP384 KeyAlgorithm = 0x14
	ThreeDesKey KeyAlgorithm = 0x03
	AesKey KeyAlgorithm = 0x0C
)

type PivCard interface {
	GetApplicationLabel() string
	GetVersion() (string, error)
	GetSerialNumber() ([]byte, error)
	GetSupportedAlgorithms() ([]KeyAlgorithm, error)
	GetCertificate(slot Slot) (*x509.Certificate, error)
	GetUUID() ([]byte, error)
	Authenticate(withKey KeyReference, value string) (*KeyReferenceAuthenticationStatus, error)
	GetAuthenticationStatus(forKey KeyReference) (*KeyReferenceAuthenticationStatus, error)
	DeAuthenticate(key KeyReference) error
	ChangeAuthenticationData(key KeyReference, currentValue, newValue string) error
	UnblockPIN(puk, newPin string) (*KeyReferenceAuthenticationStatus, error)
	GetAdminAuthenticationWitness() ([]byte, error)
	MutuallyAdminAuthenticateWithChallenge(decryptedWitness, challenge []byte) ([]byte, error)
	AdminAuthenticate(managementKey []byte) error
	GeneratePrivateKey(key KeyReference, algorithm KeyAlgorithm) (crypto.Signer, error)
	LoadCertificate(slot Slot, cert []byte) error
	GetSigner(key KeyReference) (crypto.Signer, error)
	SetManagementKey(newManagementKey []byte) error
	ResetToDefaults() error
}

func SetDebug(on bool) {
	debug = on
}

func GetPivCard(card *scard.Card) (PivCard, error) {
	err := card.BeginTransaction()	
	if err != nil {
		return nil, err
	}

	res, err := sendApdu(card, isoInterindustryCla, iso7816selectINS, 0x04, 0x00, pivAID)
	if err != nil {
		return nil, err
	}

	if bytes.Equal(res.statusWord, []byte{0x6A, 0x82}) {
		return nil, errors.New("The provided card is not a PIV card")
	}

	if !res.IsSuccess() {
		return nil, errors.New("Unknown response from card")
	}

	genericPiv := &GenericPivCard{
		sCard: card,
		supportedAlgorithms: nil,
	}

	var applicationPropertyTemplate asn1.RawValue
	_, err = asn1.Unmarshal(res.data, &applicationPropertyTemplate)
	if err != nil {
		return nil, errors.New("Received malformed response from card")
	}

	rest := applicationPropertyTemplate.Bytes
	for len(rest) > 0 {
		var obj asn1.RawValue
		r, err := asn1.Unmarshal(rest, &obj)
		if err != nil {
			return nil, errors.New("Received malformed response from card")
		}
		if obj.Tag == 16 {
			genericPiv.applicationLabel = string(obj.Bytes)			
		}
		if obj.Tag == 12 {
			var supportedAlgo asn1.RawValue
			_, err = asn1.Unmarshal(obj.Bytes, &supportedAlgo)
			if err == nil {
				if len(supportedAlgo.Bytes) == 1 {
					genericPiv.supportedAlgorithms = append(genericPiv.supportedAlgorithms, KeyAlgorithm(supportedAlgo.Bytes[0]))
				}			
			}
		}
		rest = r
	}

	/*
	 * Check for Yubikey Extended Instruction Set
	 * https://developers.yubico.com/PIV/Introduction/Yubico_extensions.html
	 */
	ykCheckRes, err := sendApdu(card, isoInterindustryCla, yubikeyGetVersionINS, 0x00, 0x00, nil)
	if err == nil {
		if ykCheckRes.IsSuccess() && len(ykCheckRes.data) == 3 {
			return &Yubikey{
				genericPiv,
				ykCheckRes.data,
			}, nil
		}
	}

	return genericPiv, nil
}

type apduResponse struct {
	statusWord []byte
	data []byte
}

func (a *apduResponse) IsSuccess() bool {
	return bytes.Equal(a.statusWord, []byte{0x90, 0x00})
}

func (a *apduResponse) Error() error {
	return fmt.Errorf("Received error from card: %X %X", a.statusWord[0], a.statusWord[1])
}

func sendApdu(card *scard.Card, cla, ins, p1, p2 byte, data []byte) (*apduResponse, error) {
	var apdu []byte
	chaining := false
	if data != nil {
		if len(data) + 6 > 255 {
			chaining = true
			apdu = append([]byte{cla | 0b00010000, ins, p1, p2, byte(249)}, data[0:249]...)
		} else {
			apdu = append([]byte{cla, ins, p1, p2, byte(len(data))}, data...)
		}
	} else {
		apdu = []byte{cla, ins, p1, p2}
	}

	if debug { log.Printf(">> %X\n", apdu) }
	resBytes, err := card.Transmit(apdu)	
	if err != nil {
		return nil, err
	}
	if debug { log.Printf("<< %X\n", resBytes) }

	res := &apduResponse{
		statusWord: resBytes[len(resBytes)-2:],
		data: resBytes[0:len(resBytes)-2],
	}

	for res.statusWord[0] == 0x61 {
		continueApdu := []byte{isoInterindustryCla, pivGetRespINS, 0x00, 0x00, res.statusWord[1]}
		if debug { log.Printf(">> %X\n", continueApdu) }
		continueBytes, err := card.Transmit(continueApdu)
		if err != nil {
			return nil, err
		}
		if debug { log.Printf("<< %X\n", continueBytes) }

		res.statusWord = continueBytes[len(continueBytes)-2:]
		res.data = append(res.data, continueBytes[0:len(continueBytes)-2]...)
	}

	if chaining && bytes.Equal(res.statusWord, []byte{0x90, 0x00}) {
		return sendApdu(card, cla, ins, p1, p2, data[249:])
	}

	return res, nil
}

func parseBerTlv(b []byte) (*asn1.RawValue, error) {
	var rawValue asn1.RawValue
	_, err := asn1.Unmarshal(b, &rawValue)
	if err != nil {
		return nil, err
	}
	return &rawValue, nil
}

func keyReferenceToSlot(key KeyReference) Slot {
	switch key {
		case AuthenticationKey:
			return AuthenticationSlot
		case DigitalSignatureKey:
			return DigitalSignatureSlot
		case KeyManagementKey:
			return KeyManagementSlot
		case CardAuthenticationKey:
			return CardAuthenticationSlot
	}
	return nil
}
