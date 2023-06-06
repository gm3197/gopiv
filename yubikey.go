package gopiv

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/rand"
	"strconv"
)

var (
	yubikeyGetVersionINS byte = 0xFD
	yubikeyGetSerialINS byte = 0xF8
	yubikeySetManagementKeyINS byte = 0xFF
	yubikeyAttestINS byte = 0xF9

	YkAttestationSlot Slot = []byte{0x5F, 0xFF, 0x01}
	YkAttestationKey KeyReference = 0xF9
)

type Yubikey struct {
	*GenericPivCard
	version []byte
}

func (y *Yubikey) GetVersion() (string, error) {
	return fmt.Sprintf("%d.%d.%d", y.version[0], y.version[1], y.version[2]), nil
}

func (y *Yubikey) GetSerialNumber() ([]byte, error) {
	res, err := sendApdu(y.sCard, isoInterindustryCla, yubikeyGetSerialINS, 0x00, 0x00, nil)
	if err != nil {
		return nil, err 
	}
	
	if !res.IsSuccess() {
		return nil, res.Error()
	}

	return res.data, nil
}

func (y *Yubikey) SetManagementKey(newManagementKey []byte) error {
	if len(newManagementKey) != 24 {
		return errors.New("3DES management keys must be 24 bytes")
	}

	res, err := sendApdu(y.sCard, isoInterindustryCla, yubikeySetManagementKeyINS, 0xFF, 0xFF, append([]byte{byte(ThreeDesKey), byte(ManagementKey), 24}, newManagementKey...))
	if err != nil {
		return err
	}

	if !res.IsSuccess() {
		return res.Error()
	}

	return nil
}

func (y *Yubikey) ResetToDefaults() error {
	y.DeAuthenticate(CardholderPIN)

	pinRemainingAttempts := -1
	for pinRemainingAttempts != 0 {
		randomIncorrectPin := 10000000 + rand.Intn(99999999-10000000)
		randomIncorrectPinStr := strconv.Itoa(randomIncorrectPin)

		pinStatus, err := y.Authenticate(CardholderPIN, randomIncorrectPinStr)
		if err != nil {
			return err
		}
		pinRemainingAttempts = *pinStatus.RemainingAttempts
	}

	pukRemainingAttempts := -1
	for pukRemainingAttempts != 0 {
		randomIncorrectPin := 10000000 + rand.Intn(99999999-10000000)
		randomIncorrectPinStr := strconv.Itoa(randomIncorrectPin)

		pukStatus, err := y.UnblockPIN(randomIncorrectPinStr, "000000")
		if err != nil {
			return err
		}
		pukRemainingAttempts = *pukStatus.RemainingAttempts
	}

	res, err := sendApdu(y.sCard, isoInterindustryCla, 0xFB, 0x00, 0x00, nil)
	if err != nil {
		return err
	}

	if !res.IsSuccess() {
		return res.Error()
	}

	return nil
}

func (y *Yubikey) Attest(key KeyReference) (*x509.Certificate, error) {
	res, err := sendApdu(y.sCard, isoInterindustryCla, yubikeyAttestINS, byte(key), 0x00, nil)
	if err != nil {
		return nil, err
	}

	if !res.IsSuccess() {
		return nil, res.Error()
	}

	var certBytes []byte
	if res.data[0] == 0x70 {
		var cert asn1.RawValue
		_, err = asn1.Unmarshal(res.data, &cert)
		if err != nil {
			return nil, err
		}
		certBytes = cert.Bytes
	} else {
		certBytes = res.data
	}

	return x509.ParseCertificate(certBytes)
}
