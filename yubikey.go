package gopiv

import (
	"errors"
	"fmt"
)

var (
	yubikeyGetVersionINS byte = 0xFD
	yubikeyGetSerialINS byte = 0xF8
	yubikeySetManagementKeyINS byte = 0xFF

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
