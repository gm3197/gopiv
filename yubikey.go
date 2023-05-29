package gopiv

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

var (
	yubikeyGetVersionINS byte = 0xFD
	yubikeyGetSerialINS byte = 0xF8
	yubikeySetManagementKeyINS byte = 0xFF
)

type Yubikey struct {
	*GenericPivCard
	version []byte
}

func (y *Yubikey) GetVersion() (string, error) {
	return fmt.Sprintf("%d.%d.%d", y.version[0], y.version[1], y.version[2]), nil
}

func (y *Yubikey) GetSerialNumber() (int32, error) {
	res, err := sendApdu(y.sCard, isoInterindustryCla, yubikeyGetSerialINS, 0x00, 0x00, nil)
	if err != nil {
		return 0, err 
	}
	
	if !res.IsSuccess() {
		return 0, res.Error()
	}

	var serial int32 
	err = binary.Read(bytes.NewReader(res.data), binary.BigEndian, &serial)
	if err != nil {
		return 0, err
	}

	return serial, nil
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
