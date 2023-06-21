# gopiv
A [NIST 800-73-4](http://dx.doi.org/10.6028/NIST.SP.800-73-4) standards compliant PIV library written in Go, with support for additional card management functionality offered by various manufacturers' proprietary extensions to the PIV protocol. Work in progress.

## Use
Uses the [scard](https://github.com/ebfe/scard) go library to interact with the underlying smartcard.

```go
ctx, err := scard.EstablishContext()
if err != nil {
	log.Fatalln(err)
}

readers, err := ctx.ListReaders()
if err != nil {
	log.Fatalln(err)
}

if len(readers) == 0 {
	log.Fatalln("No connected smartcard readers")
}

card, err := ctx.Connect(readers[0], scard.ShareShared, scard.ProtocolAny)
if err != nil {
	log.Fatalln(err) // No smartcard inserted in reader
}

defer card.Disconnect(scard.ResetCard)

pivCard, err := gopiv.GetPivCard(card)
if err != nil {
	log.Fatalln(err) // Connected smartcard supports PIV
}

cert, err := pivCard.GetCertificate(gopiv.AuthenticationSlot)
if err != nil {
	log.Fatalln(err)
}

log.Println(cert.Subject.CommonName)

if yubikey, ok := pivCard.(*gopiv.Yubikey); ok {
	// Connected smartcard supports Yubico's PIV extensions

	attestation, err := yubikey.Attest(gopiv.AuthenticationKey)
	if err != nil {
		log.Fatalln(err)
	}

	log.Println(cert.Subject.CommonName)
}

```
