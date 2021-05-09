package mycrypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
)

func Encrypt(dataOrigin []byte, publicKey *rsa.PublicKey) (dataEncrypt []byte, err error) {

	rng := rand.Reader

	dataEncrypt, err = rsa.EncryptPKCS1v15(rng, publicKey, dataOrigin)

	if err != nil {
		return
	}

	return
}

func Decrypt(dataEncrypt []byte, privateKey *rsa.PrivateKey) (dataDecript []byte, err error) {

	rng := rand.Reader

	dataDecript, err = rsa.DecryptPKCS1v15(rng, privateKey, dataEncrypt)

	if err != nil {
		return
	}

	return
}

func GetPrivateKey(nameFile string) (privateKey *rsa.PrivateKey, err error) {

	dataKeyPrivada, err := ioutil.ReadFile(nameFile)

	if err != nil {
		return
	}

	block, _ := pem.Decode(dataKeyPrivada)

	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes

	if enc {
		fmt.Println("1 is encrypted pem block")

		b, err = x509.DecryptPEMBlock(block, []byte("cfabrica46"))

		if err != nil {
			return
		}
	}

	privateKey, err = x509.ParsePKCS1PrivateKey(b)

	if err != nil {
		return
	}

	return

}

func GetPublicKey(nameFile string) (publicKey *rsa.PublicKey, err error) {

	dataKeyPublic, err := ioutil.ReadFile(nameFile)

	if err != nil {
		return
	}

	block, _ := pem.Decode(dataKeyPublic)

	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes

	if enc {
		fmt.Println("2 is encrypted pem block")

		b, err = x509.DecryptPEMBlock(block, []byte(""))

		if err != nil {
			return
		}

	}

	ifc, err := x509.ParsePKIXPublicKey(b)

	if err != nil {

		log.Fatal(err)

	}

	publicKey, ok := ifc.(*rsa.PublicKey)

	if !ok {

		log.Fatal("no es llave publica")

	}
	return
}
