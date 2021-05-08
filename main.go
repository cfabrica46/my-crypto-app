package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
)

func main() {

	flag.Usage = func() {
		documentacion := `Las opciones disponibles son
simetric Para encriptar/desencriptar con llave simetrica
asimetric Para encriptar/desencriptar con llave asimetrica`

		fmt.Fprintf(os.Stderr, "%s\n", documentacion)

	}

	cmdEncrypt := flag.NewFlagSet("encrypt", flag.ExitOnError)
	cmdDecrypt := flag.NewFlagSet("decrypt", flag.ExitOnError)

	if len(os.Args) == 1 {
		flag.Usage()
		return
	}

	switch os.Args[1] {
	case "encrypt":

		f := cmdEncrypt.String("f", "", "Introduzca el nombre del archivo a encriptar/desencriptar")
		k := cmdEncrypt.String("k", "", "Introduzca el nombre del archivo de la key")
		cmdEncrypt.Parse(os.Args[2:])

		if *f == "" {
			fmt.Println("Error: Seleccione alguna opcion. Para mas informacion ejecute 'go run main.go simetric -h'")
			return
		}

		if *k == "" {
			fmt.Println("Error: Seleccione alguna opcion. Para mas informacion ejecute 'go run main.go simetric -h'")
			return
		}

		publicKey, err := getPublicKey(*k)

		if err != nil {
			fmt.Println("Error Al leer la key, asegurese que el archivo tenga los permisos requeridos")
			return
		}

		file, err := os.Open(*f)

		if err != nil {
			fmt.Println("Error Al abir archivo a encriptar, asegurese que el archivo exista")
			return
		}

		defer file.Close()

		dataOrigin, err := ioutil.ReadAll(file)

		if err != nil {
			fmt.Println("Error Al leer archivo a encriptar, asegurese que el archivo tenga los permisos requeridos")
			return
		}

		newName := fmt.Sprintf("%s.enc", file.Name())

		dataEncrypt, err := encrypt(dataOrigin, publicKey)

		if err != nil {
			fmt.Printf("Error al encriptar el archivo, verifique si ingreso correctamente la llave publica\n")
		}

		err = ioutil.WriteFile(newName, dataEncrypt, 0644)

		if err != nil {
			fmt.Printf("Error al generar archivo encriptado\n")
		}

	case "decrypt":

		f := cmdDecrypt.String("f", "", "Introduzca el nombre del archivo a encriptar/desencriptar")
		k := cmdEncrypt.String("k", "", "Introduzca el nombre del archivo de la key")
		cmdDecrypt.Parse(os.Args[2:])

		if f == nil {
			fmt.Println("Error: Seleccione alguna opcion. Para mas informacion ejecute 'go run main.go asimetric -h'")
			return
		}

		if *k == "" {
			fmt.Println("Error: Seleccione alguna opcion. Para mas informacion ejecute 'go run main.go simetric -h'")
			return
		}

	default:
		flag.Usage()
	}

	fmt.Println("Operacion realizada con éxito")

}

func encrypt(dataOrigin []byte, publicKey *rsa.PublicKey) (dataEncrypt []byte, err error) {

	rng := rand.Reader

	dataEncrypt, err = rsa.EncryptPKCS1v15(rng, publicKey, dataOrigin)

	if err != nil {
		return
	}

	return
}

func getPublicKey(nameFile string) (publicKey *rsa.PublicKey, err error) {

	dataKeyPublic, err := ioutil.ReadFile(nameFile)

	if err != nil {
		return
	}

	block, _ := pem.Decode(dataKeyPublic)

	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes

	if enc {
		fmt.Println("2 is encrypted pem block")

		b, err = x509.DecryptPEMBlock(block, []byte("cfabrica46"))

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
