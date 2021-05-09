package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"

	"github.com/cfabrica46/my-crypto-app/mycrypto"
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
	cmdGenPrivateRsa := flag.NewFlagSet("genprivatersa", flag.ExitOnError)
	cmdGenPublicRsa := flag.NewFlagSet("genpublicrsa", flag.ExitOnError)

	if len(os.Args) == 1 {
		flag.Usage()
		return
	}

	switch os.Args[1] {
	case "encrypt":

		f := cmdEncrypt.String("f", "", "Introduzca el nombre del archivo a encriptar/desencriptar")
		k := cmdEncrypt.String("k", "", "Introduzca el nombre del archivo de la key")
		o := cmdEncrypt.String("o", "", "Introduzca el nombre que tendra el archivo destino")
		cmdEncrypt.Parse(os.Args[2:])

		if *f == "" {
			fmt.Println("Error: Seleccione alguna opcion")
			return
		}

		if *k == "" {
			fmt.Println("Error: Seleccione alguna opcion")
			return
		}

		if *o == "" {
			fmt.Println("Error: Seleccione el nombre del archivo destino")
			return
		}

		publicKey, err := mycrypto.GetPublicKey(*k)

		if err != nil {
			fmt.Println("Error Al leer la key, asegurese que el archivo tenga los permisos requeridos")
			return
		}

		dataOrigin, err := ioutil.ReadFile(*f)

		if err != nil {
			fmt.Println("Error Al leer archivo a encriptar, asegurese que el archivo tenga los permisos requeridos")
			return
		}

		dataEncrypt, err := mycrypto.Encrypt(dataOrigin, publicKey)

		if err != nil {
			fmt.Printf("Error al encriptar el archivo, verifique si ingreso correctamente la llave publica\n")
			return
		}

		err = ioutil.WriteFile(*o, dataEncrypt, 0644)

		if err != nil {
			fmt.Printf("Error al generar archivo encriptado\n")
			return
		}

	case "decrypt":

		f := cmdDecrypt.String("f", "", "Introduzca el nombre del archivo a encriptar/desencriptar")
		k := cmdDecrypt.String("k", "", "Introduzca el nombre del archivo de la key")
		o := cmdDecrypt.String("o", "", "Introduzca el nombre que tendra el archivo destino")
		cmdDecrypt.Parse(os.Args[2:])

		if f == nil {
			fmt.Println("Error: Seleccione alguna opcion")
			return
		}

		if *k == "" {
			fmt.Println("Error: Seleccione alguna opcion")
			return
		}

		if *o == "" {
			fmt.Println("Error: Seleccione el nombre del archivo destino")
			return
		}

		privateKey, err := mycrypto.GetPrivateKey(*k)

		if err != nil {
			fmt.Println("Error Al leer la key, asegurese que el archivo tenga los permisos requeridos")
			return
		}

		dataEncrypt, err := ioutil.ReadFile(*f)

		if err != nil {
			fmt.Println("Error Al leer archivo a encriptar, asegurese que el archivo tenga los permisos requeridos")
			return
		}

		dataDecript, err := mycrypto.Decrypt(dataEncrypt, privateKey)

		if err != nil {
			fmt.Printf("Error al desencriptar el archivo, verifique si ingreso correctamente la llave publica\n")
			return
		}

		err = ioutil.WriteFile(*o, dataDecript, 0644)

		if err != nil {
			fmt.Printf("Error al generar archivo desencriptado\n")
			return
		}

	case "genprivatersa":

		b := cmdGenPrivateRsa.String("b", "", "Introduzca el tamaño de bytes que tendra la llave(1024,2048,3072)")
		o := cmdGenPrivateRsa.String("o", "", "Introduzca el nombre que tendra el archivo destino")
		cmdGenPrivateRsa.Parse(os.Args[2:])

		if *o == "" {
			fmt.Println("Error: Seleccione el nombre del archivo destino")
			return
		}

		if *b == "" && *b != "1024" && *b != "2048" && *b != "3072" {
			fmt.Println("Error: Seleccione el tamaño de bytes que tendra la llave(1024,2048,3072)")
			return
		}

		keyBytes, err := strconv.Atoi(*b)

		if err != nil {
			fmt.Println("Ocurrio un error interno")
			return
		}

		privateKey, err := rsa.GenerateKey(rand.Reader, keyBytes)

		if err != nil {
			fmt.Println("Ocurrio un error interno")
			return
		}

		x509PrivateKey := x509.MarshalPKCS1PrivateKey(privateKey)

		privateKeyBlock := &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509PrivateKey,
		}

		privateKeyFile, err := os.Create(*o)

		if err != nil {
			fmt.Println("Error al generar archivo key")
		}

		defer privateKeyFile.Close()

		err = pem.Encode(privateKeyFile, privateKeyBlock)

		if err != nil {
			fmt.Println("Error al generar key ")
			return
		}

	case "genpublicrsa":

		i := cmdGenPublicRsa.String("i", "", "Introduzca el nombre de la llave privada necesaria para generar la llave publica")
		o := cmdGenPublicRsa.String("o", "", "Introduzca el nombre que tendra el archivo destino")
		cmdGenPublicRsa.Parse(os.Args[2:])

		if *i == "" {
			fmt.Println("Error: Seleccione el nombre de la llave privada necesaria para generar la llave publica")
			return
		}

		if *o == "" {
			fmt.Println("Error: Seleccione el nombre del archivo destino")
			return
		}

		privateKey, err := mycrypto.GetPrivateKey(*i)

		if err != nil {
			fmt.Println("Error al leer Private Key")
			return
		}

		publicKey := &privateKey.PublicKey

		x509PublicKey, err := x509.MarshalPKIXPublicKey(publicKey)

		if err != nil {
			fmt.Println("Ocurrio un error interno")
			return
		}

		publicKeyBlock := &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: x509PublicKey,
		}

		publicKeyFile, err := os.Create(*o)

		if err != nil {
			fmt.Println("Error al generar key publica")
			return
		}

		defer publicKeyFile.Close()

		err = pem.Encode(publicKeyFile, publicKeyBlock)

		if err != nil {
			fmt.Println("Error al generar key publica")
			return
		}

	default:
		flag.Usage()
		return
	}

	fmt.Println("Operacion realizada con éxito")

}
