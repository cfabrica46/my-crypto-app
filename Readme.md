# Commands

## Generar Keys

### Generate a private key
~~~
./my-crypto-app genprivatersa -b 2048 -o key.pem
~~~

### Generate corresponding public key
~~~
./my-crypto-app genpublicrsa -i key.pem -o public.pem
~~~

## Encrypt/Decrypt

### Encrypt
~~~
./my-crypto-app encrypt -f texto.txt -k public.pem -o encrypt.enc
~~~

### Decrypt
~~~
./my-crypto-app decrypt -f encrypt.enc -k key.pem -o decrypt.txt
~~~