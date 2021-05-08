# Commands

## generate a private key
~~~
openssl genrsa -out key.pem 3072
~~~

## generate corresponding public key
~~~
openssl rsa -in key.pem -pubout -out public.pem
~~~