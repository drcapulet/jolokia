#!/bin/bash -ex

# Generate the CA
cfssl gencert -config cfssl.json -initca ca/csr.json | cfssljson -bare ca/ca

# Generate the server cert
cfssl gencert -config cfssl.json -profile server -ca ca/ca.pem -ca-key ca/ca-key.pem server/csr.json | cfssljson -bare server/server
openssl pkcs12 -export -clcerts -in server/server.pem -inkey server/server-key.pem -password pass:changeit -out server/server.p12
keytool -importkeystore -srckeystore server/server.p12 -srcstoretype PKCS12 -destkeystore server/server.jks -deststoretype JKS -srcstorepass changeit -deststorepass changeit
rm -f server/server.p12

# Generate the client/self-signed-with-key-usage cert
cfssl selfsign -config cfssl.json -profile client-with-key-usage localhost client/self-signed-with-key-usage/csr.json | cfssljson -bare client/self-signed-with-key-usage/client
openssl pkcs12 -export -clcerts -in client/self-signed-with-key-usage/client.pem -inkey client/self-signed-with-key-usage/client-key.pem -password pass:1234 -out client/self-signed-with-key-usage/client.p12

# Generate the client/with-key-usage cert
cfssl gencert -config cfssl.json -profile client-with-key-usage -ca ca/ca.pem -ca-key ca/ca-key.pem client/with-key-usage/csr.json | cfssljson -bare client/with-key-usage/client
openssl pkcs12 -export -clcerts -in client/with-key-usage/client.pem -inkey client/with-key-usage/client-key.pem -password pass:1234 -out client/with-key-usage/client.p12

# Generate the client/with-wrong-key-usage cert
cfssl gencert -config cfssl.json -profile server -ca ca/ca.pem -ca-key ca/ca-key.pem client/with-wrong-key-usage/csr.json | cfssljson -bare client/with-wrong-key-usage/client
openssl pkcs12 -export -clcerts -in client/with-wrong-key-usage/client.pem -inkey client/with-wrong-key-usage/client-key.pem -password pass:1234 -out client/with-wrong-key-usage/client.p12

# Generate the client/without-key-usage cert
cfssl gencert -config cfssl.json -profile client-without-key-usage -ca ca/ca.pem -ca-key ca/ca-key.pem client/without-key-usage/csr.json | cfssljson -bare client/without-key-usage/client
openssl pkcs12 -export -clcerts -in client/without-key-usage/client.pem -inkey client/without-key-usage/client-key.pem -password pass:1234 -out client/without-key-usage/client.p12
