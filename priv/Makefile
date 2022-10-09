all: client.crt.pem client.key.pem

# NOTE: These are BankID test certificates and the they are well known (including
# the password)

client.crt.pem:
	openssl pkcs12 -in FPTestcert3_20200618.p12 -out client.crt.pem -clcerts -nokeys -passin 'pass:qwerty123'
#-legacy

client.key.pem:
	openssl pkcs12 -in FPTestcert3_20200618.p12 -out client.key.pem -nocerts -nodes -passin 'pass:qwerty123'
#-legacy

clean:
	rm -f client.crt.pem client.key.pem
