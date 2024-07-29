.DEFAULT_GOAL: all

version = $(shell date +"%Y-%m-%d").$(shell git rev-list --count HEAD)

.PHONY: all
all: build

.PHONY: build
build:
	go build -o ndfs main.go

.PHONY: test
test: build
	go vet ./...
	go test -v ./...

.PHONY: functional-test
functional-test:
	cd test && ./functional

.PHONY: certs
certs:
	rm -f *.pem *.srl || true
	openssl ecparam -genkey -name prime256v1 -noout -out ca-key.pem
	openssl req -new -x509 -sha256 -key ca-key.pem -out ca-cert.pem -days 3650 -subj "/C=US/ST=State/L=City/O=Organization/OU=CA/CN=ca.example.com"
	openssl ecparam -genkey -name prime256v1 -noout -out server-key.pem
	openssl req -new -sha256 -key server-key.pem -out server-req.pem -subj "/C=US/ST=State/L=City/O=Organization/OU=Server/CN=localhost" -addext "subjectAltName = IP:127.0.0.1,DNS:localhost"
	openssl x509 -req -in server-req.pem -days 3650 -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -out server-cert.pem -sha256 -extfile <(printf "subjectAltName=IP:127.0.0.1,DNS:localhost")
	openssl ecparam -genkey -name prime256v1 -noout -out client-key.pem
	openssl req -new -sha256 -key client-key.pem -out client-req.pem -subj "/C=US/ST=State/L=City/O=Organization/OU=Client/CN=client.example.com"
	openssl x509 -req -in client-req.pem -days 3650 -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -out client-cert.pem -sha256
	rm server-req.pem client-req.pem
	ls -la *.pem

.PHONY: tag
tag:
	git tag v$(version)
