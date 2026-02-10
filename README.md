# Snippetbox

## Aboute the Project
The project helps to understand the basics of programming in Go. It covers such topics as handlers, middleware, logging, error handling, authN/authZ, templates, and much more. 

## Getting Started

---

### Installation
```bash
git clone https://github.com/Coldied/snippetbox
cd snippetbox
```
Generate self-signed certificates
```bash
mv ./tls
go run /usr/local/go/src/crypto/tls/generate_cert.go --rsa-bits=2048 --host=localhost
```
Run server
```bash
go run ./cmd/web
```