// Binary tpmtls is a POC for TPM-based TLS.
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"time"

	"github.com/awly/tpmtls/tpmkey"
	"github.com/google/go-tpm/tpm2"
)

func main() {
	pk, err := tpmkey.PrimaryECC("/dev/tpm0", tpm2.HandleOwner)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer pk.Close()

	fmt.Println("loadKey OK")

	crt, err := createClientCert(pk)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("createClientCert OK")

	srv, err := startServer()
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("startServer OK")
	defer srv.Close()

	conn, err := tls.Dial("tcp", srv.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return crt, nil
		},
	})
	if err != nil {
		fmt.Println("tls.Dial:", err)
		return
	}
	defer conn.Close()
	fmt.Println("dial OK")

	if _, err := conn.Write([]byte("hi")); err != nil {
		fmt.Println("Write:", err)
		return
	}
	resp := make([]byte, 1024)
	count, err := conn.Read(resp)
	if err != nil {
		fmt.Println("Read:", err)
		return
	}
	if got := string(resp[:count]); got == "hi" {
		fmt.Println("echo message OK")
	} else {
		fmt.Printf("echo message wrong, got: %q\n", got)
	}
}

func createClientCert(pk crypto.Signer) (*tls.Certificate, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %s", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, pk.Public(), pk)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %s", err)
	}

	return &tls.Certificate{PrivateKey: pk, Leaf: template, Certificate: [][]byte{derBytes}}, nil
}

func createServerCert() (*tls.Certificate, error) {
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %s", err)
	}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %s", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, pk.Public(), pk)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %s", err)
	}

	return &tls.Certificate{PrivateKey: pk, Leaf: template, Certificate: [][]byte{derBytes}}, nil
}

func startServer() (net.Listener, error) {
	crt, err := createServerCert()
	if err != nil {
		return nil, err
	}

	lis, err := tls.Listen("tcp", ":0", &tls.Config{
		Certificates: []tls.Certificate{*crt},
		ClientAuth:   tls.RequireAnyClientCert,
	})
	if err != nil {
		return nil, err
	}

	go func() {
		conn, err := lis.Accept()
		if err != nil {
			fmt.Println("Accept:", err)
			return
		}
		fmt.Println("Accept OK")
		io.Copy(conn, conn)
	}()

	return lis, nil
}
