// Binary tpmtls is a simple POC of TPM-based TLS oracle.
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

func main() {
	pk, err := loadKey()
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

type privateKey struct {
	rwc io.ReadWriteCloser
	h   tpmutil.Handle
	pub *rsa.PublicKey
}

func loadKey() (*privateKey, error) {
	rwc, err := tpmutil.OpenTPM("/dev/tpm0")
	if err != nil {
		return nil, err
	}
	public := tpm2.Public{
		Type:       tpm2.AlgRSA,
		NameAlg:    tpm2.AlgSHA1,
		Attributes: tpm2.FlagSign | tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth,
		RSAParameters: &tpm2.RSAParams{
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgRSASSA,
				Hash: tpm2.AlgSHA256,
			},
			KeyBits:  2048,
			Exponent: uint32(0x00010001),
			Modulus:  big.NewInt(0),
		},
	}

	h, pub, err := tpm2.CreatePrimary(rwc, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", public)
	if err != nil {
		rwc.Close()
		return nil, err
	}

	return &privateKey{rwc: rwc, h: h, pub: pub}, nil
}

func (pk *privateKey) Close() {
	if pk.rwc == nil {
		return
	}
	defer pk.rwc.Close()
	if pk.h != 0 {
		tpm2.FlushContext(pk.rwc, pk.h)
	}
}

func (pk *privateKey) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	_, sig, err := tpm2.Sign(pk.rwc, pk.h, digest)
	fmt.Printf("Sign(%x) = %x\n", digest, sig)
	return sig, err
}

func (pk *privateKey) Public() crypto.PublicKey { return pk.pub }

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
		for {
			conn, err := lis.Accept()
			if err != nil {
				fmt.Println("Accept:", err)
				return
			}
			fmt.Println("Accept OK")
			go io.Copy(conn, conn)
		}
	}()

	return lis, nil
}
