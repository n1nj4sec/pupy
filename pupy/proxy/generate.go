package main

import (
	"net"

	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
)

func GetOutboundIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP.String()
}

func CheckExternalBindHostIP() bool {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}

	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}

		// handle err
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			// process IP address

			if ip.String() == ExternalBindHost {
				return true
			}
		}
	}

	return false
}

func getCN() string {
	switch {
	case ProxyHostname != "":
		return ProxyHostname

	case CheckExternalBindHostIP():
		return ExternalBindHost

	default:
		return GetOutboundIP()
	}
}

func generateKeys() {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Pupy CA"},
			Country:      []string{"ZZ"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(1, 0, 0),
		IsCA:      true,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	curve := elliptic.P384()

	privCA, _ := ecdsa.GenerateKey(curve, rand.Reader)
	pubCA := &privCA.PublicKey
	ca_b, err := x509.CreateCertificate(rand.Reader, ca, ca, pubCA, privCA)
	if err != nil {
		log.Fatalln("create ca failed", err)
	}

	caSigned, _ := x509.ParseCertificate(ca_b)

	certOut, err := os.Create(ListenerCA)
	if err != nil {
		log.Fatalln("Couldn't save CA certificate:", err)
	}

	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: ca_b})
	certOut.Close()
	log.Info("CA certificate saved to ", ListenerCA)

	keyOut, err := os.OpenFile(ListenerCAKey, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalln("Coulnd't save CA key:", err)
	}

	pk_b, _ := x509.MarshalECPrivateKey(privCA)
	pem.Encode(keyOut, &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: pk_b,
	})
	keyOut.Close()
	log.Info("CA key saved to ", ListenerCA)

	proxyCert := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			Organization: []string{"Pupy"},
			Country:      []string{"ZZ"},
			CommonName:   getCN(),
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		SubjectKeyId: []byte{1},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	proxyPriv, _ := ecdsa.GenerateKey(curve, rand.Reader)
	proxyPub := &proxyPriv.PublicKey

	proxyCert_b, err := x509.CreateCertificate(rand.Reader, proxyCert, caSigned, proxyPub, privCA)
	if err != nil {
		log.Fatalln("Couldn't generate server cert:", err)
	}

	certOut, err = os.Create(ListenerCert)
	if err != nil {
		log.Fatalln("Couldn't save proxy certificate:", err)
	}

	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: proxyCert_b})
	certOut.Close()
	log.Info("Proxy certificate saved to ", ListenerCert)

	keyOut, err = os.OpenFile(ListenerKey, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalln("Coulnd't save proxy key:", err)
	}

	proxyPriv_b, _ := x509.MarshalECPrivateKey(proxyPriv)
	pem.Encode(keyOut, &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: proxyPriv_b,
	})
	keyOut.Close()
	log.Info("Proxy key saved to ", ListenerKey)

	clientCert := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			Organization: []string{"Pupy"},
			Country:      []string{"ZZ"},
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		SubjectKeyId: []byte{2},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	clientPriv, _ := ecdsa.GenerateKey(curve, rand.Reader)
	clientPub := &clientPriv.PublicKey

	clientCert_b, err := x509.CreateCertificate(rand.Reader, clientCert, caSigned, clientPub, privCA)
	if err != nil {
		log.Fatalln("Couldn't generate client cert:", err)
	}

	certOut, err = os.Create(ClientCert)
	if err != nil {
		log.Fatalln("Couldn't save client certificate:", err)
	}

	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: clientCert_b})
	certOut.Close()
	log.Info("Client cert saved to ", ClientCert)

	keyOut, err = os.OpenFile(ClientKey, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalln("Coulnd't save client key:", err)
	}

	clientPriv_b, _ := x509.MarshalECPrivateKey(clientPriv)
	pem.Encode(keyOut, &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: clientPriv_b,
	})
	keyOut.Close()
	log.Info("Client key saved to ", ClientKey)
}
