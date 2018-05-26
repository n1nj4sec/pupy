package main

import (
	"fmt"
	"path"

	"io/ioutil"

	"crypto/tls"
	"crypto/x509"
	"strconv"
	"strings"

	"flag"

	log "github.com/sirupsen/logrus"
	iniflags "github.com/vharitonsky/iniflags"
)

var (
	ProxyBindHost         = "0.0.0.0"
	ExternalBindHost      = "0.0.0.0"
	ProxyBindPort    uint = 9876
	DnsBindPort      uint = 5454
	ProxyHostname         = ""
	UDPSize          uint = 1400
	ListenerCA            = path.Join("..", "crypto", "proxy-ca.crt")
	ListenerCAKey         = path.Join("..", "crypto", "proxy-ca.key")
	ListenerKey           = path.Join("..", "crypto", "proxy.key")
	ListenerCert          = path.Join("..", "crypto", "proxy.crt")
	ClientKey             = path.Join("..", "crypto", "proxy-client.key")
	ClientCert            = path.Join("..", "crypto", "proxy-client.crt")

	PortMaps []PortMap

	OnListenerEnabledURL  = ""
	OnListenerDisabledURL = ""

	ListenerConfig *tls.Config
)

func init() {
	generate := false
	loglevel := "ERROR"
	portmap := ""

	flag.StringVar(&ProxyBindHost, "listen-proxy", ProxyBindHost, "IP address to bind pupysh listener side")
	flag.UintVar(&ProxyBindPort, "port-proxy", ProxyBindPort, "Port to bind pupysh listener side")
	flag.StringVar(&ExternalBindHost, "listen", ExternalBindHost, "IP address to bind services listener side")
	flag.UintVar(&DnsBindPort, "dns-port", DnsBindPort, "Port to bind DNS listeners (if any)")
	flag.UintVar(&UDPSize, "udp-mtu-size", UDPSize, "MTU Size for DNS and KCP UDP Packets")
	flag.StringVar(&ListenerCA, "ca", ListenerCA, "Path to CA certificate (pupysh side)")
	flag.StringVar(&ListenerKey, "key", ListenerKey, "Path to TLS key (pupysh side)")
	flag.StringVar(&ListenerCert, "cert", ListenerCert, "Path to TLS cert (pupysh side)")
	flag.StringVar(&portmap, "port-map", portmap, "Automatically substitute ports (example: \"443:1443 80:8080\")")
	flag.StringVar(&ProxyHostname, "hostname-proxy", ProxyHostname,
		"Hostname for pupysh listener side (used with generate)")
	flag.StringVar(&loglevel, "loglevel", loglevel, "Set log level")
	flag.StringVar(&OnListenerEnabledURL, "on-enabled-url", OnListenerEnabledURL,
		"Send GET request when at least one client connected")
	flag.StringVar(&OnListenerDisabledURL, "on-disabled-url", OnListenerDisabledURL,
		"Send GET request when at least one client connected")
	flag.BoolVar(&generate, "generate", false, "Generate all the keys")

	iniflags.Parse()

	switch strings.ToLower(loglevel) {
	case "error":
		log.SetLevel(log.ErrorLevel)
	case "err":
		log.SetLevel(log.ErrorLevel)
	case "warning":
		log.SetLevel(log.WarnLevel)
	case "warn":
		log.SetLevel(log.WarnLevel)
	case "info":
		log.SetLevel(log.InfoLevel)
	case "debug":
		log.SetLevel(log.DebugLevel)
	default:
		log.Fatalln("Invalid log level", loglevel)
	}

	if strings.Contains(portmap, ":") {
		for _, mapping := range strings.Split(portmap, " ") {
			if !strings.Contains(portmap, ":") {
				continue
			}

			parts := strings.Split(mapping, ":")
			if len(parts) != 2 {
				log.Fatalln("Invalid mapping specification: ", parts)
			}

			var (
				from, to int
				err      error
			)

			from, err = strconv.Atoi(parts[0])
			if err != nil {
				log.Fatalln("Invalid mapping specification: ", parts, "From: ", err)
			}

			to, err = strconv.Atoi(parts[1])
			if err != nil {
				log.Fatalln("Invalid mapping specification: ", parts, "To: ", err)
			}

			PortMaps = append(PortMaps, PortMap{
				From: from,
				To:   to,
			})

		}
	}

	if strings.Index(ProxyBindHost, ":") == -1 {
		if ExternalBindHost == "0.0.0.0" {
			ExternalBindHost = ProxyBindHost
		}

		ProxyBindHost = fmt.Sprintf("%s:%d", ProxyBindHost, ProxyBindPort)
	} else {
		if ExternalBindHost == "0.0.0.0" {
			ExternalBindHost = strings.SplitN(ProxyBindHost, ":", 1)[0]
		}
	}

	if strings.Index(ExternalBindHost, ":") != -1 {
		log.Fatalln("External IP address should be specified without port")
	}

	if generate {
		log.Warn("Genrating NEW keys")
		generateKeys()
	}

	cert, err := tls.LoadX509KeyPair(ListenerCert, ListenerKey)
	if err != nil {
		log.Fatalln(err)
	}

	pem, err := ioutil.ReadFile(ListenerCA)
	if err != nil {
		log.Fatalln(err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(pem) {
		log.Fatalln("Could't append CA certificates to CA pool")
	}

	ListenerConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  caPool,
		NextProtos: []string{"pp/1"},
	}
}

func main() {
	NewDaemon(ProxyBindHost).ListenAndServe()
}
