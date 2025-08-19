package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"time"
)

func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	return tls.X509KeyPair(certPEM, keyPEM)
}

func main() {
	ollamaAddr := os.Getenv("OLLAMA_ADDR")
	if ollamaAddr == "" {
		ollamaAddr = "http://127.0.0.1:11434"
	}
	targetURL, err := url.Parse(ollamaAddr)
	if err != nil {
		log.Fatal("Invalid OLLAMA_ADDR:", err)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "443"
	}
	addr := ":" + port

	// Generate self-signed cert if none provided
	var cert tls.Certificate
	certFile := os.Getenv("TLS_CERT")
	keyFile := os.Getenv("TLS_KEY")
	if certFile != "" && keyFile != "" {
		cert, err = tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			log.Fatal("Failed to load TLS cert/key:", err)
		}
	} else {
		cert, err = generateSelfSignedCert()
		if err != nil {
			log.Fatal("Failed to generate self-signed cert:", err)
		}
		log.Println("Using self-signed TLS certificate")
	}

	proxyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req, err := http.NewRequest(r.Method, targetURL.String()+r.URL.Path, r.Body)
		if err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		req.Header = r.Header

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			http.Error(w, "Upstream error", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		for k, vv := range resp.Header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	})

	server := &http.Server{
		Addr:    addr,
		Handler: proxyHandler,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		},
	}

	log.Println("Starting HTTPS proxy to Ollama at", ollamaAddr, "on port", port)
	err = server.ListenAndServeTLS("", "")
	if err != nil {
		log.Fatal(err)
	}
}
