package main

// The execution's CA (README S-16; validation.md S-16) and the leaf certificates signed with it, laid out as mitmproxy
// 12.3.1 lays them out for the Python frontend: <confdir>/mitmproxy-ca.pem holds key then certificate; --ca-dir copies
// the cell's ca.key and ca.pem there (engine_frontend.py prepare_ca); without it a CA is made once and its certificate
// is also written to <confdir>/mitmproxy-ca-cert.pem (tests). Leaves follow certs.py get_cert/dummy_cert: subject
// names are the client's SNI (or the local address) and the CONNECT host, the key is the CA's own key, validity runs
// from two days back for 199 days, and the chain served is the leaf then every certificate in the CA file.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	validityOffset = -2 * 24 * time.Hour
	leafLifetime   = 199 * 24 * time.Hour
	caLifetime     = 10 * 365 * 24 * time.Hour
	cacheCap       = 100 // mitmproxy's certificate store keeps its last 100 entries
)

type certStore struct {
	ca    *x509.Certificate
	key   crypto.Signer // the CA's key, also the leaves' key
	chain [][]byte      // every certificate in the CA file, in order
	mu    sync.Mutex
	cache map[string]*tls.Certificate
}

func prepareCA(confdir, caDir string) (*certStore, error) {
	if err := os.MkdirAll(confdir, 0o700); err != nil {
		return nil, err
	}
	target := filepath.Join(confdir, "mitmproxy-ca.pem")
	if caDir != "" {
		key, err := os.ReadFile(filepath.Join(caDir, "ca.key"))
		if err != nil {
			return nil, err
		}
		cert, err := os.ReadFile(filepath.Join(caDir, "ca.pem"))
		if err != nil {
			return nil, err
		}
		if err := writeFile(target, append(key, cert...), 0o600); err != nil {
			return nil, err
		}
	}
	raw, err := os.ReadFile(target)
	if errors.Is(err, fs.ErrNotExist) {
		raw, err = createCA(confdir, target)
	}
	if err != nil {
		return nil, err
	}
	pair, err := tls.X509KeyPair(raw, raw) // key and certificates from the one file; the key must match the first
	if err != nil {
		return nil, fmt.Errorf("%s: %w", target, err)
	}
	key, ok := pair.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("%s: the key cannot sign", target)
	}
	ca := pair.Leaf
	if ca == nil {
		if ca, err = x509.ParseCertificate(pair.Certificate[0]); err != nil {
			return nil, err
		}
	}
	return &certStore{ca: ca, key: key, chain: pair.Certificate, cache: map[string]*tls.Certificate{}}, nil
}

func writeFile(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func serial() (*big.Int, error) { return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127)) }

// createCA makes the tests' CA when no --ca-dir is given (mitmproxy makes an RSA-2048 one; P-256 here).
func createCA(confdir, target string) ([]byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	name := pkix.Name{CommonName: "mitmproxy", Organization: []string{"mitmproxy"}}
	tmpl := &x509.Certificate{
		SerialNumber: sn, Subject: name, Issuer: name,
		NotBefore: now.Add(validityOffset), NotAfter: now.Add(validityOffset + caLifetime),
		BasicConstraintsValid: true, IsCA: true,
		KeyUsage:    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, err
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	combined := append(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}), certPEM...)
	if err := writeFile(target, combined, 0o600); err != nil {
		return nil, err
	}
	if err := writeFile(filepath.Join(confdir, "mitmproxy-ca-cert.pem"), certPEM, 0o644); err != nil {
		return nil, err
	}
	return combined, nil
}

// leaf returns the certificate for these subject names, signing it on first use.
func (s *certStore) leaf(names []string) (*tls.Certificate, error) {
	id := strings.Join(names, "\x00")
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.cache[id]; ok {
		return c, nil
	}
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: sn,
		NotBefore:    now.Add(validityOffset), NotAfter: now.Add(validityOffset + leafLifetime),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if len(names[0]) < 64 {
		tmpl.Subject.CommonName = names[0]
	}
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, n)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, s.ca, s.key.Public(), s.key)
	if err != nil {
		return nil, err
	}
	if len(s.cache) >= cacheCap {
		s.cache = map[string]*tls.Certificate{}
	}
	c := &tls.Certificate{Certificate: append([][]byte{der}, s.chain...), PrivateKey: s.key}
	s.cache[id] = c
	return c, nil
}

// pickALPN is mitmproxy's alpn_select_callback with http2=False: the client's first HTTP/1 protocol, else none at all
// (OpenSSL's no-ack: the handshake goes on without ALPN).
func pickALPN(offered []string) []string {
	for _, p := range offered {
		if p == "http/1.1" || p == "http/1.0" || p == "http/0.9" {
			return []string{p}
		}
	}
	return nil
}

func (s *certStore) serverConfig(connectHost, local string) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			first := hello.ServerName
			if first == "" {
				first = local
			}
			names := []string{first}
			if connectHost != first {
				names = append(names, connectHost)
			}
			cert, err := s.leaf(names)
			if err != nil {
				return nil, err
			}
			return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{*cert},
				NextProtos: pickALPN(hello.SupportedProtos)}, nil
		},
	}
}
