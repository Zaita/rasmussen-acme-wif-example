// Command rasmussen-acme-wif-example obtains a certificate from an ACME
// server using the wif-01 challenge (draft-rasmussen-acme-wif), presenting
// the GitHub Actions OIDC token of the job it runs in. It is configured
// entirely through environment variables; see README.md.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/mholt/acmez/v3"
	"github.com/mholt/acmez/v3/acme"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(context.Background(), logger); err != nil {
		logger.Error("obtaining certificate", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, logger *slog.Logger) error {
	directoryURL := os.Getenv("ACME_DIRECTORY_URL")
	if directoryURL == "" {
		return errors.New("ACME_DIRECTORY_URL is required")
	}

	lifetime := 5 * time.Minute
	if v := os.Getenv("CERT_LIFETIME"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			return fmt.Errorf("CERT_LIFETIME: invalid duration %q", v)
		}
		lifetime = d
	}
	mtlsURL := os.Getenv("MTLS_TEST_URL")

	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	var summary strings.Builder

	// Baseline: without a client certificate the mTLS endpoint must refuse
	// the request, otherwise the later success would prove nothing.
	if mtlsURL != "" {
		status, body, err := mtlsProbe(ctx, mtlsURL, nil)
		switch {
		case err != nil:
			logger.Info("baseline without client certificate failed as expected", "url", mtlsURL, "error", err)
			fmt.Fprintf(&summary, "| Baseline (no client cert) | failed as expected: `%v` |\n", err)
		case status >= 200 && status < 300:
			return fmt.Errorf("baseline request to %s without a client certificate succeeded (HTTP %d); the endpoint does not enforce mTLS", mtlsURL, status)
		default:
			logger.Info("baseline without client certificate failed as expected", "url", mtlsURL, "status", status, "body", body)
			fmt.Fprintf(&summary, "| Baseline (no client cert) | failed as expected: HTTP %d |\n", status)
		}
	}

	client := acmez.Client{
		Client: &acme.Client{
			Directory: directoryURL,
			UserAgent: "rasmussen-acme-wif-example",
			Logger:    logger,
		},
		ChallengeSolvers: map[string]acmez.Solver{
			acme.ChallengeTypeWIF01: acmez.NewGitHubActionsWIF01Solver(),
		},
	}

	dir, err := client.GetDirectory(ctx)
	if err != nil {
		return fmt.Errorf("fetching directory: %w", err)
	}
	if dir.Meta == nil || dir.Meta.WIF == nil {
		logger.Warn("directory does not advertise wif-01 support (meta.wif); continuing anyway")
	} else if len(dir.Meta.WIF.Issuers) > 0 && !slices.Contains(dir.Meta.WIF.Issuers, acmez.GitHubActionsIssuer) {
		logger.Warn("directory does not list the GitHub Actions issuer",
			"issuer", acmez.GitHubActionsIssuer, "accepted", dir.Meta.WIF.Issuers)
	}

	// A fresh account on every run: wif-01 needs no EAB or pre-shared
	// secret, and the account holds no authority of its own.
	// draft-rasmussen-acme-wif-00 §5.1, §5.3
	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generating account key: %w", err)
	}
	account := acme.Account{
		TermsOfServiceAgreed: true,
		PrivateKey:           accountKey,
	}
	if email := os.Getenv("ACME_CONTACT_EMAIL"); email != "" {
		account.Contact = []string{"mailto:" + email}
	}
	account, err = client.NewAccount(ctx, account)
	if err != nil {
		return fmt.Errorf("creating account: %w", err)
	}
	logger.Info("created account", "location", account.Location)

	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generating certificate key: %w", err)
	}
	csr, err := newCSR(certKey)
	if err != nil {
		return err
	}
	params, err := acmez.OrderParametersFromCSR(account, csr)
	if err != nil {
		return fmt.Errorf("building order: %w", err)
	}
	now := time.Now()
	params.NotBefore = now
	params.NotAfter = now.Add(lifetime)
	logger.Info("requesting short-lived certificate", "notBefore", params.NotBefore, "notAfter", params.NotAfter)

	certs, err := client.ObtainCertificate(ctx, params)
	if err != nil {
		return err
	}
	if len(certs) == 0 {
		return errors.New("server returned no certificate chains")
	}
	chain := certs[0].ChainPEM

	// Print only the certificate chain; the private key never leaves memory.
	fmt.Print(string(chain))

	clientCert, err := tlsCertificate(chain, certKey)
	if err != nil {
		return err
	}
	leaf := clientCert.Leaf
	issued := leaf.NotAfter.Sub(leaf.NotBefore)
	logger.Info("issued certificate",
		"subject", leaf.Subject.String(), "issuer", leaf.Issuer.String(),
		"notBefore", leaf.NotBefore, "notAfter", leaf.NotAfter, "lifetime", issued)
	fmt.Fprintf(&summary, "| Certificate validity | %s → %s (%s) |\n",
		leaf.NotBefore.UTC().Format(time.RFC3339), leaf.NotAfter.UTC().Format(time.RFC3339), issued)

	// Write what we have so far even if a later check fails.
	defer func() {
		if path := os.Getenv("GITHUB_STEP_SUMMARY"); path != "" {
			if err := appendSummary(path, chain, summary.String()); err != nil {
				logger.Warn("writing job summary", "error", err)
			}
		}
	}()

	// Allow a minute of slack for server-side backdating or clock skew.
	if issued > lifetime+time.Minute {
		return fmt.Errorf("CA issued a certificate valid for %s, longer than the requested %s", issued, lifetime)
	}
	if issued <= 0 || !time.Now().Before(leaf.NotAfter) {
		fmt.Fprintf(&summary, "| Certificate usable | **no**: expired on issuance |\n")
		return fmt.Errorf("CA issued a certificate that is already expired (notBefore %s, notAfter %s, requested %s)",
			leaf.NotBefore.UTC().Format(time.RFC3339), leaf.NotAfter.UTC().Format(time.RFC3339), lifetime)
	}
	if len(leaf.ExtKeyUsage) > 0 && !slices.ContainsFunc(leaf.ExtKeyUsage, func(u x509.ExtKeyUsage) bool {
		return u == x509.ExtKeyUsageClientAuth || u == x509.ExtKeyUsageAny
	}) {
		fmt.Fprintf(&summary, "| Certificate usable | **no**: EKU lacks clientAuth |\n")
		return errors.New("CA issued a certificate whose extended key usage does not include clientAuth; it cannot be used for mTLS")
	}

	if mtlsURL != "" {
		status, body, err := mtlsProbe(ctx, mtlsURL, &clientCert)
		if err != nil {
			fmt.Fprintf(&summary, "| mTLS with issued cert | **failed**: `%v` |\n", err)
			return fmt.Errorf("mTLS request to %s: %w", mtlsURL, err)
		}
		if status < 200 || status >= 300 {
			fmt.Fprintf(&summary, "| mTLS with issued cert | **failed**: HTTP %d |\n", status)
			return fmt.Errorf("mTLS request to %s with the issued certificate returned HTTP %d: %s", mtlsURL, status, body)
		}
		logger.Info("mTLS with issued certificate succeeded", "url", mtlsURL, "status", status, "body", body)
		fmt.Fprintf(&summary, "| mTLS with issued cert | succeeded: HTTP %d |\n", status)
	}
	return nil
}

// tlsCertificate pairs the PEM chain with its in-memory private key.
func tlsCertificate(chainPEM []byte, key *ecdsa.PrivateKey) (tls.Certificate, error) {
	var cert tls.Certificate
	for rest := chainPEM; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, block.Bytes)
		}
	}
	if len(cert.Certificate) == 0 {
		return cert, errors.New("certificate chain contains no certificates")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return cert, fmt.Errorf("parsing leaf certificate: %w", err)
	}
	cert.Leaf = leaf
	cert.PrivateKey = key
	return cert, nil
}

// mtlsProbe GETs url, presenting cert as the TLS client certificate when it
// is non-nil. It returns the HTTP status and the start of the body.
func mtlsProbe(ctx context.Context, url string, cert *tls.Certificate) (int, string, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if cert != nil {
		// Go silently sends no certificate when the chain doesn't match the
		// server's acceptable CAs; fail with the reason instead.
		tlsConfig.GetClientCertificate = func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			if err := cri.SupportsCertificate(cert); err != nil {
				var accepted []string
				for _, raw := range cri.AcceptableCAs {
					var rdn pkix.RDNSequence
					if _, err := asn1.Unmarshal(raw, &rdn); err == nil {
						var name pkix.Name
						name.FillFromRDNSequence(&rdn)
						accepted = append(accepted, name.String())
					}
				}
				return nil, fmt.Errorf("server will not accept the issued certificate (issuer %q; server accepts %q): %w",
					cert.Leaf.Issuer.String(), accepted, err)
			}
			return cert, nil
		}
	}
	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	return resp.StatusCode, strings.TrimSpace(string(body)), nil
}

// newCSR builds a CSR from the CSR_* environment variables. The order's
// identifiers are taken from the CSR's SANs, so the common name is added
// as a SAN if it is not already one.
func newCSR(key *ecdsa.PrivateKey) (*x509.CertificateRequest, error) {
	cn := os.Getenv("CSR_COMMON_NAME")
	dnsNames := splitList(os.Getenv("CSR_DNS_NAMES"))
	var ips []net.IP
	for _, s := range splitList(os.Getenv("CSR_IP_ADDRESSES")) {
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, fmt.Errorf("CSR_IP_ADDRESSES: invalid IP address %q", s)
		}
		ips = append(ips, ip)
	}
	if cn != "" {
		if ip := net.ParseIP(cn); ip != nil {
			if !slices.ContainsFunc(ips, ip.Equal) {
				ips = append(ips, ip)
			}
		} else if !slices.Contains(dnsNames, cn) {
			dnsNames = append(dnsNames, cn)
		}
	}
	if len(dnsNames) == 0 && len(ips) == 0 {
		return nil, errors.New("set CSR_COMMON_NAME, CSR_DNS_NAMES or CSR_IP_ADDRESSES")
	}

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:         cn,
			Organization:       splitList(os.Getenv("CSR_ORGANIZATION")),
			OrganizationalUnit: splitList(os.Getenv("CSR_ORGANIZATIONAL_UNIT")),
			Country:            splitList(os.Getenv("CSR_COUNTRY")),
			Province:           splitList(os.Getenv("CSR_PROVINCE")),
			Locality:           splitList(os.Getenv("CSR_LOCALITY")),
		},
		DNSNames:    dnsNames,
		IPAddresses: ips,
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, fmt.Errorf("creating CSR: %w", err)
	}
	return x509.ParseCertificateRequest(der)
}

func appendSummary(path string, chain []byte, results string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		return err
	}
	if results != "" {
		_, err = fmt.Fprintf(f, "### mTLS test\n\n| Check | Result |\n|---|---|\n%s\n", results)
	}
	if err == nil {
		_, err = fmt.Fprintf(f, "### Issued certificate chain\n\n```\n%s```\n", chain)
	}
	return errors.Join(err, f.Close())
}

// splitList splits a comma-separated value, trimming spaces and dropping
// empty entries.
func splitList(s string) []string {
	var out []string
	for part := range strings.SplitSeq(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}
