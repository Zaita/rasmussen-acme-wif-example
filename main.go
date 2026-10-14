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
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"log/slog"
	"net"
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

	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

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
	if path := os.Getenv("GITHUB_STEP_SUMMARY"); path != "" {
		if err := appendSummary(path, chain); err != nil {
			logger.Warn("writing job summary", "error", err)
		}
	}
	return nil
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

func appendSummary(path string, chain []byte) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(f, "### Issued certificate chain\n\n```\n%s```\n", chain)
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
