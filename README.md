# rasmussen-acme-wif-example

An example GitHub Actions workflow that obtains a TLS certificate with the ACME
`wif-01` challenge from
[draft-rasmussen-acme-wif](https://datatracker.ietf.org/doc/draft-rasmussen-acme-wif/).
The job proves control of its identifiers by presenting its own GitHub Actions
OIDC token. It needs no DNS or HTTP validation and no External Account Binding
secret.

The client is a small Go program ([main.go](main.go)) built on the
[`wif-01` branch of acmez](https://github.com/Zaita/acmez/tree/wif-01), which
`go.mod` pulls in through a `replace` directive.

## How it works

1. A fresh ACME account key is generated on every run. No secret is
   provisioned (draft §5.1, §5.3).
2. A CSR is built from the `CSR_*` environment variables.
3. For each `wif-01` challenge, acmez requests an OIDC token from the runner
   whose `aud` is the challenge's Audience Binding Value. The ABV is
   `urn:ietf:params:acme:wif:` followed by base64url(SHA-256(keyAuthorization)).
   acmez then posts the token as `{"wifToken": "..."}`.
4. The issued certificate chain is printed to the log and the job summary. The
   private key stays in memory and is discarded when the job ends.

## Configuration

Edit the `TODO` values in [.github/workflows/acme-wif.yml](.github/workflows/acme-wif.yml):

| Variable | Description |
|---|---|
| `ACME_DIRECTORY_URL` | Required. The CA's ACME directory URL |
| `ACME_CONTACT_EMAIL` | Optional account contact |
| `CSR_COMMON_NAME` | Subject CN; also requested as a SAN |
| `CSR_DNS_NAMES`, `CSR_IP_ADDRESSES` | Comma-separated SANs |
| `CSR_ORGANIZATION`, `CSR_ORGANIZATIONAL_UNIT`, `CSR_COUNTRY`, `CSR_PROVINCE`, `CSR_LOCALITY` | Optional Subject fields |

Run it from the **Actions** tab (`workflow_dispatch`). The job needs
`permissions: id-token: write`, which the workflow already sets.

## CA requirements

The ACME server must:

- support `wif-01` and accept the issuer `https://token.actions.githubusercontent.com`;
- have a policy entry that permits this workflow to obtain the requested
  identifiers. Per Appendix A.1 of the draft, match `repository_id` and
  `repository_owner_id` rather than the mutable names, and constrain `ref`
  or `environment`.
