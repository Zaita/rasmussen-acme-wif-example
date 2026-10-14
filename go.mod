module github.com/Zaita/rasmussen-acme-wif-example

go 1.26.0

replace github.com/mholt/acmez/v3 => github.com/Zaita/acmez/v3 v3.0.0-20261014093507-3c5180dc6c4c

require github.com/mholt/acmez/v3 v3.0.0-00010101000000-000000000000

require (
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/net v0.59.0 // indirect
	golang.org/x/text v0.42.0 // indirect
)
