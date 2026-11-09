// Command server-update-tool creates and checks signed shorebird-server
// update artifacts. It never prints or copies a private key.
//
//	server-update-tool keygen -out KEY.pem
//	server-update-tool public-key -key KEY.pem
//	server-update-tool sign -key KEY.pem -binary FILE -version V -goos OS -goarch ARCH -out-dir DIR [-trusted KEYS] [-production]
//	server-update-tool verify-zip -zip FILE -goos OS -goarch ARCH -trusted KEYS [-allow-development]
//
// KEY.pem is an Ed25519 PKCS#8 PEM private key (the format the P4 release
// tooling uses). KEYS is the comma-separated base64 public key list that the
// server binary pins with -ldflags (updater.TrustedKeys).
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/shorebird-server/internal/updater"
	"golang.org/x/mod/semver"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = keygen(os.Args[2:])
	case "public-key":
		err = publicKey(os.Args[2:])
	case "sign":
		err = sign(os.Args[2:])
	case "verify-zip":
		err = verifyZIP(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "server-update-tool:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: server-update-tool keygen|public-key|sign|verify-zip [flags]")
	os.Exit(2)
}

func loadKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("signing key must be a PKCS#8 PEM file")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("signing key: %w", err)
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("signing key is not Ed25519")
	}
	return key, nil
}

func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", "", "new private key file (must not exist)")
	_ = fs.Parse(args)
	if *out == "" {
		return errors.New("-out is required")
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(*out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if err = pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: der}); err == nil {
		err = f.Close()
	}
	if err != nil {
		return err
	}
	fmt.Printf("%s %s\n", base64.StdEncoding.EncodeToString(public), updater.KeyID(public))
	return nil
}

func publicKey(args []string) error {
	fs := flag.NewFlagSet("public-key", flag.ExitOnError)
	keyPath := fs.String("key", "", "private key file")
	_ = fs.Parse(args)
	key, err := loadKey(*keyPath)
	if err != nil {
		return err
	}
	public := key.Public().(ed25519.PublicKey)
	fmt.Printf("%s %s\n", base64.StdEncoding.EncodeToString(public), updater.KeyID(public))
	return nil
}

func sign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	keyPath := fs.String("key", "", "private key file")
	binaryPath := fs.String("binary", "", "server binary")
	version := fs.String("version", "", "vMAJOR.MINOR.PATCH[-pre]")
	goos := fs.String("goos", "", "target GOOS")
	goarch := fs.String("goarch", "", "target GOARCH")
	outDir := fs.String("out-dir", "", "directory receiving <asset>.manifest.json and <asset>.sig")
	trusted := fs.String("trusted", "", "pinned public keys; the signing key must be one of them")
	production := fs.Bool("production", false, "refuse the DEVELOPMENT-ONLY key")
	_ = fs.Parse(args)
	if *outDir == "" || *binaryPath == "" {
		return errors.New("-binary and -out-dir are required")
	}
	if !semver.IsValid(*version) || semver.Build(*version) != "" {
		return errors.New("invalid -version")
	}
	key, err := loadKey(*keyPath)
	if err != nil {
		return err
	}
	public := base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	if *production && public == updater.DevelopmentPublicKey {
		return errors.New("refusing to sign a production build with the DEVELOPMENT-ONLY key")
	}
	if *trusted != "" && !containsKey(*trusted, public) {
		return errors.New("the signing key is not in the pinned -trusted list")
	}
	binary, err := os.ReadFile(*binaryPath)
	if err != nil {
		return err
	}
	channel := "stable"
	if semver.Prerelease(*version) != "" {
		channel = "dev"
	}
	platform := updater.Platform{GOOS: *goos, GOARCH: *goarch}
	manifest, err := updater.BuildManifest(*version, channel, platform, binary)
	if err != nil {
		return err
	}
	asset, _ := updater.AssetName(platform)
	if err := os.WriteFile(filepath.Join(*outDir, asset+".manifest.json"), manifest, 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(*outDir, asset+".sig"), updater.EncodeSignature(key, manifest), 0o644)
}

func containsKey(list, key string) bool {
	for _, entry := range strings.Split(list, ",") {
		if strings.TrimSpace(entry) == key {
			return true
		}
	}
	return false
}

func verifyZIP(args []string) error {
	fs := flag.NewFlagSet("verify-zip", flag.ExitOnError)
	zipPath := fs.String("zip", "", "update ZIP")
	goos := fs.String("goos", "", "target GOOS")
	goarch := fs.String("goarch", "", "target GOARCH")
	trusted := fs.String("trusted", "", "pinned public keys")
	allowDevelopment := fs.Bool("allow-development", false, "accept the DEVELOPMENT-ONLY key")
	_ = fs.Parse(args)
	trust, err := updater.NewTrust(*trusted, *allowDevelopment)
	if err != nil {
		return err
	}
	version, channel, err := updater.VerifyZIPFile(*zipPath, trust, updater.Platform{GOOS: *goos, GOARCH: *goarch})
	if err != nil {
		return err
	}
	fmt.Printf("ok %s %s\n", version, channel)
	return nil
}
