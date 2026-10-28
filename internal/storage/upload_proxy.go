package storage

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const MaxUploadBytes int64 = 2 << 30

// UploadProxyConfig adapts the CLI's multipart POST protocol to object storage.
type UploadProxyConfig struct {
	BaseURL string
	Secret  string
}

func validUploadKey(scope, key string) bool {
	if scope != "releases" && scope != "patches" || key == "" || strings.ContainsAny(key, "\\\x00") {
		return false
	}
	for _, part := range strings.Split(key, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}
func signUploadGrant(secret, scope, key string, expires, size int64) string {
	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "upload-v2\n%s\n%s\n%d\n%d", scope, key, expires, size)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
func (cfg UploadProxyConfig) generate(scope, key string, expiry time.Duration, size int64) (string, error) {
	if cfg.BaseURL == "" || cfg.Secret == "" {
		return "", fmt.Errorf("storage multipart upload proxy is not configured")
	}
	if !validUploadKey(scope, key) || expiry <= 0 || size <= 0 || size > MaxUploadBytes {
		return "", fmt.Errorf("invalid upload grant scope, object key, expiry, or size")
	}
	base, err := url.Parse(cfg.BaseURL)
	if err != nil || base.Host == "" || (base.Scheme != "http" && base.Scheme != "https") {
		return "", fmt.Errorf("invalid upload proxy URL")
	}
	base.Path = strings.TrimRight(base.Path, "/") + "/storage/upload/" + scope + "/" + key
	base.RawPath = ""
	base.Fragment = ""
	expires := time.Now().Add(expiry).Unix()
	base.RawQuery = url.Values{"expires": {strconv.FormatInt(expires, 10)}, "size": {strconv.FormatInt(size, 10)}, "token": {signUploadGrant(cfg.Secret, scope, key, expires, size)}}.Encode()
	return base.String(), nil
}
func (cfg UploadProxyConfig) validate(scope, key, token string, expires, size int64) bool {
	if cfg.Secret == "" || !validUploadKey(scope, key) || expires <= time.Now().Unix() || size <= 0 || size > MaxUploadBytes {
		return false
	}
	return hmac.Equal([]byte(token), []byte(signUploadGrant(cfg.Secret, scope, key, expires, size)))
}
