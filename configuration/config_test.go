package configuration

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/quara-dev/letsgo-nats/constants"
	"github.com/quara-dev/letsgo-nats/stores"
	"golang.org/x/exp/slices"
)

// Test that getOrCreateAccountKey function behaves as expected
func TestGetAccountKey(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "account.key")
	rawConfig := NewRawUserConfig()
	rawConfig.AccountKeyFile = file
	key, err := rawConfig.getAccountKey()
	if err != nil {
		t.Errorf(err.Error())
	}
	secondKey, err := rawConfig.getAccountKey()
	if bytes.Equal(certcrypto.PEMBlock(key).Bytes, certcrypto.PEMBlock(secondKey).Bytes) != true {
		t.Errorf("getAccountKey did not load existing key but created a new key instead")
	}
	os.Remove(file)
	thirdKey, err := rawConfig.getAccountKey()
	if bytes.Equal(certcrypto.PEMBlock(key).Bytes, certcrypto.PEMBlock(thirdKey).Bytes) != false {
		t.Errorf("getAccountKey did not create a new key")
	}
}

func TestGetKeyType(t *testing.T) {
	c := RawUserConfig{KeyType: "RSA2048"}
	typ, err := c.getKeyType()
	if err != nil {
		t.Errorf(err.Error())
	}
	if typ != certcrypto.RSA2048 {
		t.Errorf(fmt.Sprintf("Expected RSA2048 but got %s", typ))
	}

	c = RawUserConfig{KeyType: "RSA4096"}
	typ, err = c.getKeyType()
	if err != nil {
		t.Errorf(err.Error())
	}
	if typ != certcrypto.RSA4096 {
		t.Errorf(fmt.Sprintf("Expected RSA4096 but got %s", typ))
	}

	c = RawUserConfig{KeyType: "RSA8192"}
	typ, err = c.getKeyType()
	if err != nil {
		t.Errorf(err.Error())
	}
	if typ != certcrypto.RSA8192 {
		t.Errorf(fmt.Sprintf("Expected RSA8192 but got %s", typ))
	}

	c = RawUserConfig{KeyType: "unknown"}
	typ, err = c.getKeyType()
	got := err.Error()
	want := "Invalid key type. Allowed values are 'RSA2048', 'RSA4096' and 'RSA8192'."
	if got != want {
		t.Errorf(fmt.Sprintf("Bad error message. Want: %s. Got: %s", want, got))
	}
}

// Test that getCADir function behaves as expected
func TestGetCADir(t *testing.T) {
	want := constants.ACME_STAGING_CA_DIR
	c := &RawUserConfig{CADir: "STAGING"}
	got, err := c.getCADir()
	if err != nil {
		t.Errorf(err.Error())
	}
	if want != got {
		t.Errorf("Bad CA dir. Want: %s. Got: %s", want, got)
	}

	want = constants.ACME_PRODUCTION_CA_DIR
	c = &RawUserConfig{CADir: "PRODUCTION"}
	got, err = c.getCADir()
	if err != nil {
		t.Errorf(err.Error())
	}
	if want != got {
		t.Errorf("Bad CA dir. Want: %s. Got: %s", want, got)
	}

	want = constants.ACME_TEST_CA_DIR
	c = &RawUserConfig{CADir: "TEST"}
	got, err = c.getCADir()
	if err != nil {
		t.Errorf(err.Error())
	}
	if want != got {
		t.Errorf("Bad CA dir. Want: %s. Got: %s", want, got)
	}

	want = "http://somewhere:4000/directory"
	c = &RawUserConfig{CADir: want}
	got, err = c.getCADir()
	if err != nil {
		t.Errorf(err.Error())
	}
	if want != got {
		t.Errorf("Bad CA dir. Want: %s. Got: %s", want, got)
	}

	want = "bad/value"
	c = &RawUserConfig{CADir: want}
	got, err = c.getCADir()
	err_want := "Invalid CA directory: bad/value"
	err_got := err.Error()
	if err == nil {
		t.Errorf("Expected error but got value: %s", got)
	}
	if err_want != err_got {
		t.Errorf("Bad error. Want: %s. Got: %s", err_want, err_got)
	}

}

// Test that getAuthToken behaves as expected
func TestGetAuthTokenFail(t *testing.T) {
	c := NewRawUserConfig()
	storage := stores.TestStores("")
	token, err := c.getDNSAuthToken(&storage)
	if token != "" || err == nil {
		t.Errorf(fmt.Sprintf("Expected empty token and error, got token: %s", token))
	}
	err_want := "Invalid DNS auth token. Use one of 'DNS_AUTH_TOKEN_VAULT', 'DNS_AUTH_TOKEN_FILE' or 'DNS_AUTH_TOKEN' env variable"
	err_got := err.Error()
	if err_want != err_got {
		t.Errorf(fmt.Sprintf("Invalid error message. Want: %s. Got %s.", err_want, err_got))
	}
}

func TestGetAuthTokenFromValue(t *testing.T) {
	want := "XXXXX"
	t.Setenv("DNS_AUTH_TOKEN", want)
	c := NewRawUserConfig()
	storage := stores.TestStores("")
	token, err := c.getDNSAuthToken(&storage)
	if err != nil {
		t.Errorf(err.Error())
	}
	if token != want {
		t.Errorf(fmt.Sprintf("Bad token. Want: %s. Got: %s", want, token))
	}
}

func TestGetAuthTokenFromFile(t *testing.T) {
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	want := "XXXXX"
	data := []byte(want)
	os.WriteFile(tokenFile, data, 0o600)
	t.Setenv("DNS_AUTH_TOKEN_FILE", tokenFile)
	c := NewRawUserConfig()
	storage := stores.TestStores(want)
	token, err := c.getDNSAuthToken(&storage)
	if err != nil {
		t.Errorf(err.Error())
	}
	if token != want {
		t.Errorf(fmt.Sprintf("Bad token. Want: %s. Got: %s", want, token))
	}
}

func TestGetAuthTokenFromKeyVault(t *testing.T) {
	want := "XXXXX"
	t.Setenv("DNS_AUTH_TOKEN_VAULT", "test-vault")
	c := NewRawUserConfig()
	storage := stores.TestStores(want)
	token, err := c.getDNSAuthToken(&storage)
	if err != nil {
		t.Errorf(err.Error())
	}
	if token != want {
		t.Errorf(fmt.Sprintf("Bad token. Want: %s. Got: %s", want, token))
	}
}

func TestNewUserConfigFromEnv(t *testing.T) {
	stores := stores.TestStores("")
	_, err := NewUserConfig(&stores)
	err_want := "A comma-separated list of domain names must be provided through DOMAINS environment variable"
	if err == nil {
		t.Fatalf("Expected error. Want: %s. Got: nil", err_want)
	}
	err_got := err.Error()
	if err_got != err_want {
		t.Fatalf("Bad error. Want: %s. Got: %s", err_want, err_got)
	}

	t.Setenv("DOMAINS", "example.com")
	_, err = NewUserConfig(&stores)
	err_want = "An email must be provided through ACCOUNT_EMAIL environment variable"
	if err == nil {
		t.Fatalf("Expected error. Want: %s. Got: nil", err_want)
	}
	err_got = err.Error()
	if err_got != err_want {
		t.Fatalf("Bad error. Want: %s. Got: %s", err_want, err_got)
	}

	t.Setenv("ACCOUNT_EMAIL", "support@example.com")
	_, err = NewUserConfig(&stores)
	err_want = "Invalid DNS auth token. Use one of 'DNS_AUTH_TOKEN_VAULT', 'DNS_AUTH_TOKEN_FILE' or 'DNS_AUTH_TOKEN' env variable"
	if err == nil {
		t.Fatalf("Expected error. Want: %s. Got: nil", err_want)
	}
	err_got = err.Error()
	if err_got != err_want {
		t.Fatalf("Bad error. Want: %s. Got: %s", err_want, err_got)
	}
	want_token := "XXXXX"
	t.Setenv("DNS_AUTH_TOKEN", want_token)
	config, err := NewUserConfig(&stores)

	want_domains := []string{"example.com"}
	if !slices.Equal(config.Domains, want_domains) {
		t.Fatalf("Bad domain. Want: %s. Got: %s", config.Domains, want_domains)
	}
	if config.AuthToken != want_token {
		t.Fatalf(
			"Bad token. Want: %s. Got: %s", want_token, config.AuthToken,
		)
	}

	want_resolvers := []string{"1.1.1.1:53"}
	t.Setenv("DNS_RESOLVERS", want_resolvers[0])
	config, err = NewUserConfig(&stores)
	if !slices.Equal(config.DNSResolvers, want_resolvers) {
		t.Fatalf("Bad resolvers. Want: %s. Got: %s", want_resolvers, config.DNSResolvers)
	}

	want_timeout := 12.0
	t.Setenv("DNS_TIMEOUT", fmt.Sprintf("%f", want_timeout))
	config, err = NewUserConfig(&stores)
	if config.DNSTimeout != time.Second*time.Duration(want_timeout) {
		t.Fatalf("Bad resolvers. Want: %s. Got: %s", time.Second*time.Duration(want_timeout), config.DNSTimeout)
	}

	t.Setenv("DISABLE_CP", "false")
	config, err = NewUserConfig(&stores)
	if config.DisableCP {
		t.Fatalf("Bad DisableCP option. Want: false. Got: true")
	}

	t.Setenv("DISABLE_CP", "true")
	config, err = NewUserConfig(&stores)
	if !config.DisableCP {
		t.Fatalf("Bad DisableCP option. Want: true. Got: false")
	}

	t.Setenv(constants.LE_TOS_AGREED, "false")
	err_want = "It is mandatory to agree to Let's Encrypt Term of Usage through LE_TOS_AGREED environment variable"
	_, err = NewUserConfig(&stores)
	if err == nil {
		t.Fatalf("Expected error. Want: %s. Got: nil", err_want)
	}
	err_got = err.Error()
	if err_got != err_want {
		t.Fatalf("Bad error. Want: %s. Got: %s", err_want, err_got)
	}
}
