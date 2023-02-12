package configuration

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/quara-dev/letsgo-nats/constants"
	"github.com/quara-dev/letsgo-nats/stores"
)

type RawUserConfig struct {
	AccountEmail       string
	AccountKeyFile     string
	TOSAgreed          string
	CADir              string
	KeyType            string
	Domains            string
	Filename           string
	OutputDirectory    string
	DisableCP          string
	DNSTimeout         string
	DNSResolver        string
	DNSAuthToken       string
	DNSAuthTokenFile   string
	DNSAuthTokenVault  string
	DNSAuthTokenSecret string
	WebRoot            string
	WebEnabled         string
}

type UserConfig struct {
	Email                string
	Key                  crypto.PrivateKey
	CADirURL             string
	CADirKeyType         certcrypto.KeyType
	TermsOfServiceAgreed bool
	Domains              []string
	Filename             string
	OutputDirectory      string
	AuthToken            string
	DisableCP            bool
	DNSResolvers         []string
	DNSTimeout           time.Duration
	WebRoot              string
	WebEnabled           bool
}

// Parse domains from string
func (c *RawUserConfig) getDomains() ([]string, error) {
	domains := strings.Split(c.Domains, ",")
	fallback := []string{}
	if len(domains) == 0 {
		return fallback, errors.New(fmt.Sprintf("A comma-separated list of domain names must be provided through %s environment variable", constants.DOMAINS))
	}
	if len(domains) == 1 && (domains[0] == "") {
		return fallback, errors.New(fmt.Sprintf("A comma-separated list of domain names must be provided through %s environment variable", constants.DOMAINS))
	}
	return domains, nil
}

func (c *RawUserConfig) getAccountEmail() (string, error) {
	if c.AccountEmail == "" {
		return "", errors.New(fmt.Sprintf("An email must be provided through %s environment variable", constants.ACCOUNT_EMAIL))
	}
	return c.AccountEmail, nil
}

func (c *RawUserConfig) getTOSAgreement() (bool, error) {
	tosAgreed, err := strconv.ParseBool(c.TOSAgreed)
	if err != nil {
		return false, err
	}
	if !tosAgreed {
		return false, errors.New(fmt.Sprintf("It is mandatory to agree to Let's Encrypt Term of Usage through %s environment variable", constants.LE_TOS_AGREED))
	}
	return true, nil
}

func (c *RawUserConfig) getWebEnabled() (bool, error) {
	return strconv.ParseBool(c.WebEnabled)
}

func (c *RawUserConfig) getCADir() (string, error) {
	// Return URL associated with environment
	switch strings.ToUpper(c.CADir) {
	case constants.ACME_PRODUCTION_ENV:
		return constants.ACME_PRODUCTION_CA_DIR, nil
	case constants.ACME_STAGING_ENV:
		return constants.ACME_STAGING_CA_DIR, nil
	// This CA URL is configured for a local dev instance of Boulder running in Docker in a VM.
	case constants.ACME_TEST_ENV:
		return constants.ACME_TEST_CA_DIR, nil
	default:
		if !(strings.HasPrefix(c.CADir, "http://") || strings.HasPrefix(c.CADir, "https://")) {
			return "", errors.New(fmt.Sprintf("Invalid CA directory: %s", c.CADir))
		}
		return c.CADir, nil
	}
}

func (c *RawUserConfig) getAccountKey() (crypto.PrivateKey, error) {
	if fileExists(c.AccountKeyFile) {
		pemKey, err := os.ReadFile(c.AccountKeyFile)
		if err != nil {
			return nil, err
		}
		keyBlock, _ := pem.Decode(pemKey)

		switch keyBlock.Type {
		case "RSA PRIVATE KEY":
			return x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		case "EC PRIVATE KEY":
			return x509.ParseECPrivateKey(keyBlock.Bytes)
		}

		return nil, errors.New("unknown private key type")
	}
	// Create a private key. New accounts need an email and private key to start.
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	keyFile, err := os.Create(c.AccountKeyFile)
	if err != nil {
		return nil, err
	}
	defer keyFile.Close()

	pemKey := certcrypto.PEMBlock(privateKey)
	err = pem.Encode(keyFile, pemKey)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

func (c *RawUserConfig) getKeyType() (certcrypto.KeyType, error) {
	switch c.KeyType {
	case constants.KEY_TYPE_RSA2048:
		return certcrypto.RSA2048, nil
	case constants.KEY_TYPE_RSA4096:
		return certcrypto.RSA4096, nil
	case constants.KEY_TYPE_RSA8192:
		return certcrypto.RSA8192, nil
	default:
		return certcrypto.RSA2048, errors.New(fmt.Sprintf("Invalid key type. Allowed values are '%s', '%s' and '%s'.", constants.KEY_TYPE_RSA2048, constants.KEY_TYPE_RSA4096, constants.KEY_TYPE_RSA8192))
	}
}

func (c *RawUserConfig) getFilename(domains []string) (string, error) {
	if c.Filename == "" {
		defaultName, err := sanitizeDomain(domains[0])
		if err != nil {
			return "", err
		}
		return defaultName, nil
	}
	return c.Filename, nil
}

func (c *RawUserConfig) getDNSResolvers() ([]string, error) {
	dnsResolvers := []string{}
	if c.DNSResolver != "" {
		dnsResolvers = strings.Split(c.DNSResolver, ",")
	}
	return dnsResolvers, nil
}

func (c *RawUserConfig) getDNSTimeout() (time.Duration, error) {
	timeout, err := strconv.ParseFloat(c.DNSTimeout, 32)
	fallback := time.Duration(0)
	if err != nil {
		return fallback, err
	}
	return time.Duration(timeout) * time.Second, nil
}

func (c *RawUserConfig) getDisableCPOption() (bool, error) {
	option, err := strconv.ParseBool(c.DisableCP)
	if err != nil {
		return false, err
	}
	return option, nil
}

func (c *RawUserConfig) getDNSAuthToken(storage *stores.Stores) (string, error) {
	// Check that token is not empty
	if c.DNSAuthToken != "" {
		return c.DNSAuthToken, nil
	}
	// Check if token should be fetched from file
	if c.DNSAuthTokenFile != "" {
		filestore := storage.GetFileStore()
		return filestore.GetToken(c.DNSAuthTokenFile)
	}
	// Check if token should be fetched from vault
	if c.DNSAuthTokenVault != "" {
		uri, err := c.getDNSAuthTokenVaultURI()
		if err != nil {
			return "", err
		}
		secret, err := c.getDNSAuthTokenSecretName()
		if err != nil {
			return "", err
		}
		keyvault := storage.GetKeyvaultStore()
		return keyvault.GetToken(uri, secret)
	}
	// Return an error
	return "", errors.New(fmt.Sprintf("Invalid DNS auth token. Use one of '%s', '%s' or '%s' env variable", constants.DNS_AUTH_TOKEN_VAULT, constants.DNS_AUTH_TOKEN_FILE, constants.DNS_AUTH_TOKEN))
}

func (c *RawUserConfig) getDNSAuthTokenVaultURI() (string, error) {
	if c.DNSAuthTokenVault == "" {
		return "", errors.New(fmt.Sprintf("Invalid Keyvault URI: %s", c.DNSAuthTokenVault))
	}
	if strings.HasPrefix(c.DNSAuthTokenVault, "https://") {
		return c.DNSAuthTokenVault, nil
	} else {
		return fmt.Sprintf("https://%s.vault.azure.net/", c.DNSAuthTokenVault), nil
	}
}

func (c *RawUserConfig) getDNSAuthTokenSecretName() (string, error) {
	if c.DNSAuthTokenSecret == "" {
		return "", errors.New(fmt.Sprintf("Invalid DNS auth token: %s", c.DNSAuthTokenSecret))
	}
	return c.DNSAuthTokenSecret, nil
}

func (c *RawUserConfig) getOutputDirectory() (string, error) {
	dir, err := filepath.Abs(c.OutputDirectory)
	if err != nil {
		return "", err
	}
	err = os.MkdirAll(dir, os.ModePerm)
	if err != nil {
		return "", err
	}
	return dir, nil
}

func (c *RawUserConfig) parse(storage *stores.Stores) (*UserConfig, error) {
	config := &UserConfig{}

	// Parse domains
	domains, err := c.getDomains()
	if err != nil {
		return config, err
	} else {
		config.Domains = domains
	}

	// Parse filename
	name, err := c.getFilename(domains)
	if err != nil {
		return config, err
	} else {
		config.Filename = name
	}

	// Parse email
	email, err := c.getAccountEmail()
	if err != nil {
		return config, err
	} else {
		config.Email = email
	}

	// Parse TOS agreement
	tosAgreed, err := c.getTOSAgreement()
	if err != nil {
		return config, err
	} else {
		config.TermsOfServiceAgreed = tosAgreed
	}

	// Parse account key (and generate it if missing)
	accountKey, err := c.getAccountKey()
	if err != nil {
		return config, err
	} else {
		config.Key = accountKey
	}

	// Parsa CA directory
	caDir, err := c.getCADir()
	if err != nil {
		return config, err
	} else {
		config.CADirURL = caDir
	}

	// Parse key type
	keyType, err := c.getKeyType()
	if err != nil {
		return config, err
	} else {
		config.CADirKeyType = keyType
	}

	// Parse DNS resolvers
	resolvers, err := c.getDNSResolvers()
	if err != nil {
		return config, err
	} else {
		config.DNSResolvers = resolvers
	}

	// Parse DNS timeout
	timeout, err := c.getDNSTimeout()
	if err != nil {
		return config, err
	} else {
		config.DNSTimeout = timeout
	}

	// Parse disableCP option
	disableCP, err := c.getDisableCPOption()
	if err != nil {
		return config, err
	} else {
		config.DisableCP = disableCP
	}

	// Parse output directory
	outputDirectory, err := c.getOutputDirectory()
	if err != nil {
		return config, err
	} else {
		config.OutputDirectory = outputDirectory
	}

	// Parse dns auth token
	token, err := c.getDNSAuthToken(storage)
	if err != nil {
		return config, err
	} else {
		config.AuthToken = token
	}

	config.WebRoot = c.WebRoot
	webEnabled, err := c.getWebEnabled()
	if err != nil {
		return config, err
	} else {
		config.WebEnabled = webEnabled
	}

	return config, nil
}

func NewRawUserConfig() *RawUserConfig {
	return &RawUserConfig{
		AccountEmail:       getEnv(constants.ACCOUNT_EMAIL, ""),
		AccountKeyFile:     getEnv(constants.ACCOUNT_KEY_FILE, constants.DEFAULT_ACCOUNT_KEY_FILE),
		TOSAgreed:          getEnv(constants.LE_TOS_AGREED, constants.DEFAULT_LE_TOS_AGREED),
		CADir:              getEnv(constants.CA_DIR, constants.DEFAULT_CA_DIR),
		KeyType:            getEnv(constants.LE_CRT_KEY_TYPE, constants.DEFAULT_LE_CRT_KEY_TYPE),
		Domains:            getEnv(constants.DOMAINS, ""),
		Filename:           getEnv(constants.FILENAME, ""),
		DisableCP:          getEnv(constants.DISABLE_CP, constants.DEFAULT_DISABLE_CP),
		DNSTimeout:         getEnv(constants.DNS_TIMEOUT, "0"),
		DNSResolver:        getEnv(constants.DNS_RESOLVERS, ""),
		DNSAuthToken:       getEnv(constants.DNS_AUTH_TOKEN, ""),
		DNSAuthTokenFile:   getEnv(constants.DNS_AUTH_TOKEN_FILE, ""),
		DNSAuthTokenVault:  getEnv(constants.DNS_AUTH_TOKEN_VAULT, ""),
		DNSAuthTokenSecret: getEnv(constants.DNS_AUTH_TOKEN_SECRET, constants.DEFAULT_DNS_AUTH_TOKEN_SECRET),
		OutputDirectory:    getEnv(constants.OUTPUT_DIRECTORY, "./"),
		WebRoot:            getEnv(constants.WEB_ROOT, constants.DEFAULT_WEB_ROOT),
		WebEnabled:         getEnv(constants.WEB_ENABLED, constants.DEFAULT_WEB_ENABLED),
	}
}

func NewUserConfig(storage *stores.Stores) (*UserConfig, error) {
	config := NewRawUserConfig()
	return config.parse(storage)
}
