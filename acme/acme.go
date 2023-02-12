package acme

import (
	"crypto"
	"crypto/x509"
	"errors"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/digitalocean"
	"github.com/go-acme/lego/v4/registration"

	"github.com/quara-dev/letsgo-nats/configuration"
)

// User type that implements acme.User
//
// Implements the following methods:
//   - User.GetEmail()
//   - User.GetRegistration()
//   - User.GetPrivateKey()
type User struct {
	Email        string
	Registration *registration.Resource
	Key          crypto.PrivateKey
}

func (u *User) GetEmail() string {
	return u.Email
}
func (u User) GetRegistration() *registration.Resource {
	return u.Registration
}
func (u *User) GetPrivateKey() crypto.PrivateKey {
	return u.Key
}

// Create a new client to request certificate
func NewClient(userConfig configuration.UserConfig) (lego.Client, error) {
	// Generate user
	user := &User{
		Email: userConfig.Email,
		Key:   userConfig.Key,
	}
	// Generate config for user
	legoConfig := lego.NewConfig(user)
	// The default URL is ACME v2 staging environment
	legoConfig.CADirURL = userConfig.CADirURL
	legoConfig.Certificate.KeyType = userConfig.CADirKeyType
	// A client facilitates communication with the CA server.
	client, err := lego.NewClient(legoConfig)
	if err != nil {
		return lego.Client{}, err
	}
	// Generate DigitalOcean provider configuration
	providerConfig := digitalocean.NewDefaultConfig()
	// Set auth token from user config
	providerConfig.AuthToken = userConfig.AuthToken
	// Use a propagation timeout of 1 minute and 30 seconds
	providerConfig.PropagationTimeout = time.Duration(time.Second * 90)
	// Create DigitalOcean DNS Provider
	dnsProvider, err := digitalocean.NewDNSProviderConfig(providerConfig)
	if err != nil {
		return lego.Client{}, err
	}
	// Use DNS provider with some conditional options
	err = client.Challenge.SetDNS01Provider(dnsProvider,
		dns01.CondOption(
			len(userConfig.DNSResolvers) > 0,
			dns01.AddRecursiveNameservers(dns01.ParseNameservers(userConfig.DNSResolvers)),
		),
		dns01.CondOption(userConfig.DisableCP,
			dns01.DisableCompletePropagationRequirement(),
		),
		dns01.CondOption(userConfig.DNSTimeout > 0,
			dns01.AddDNSTimeout(userConfig.DNSTimeout),
		),
	)
	if err != nil {
		return lego.Client{}, err
	}
	// Perform use registration
	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		log.Fatal(err)
	}
	user.Registration = reg
	// Return client
	return *client, err
}

// Request certificate according to user configuration
func RequestCertificate(config configuration.UserConfig) (*certificate.Resource, error) {
	// Generate lego client
	client, err := NewClient(config)
	if err != nil {
		return &certificate.Resource{}, err
	}
	// Gather request
	request := certificate.ObtainRequest{
		Domains: config.Domains,
		Bundle:  true,
	}
	// Send request
	return client.Certificate.Obtain(request)
}

func saveResource(resource *certificate.Resource, config *configuration.UserConfig) error {
	// Write certificate to file
	certPath := filepath.Join(config.OutputDirectory, config.Filename+".crt")
	keyPath := filepath.Join(config.OutputDirectory, config.Filename+".key")
	issuerPath := filepath.Join(config.OutputDirectory, config.Filename+".issuer.crt")

	err := os.WriteFile(certPath, resource.Certificate, 0o600)
	if err != nil {
		return err
	}
	err = os.WriteFile(keyPath, resource.PrivateKey, 0o600)
	if err != nil {
		return err
	}
	err = os.WriteFile(issuerPath, resource.IssuerCertificate, 0o600)
	if err != nil {
		return err
	}
	return nil
}

func readCert(filepath string) ([]*x509.Certificate, error) {
	// Read certificate
	content, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}
	// The input may be a bundle or a single certificate.
	return certcrypto.ParsePEMBundle(content)
}

func needRenewal(x509Cert *x509.Certificate, days int) (bool, error) {
	if x509Cert.IsCA {
		return false, errors.New("Certificate bundle starts with a CA certificate")
	}
	if days >= 0 {
		notAfter := int(time.Until(x509Cert.NotAfter).Hours() / 24.0)
		if notAfter > days {
			return false, nil
		}
	}

	return true, nil
}

func GetOrRenewCertificate(config *configuration.UserConfig, days int) (bool, error) {
	filepath := filepath.Join(config.OutputDirectory, config.Filename+".crt")
	cert, err := readCert(filepath)
	if err != nil {
		resource, requestErr := RequestCertificate(*config)
		if requestErr != nil {
			return false, requestErr
		}
		err = saveResource(resource, config)
		if err != nil {
			return false, err
		}
		return true, err
	}
	x509Cert := cert[0]
	if x509Cert.IsCA {
		return false, errors.New("Certificate bundle starts with a CA certificate")
	}
	if days >= 0 {
		notAfter := int(time.Until(x509Cert.NotAfter).Hours() / 24.0)
		if notAfter > days {
			return false, nil
		}
		resource, err := RequestCertificate(*config)
		if err != nil {
			return false, err
		}
		err = saveResource(resource, config)
		if err != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil
}
