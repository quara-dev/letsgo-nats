package stores

import (
	"context"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azsecrets"
)

// Azure Keyvault store implementation to fetch token from azure keyvault
type KeyVault struct{}

func (k *KeyVault) GetToken(uri string, secret string) (string, error) {
	// Generate azure credentials
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return "", err
	}
	// Create client to interact with key vault
	client, err := azsecrets.NewClient(uri, cred, nil)
	if err != nil {
		return "", err
	}
	// Fetch the token
	resp, err := client.GetSecret(context.TODO(), secret, "", nil)
	if err != nil {
		return "", err
	}
	// Return the token (secret value)
	return strings.TrimSuffix(*resp.Value, "\n"), nil
}
