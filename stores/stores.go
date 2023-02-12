package stores

type FileStoreProtocol interface {
	GetToken(path string) (string, error)
}

type KeyvaultStoreProtocol interface {
	GetToken(uri string, secret string) (string, error)
}

// Stores used to find DNS auth token
type Stores struct {
	Files    FileStoreProtocol
	Keyvault KeyvaultStoreProtocol
}

// Access the file store
func (s *Stores) GetFileStore() FileStoreProtocol {
	return s.Files
}

// Access the keyvault store
func (s *Stores) GetKeyvaultStore() KeyvaultStoreProtocol {
	return s.Keyvault
}

// Default stores
func DefaultStores() Stores {
	return Stores{
		Keyvault: &KeyVault{},
		Files:    &FileStore{},
	}
}

// Stores used in tests
func TestStores(token string) Stores {
	return Stores{
		Keyvault: &KeyVaultMock{
			Token: token,
		},
		Files: &FileStoreMock{
			Token: token,
		},
	}
}
