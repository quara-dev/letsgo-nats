package stores

type KeyVaultMock struct {
	Token string
}

func (k *KeyVaultMock) GetToken(uri string, secret string) (string, error) {
	return k.Token, nil
}

type FileStoreMock struct {
	Token string
}

func (k *FileStoreMock) GetToken(path string) (string, error) {
	return k.Token, nil
}
