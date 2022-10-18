package multisig

import (
	crypto "github.com/ME-MotherEarth/me-crypto"
)

func convertStringsToPubKeys(pubKeys []string, kg crypto.KeyGenerator) ([]crypto.PublicKey, error) {
	// convert pubKeys
	pk := make([]crypto.PublicKey, 0, len(pubKeys))
	for _, pubKeyStr := range pubKeys {
		if pubKeyStr == "" {
			return nil, crypto.ErrEmptyPubKeyString
		}

		pubKey, err := kg.PublicKeyFromByteArray([]byte(pubKeyStr))
		if err != nil {
			return nil, crypto.ErrInvalidPublicKeyString
		}

		pk = append(pk, pubKey)
	}
	return pk, nil
}
