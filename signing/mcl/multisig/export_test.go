package multisig

import (
	"github.com/ME-MotherEarth/me-core/hashing"
	crypto "github.com/ME-MotherEarth/me-crypto"
	"github.com/ME-MotherEarth/me-crypto/signing/mcl"
	"github.com/herumi/bls-go-binary/bls"
)

func ScalarMulSig(suite crypto.Suite, scalarBytes []byte, sigPoint *mcl.PointG1) (*mcl.PointG1, error) {
	return scalarMulSig(suite, scalarBytes, sigPoint)
}

func PreparePublicKeys(pubKeys []crypto.PublicKey, hasher hashing.Hasher, suite crypto.Suite) ([]bls.PublicKey, error) {
	return preparePublicKeys(pubKeys, hasher, suite)
}

func (bms *BlsMultiSigner) PrepareSignatures(suite crypto.Suite, signatures [][]byte, pubKeysSigners []crypto.PublicKey) ([]bls.Sign, error) {
	return bms.prepareSignatures(suite, signatures, pubKeysSigners)
}

func ScalarMulPk(suite crypto.Suite, scalarBytes []byte, pk crypto.Point) (crypto.Point, error) {
	return scalarMulPk(suite, scalarBytes, pk)
}

func HashPublicKeyPoints(hasher hashing.Hasher, pubKeyPoint crypto.Point, concatPubKeys []byte) ([]byte, error) {
	return hashPublicKeyPoints(hasher, pubKeyPoint, concatPubKeys)
}

func ConcatPubKeys(pubKeys []crypto.PublicKey) ([]byte, error) {
	return concatPubKeys(pubKeys)
}

func SigBytesToPoint(sig []byte) (crypto.Point, error) {
	return sigBytesToPoint(sig)
}

func SigBytesToSig(sig []byte) (*bls.Sign, error) {
	return sigBytesToSig(sig)
}

func PubKeyCryptoToBLS(pubKey crypto.PublicKey) (*bls.PublicKey, error) {
	return pubKeyCryptoToBLS(pubKey)
}

func PubKeysCryptoToBLS(pubKeys []crypto.PublicKey) ([]bls.PublicKey, error) {
	return pubKeysCryptoToBLS(pubKeys)
}
