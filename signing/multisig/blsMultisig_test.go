package multisig_test

import (
	"testing"

	"github.com/ME-MotherEarth/me-core/core/check"
	"github.com/ME-MotherEarth/me-crypto"
	"github.com/ME-MotherEarth/me-crypto/mock"
	"github.com/ME-MotherEarth/me-crypto/signing"
	"github.com/ME-MotherEarth/me-crypto/signing/mcl"
	llsig "github.com/ME-MotherEarth/me-crypto/signing/mcl/multisig"
	"github.com/ME-MotherEarth/me-crypto/signing/multisig"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func generateMultiSigParamsBLSWithPrivateKeys(consensusGroupSize int, ownIndex uint16) (
	privKey crypto.PrivateKey,
	pubKey crypto.PublicKey,
	privKeys []crypto.PrivateKey,
	pubKeys []string,
	kg crypto.KeyGenerator,
) {
	suite := mcl.NewSuiteBLS12()
	kg = signing.NewKeyGenerator(suite)
	var pubKeyBytes []byte
	pubKeys = make([]string, 0)

	privKeys = make([]crypto.PrivateKey, 0, consensusGroupSize)
	for i := 0; i < consensusGroupSize; i++ {
		sk, pk := kg.GeneratePair()
		if uint16(i) == ownIndex {
			privKey = sk
			pubKey = pk
		}

		pubKeyBytes, _ = pk.ToByteArray()
		pubKeys = append(pubKeys, string(pubKeyBytes))
		privKeys = append(privKeys, sk)
	}

	return privKey, pubKey, privKeys, pubKeys, kg
}

func generateMultiSigParamsBLS(consensusGroupSize int, ownIndex uint16) (
	privKey crypto.PrivateKey,
	pubKey crypto.PublicKey,
	pubKeys []string,
	kg crypto.KeyGenerator,
) {
	privKey, pubKey, _, pubKeys, kg = generateMultiSigParamsBLSWithPrivateKeys(consensusGroupSize, ownIndex)
	return
}

func createSignerAndSigShareBLS(
	pubKeys []string,
	privKey crypto.PrivateKey,
	kg crypto.KeyGenerator,
	ownIndex uint16,
	message []byte,
	llSigner crypto.LowLevelSignerBLS,
) (sigShare []byte, multiSig crypto.MultiSigner) {
	multiSig, _ = multisig.NewBLSMultisig(llSigner, pubKeys, privKey, kg, ownIndex)
	sigShare, _ = multiSig.CreateSignatureShare(message, []byte(""))

	return sigShare, multiSig
}

func createSigSharesBLS(
	nbSigs uint16,
	grSize uint16,
	message []byte,
	ownIndex uint16,
	llSigner crypto.LowLevelSignerBLS,
) (sigShares [][]byte, multiSigner crypto.MultiSigner) {
	suite := mcl.NewSuiteBLS12()
	kg := signing.NewKeyGenerator(suite)

	var pubKeyBytes []byte

	privKeys := make([]crypto.PrivateKey, grSize)
	pubKeys := make([]crypto.PublicKey, grSize)
	pubKeysStr := make([]string, grSize)

	for i := uint16(0); i < grSize; i++ {
		sk, pk := kg.GeneratePair()
		privKeys[i] = sk
		pubKeys[i] = pk

		pubKeyBytes, _ = pk.ToByteArray()
		pubKeysStr[i] = string(pubKeyBytes)
	}

	sigShares = make([][]byte, nbSigs)
	multiSigners := make([]crypto.MultiSigner, nbSigs)

	for i := uint16(0); i < nbSigs; i++ {
		multiSigners[i], _ = multisig.NewBLSMultisig(llSigner, pubKeysStr, privKeys[i], kg, i)
	}

	for i := uint16(0); i < nbSigs; i++ {
		sigShares[i], _ = multiSigners[i].CreateSignatureShare(message, []byte(""))
	}

	return sigShares, multiSigners[ownIndex]
}

func createAndAddSignatureSharesBLS(msg []byte, llSigner crypto.LowLevelSignerBLS) (multiSigner crypto.MultiSigner, bitmap []byte) {
	grSize := uint16(15)
	ownIndex := uint16(0)
	nbSigners := uint16(3)
	bitmap = make([]byte, 2)
	bitmap[0] = 0x07

	sigs, multiSigner := createSigSharesBLS(nbSigners, grSize, msg, ownIndex, llSigner)

	for i := 0; i < len(sigs); i++ {
		_ = multiSigner.StoreSignatureShare(uint16(i), sigs[i])
	}

	return multiSigner, bitmap
}

func createAggregatedSigBLS(msg []byte, llSigner crypto.LowLevelSignerBLS, t *testing.T) (multiSigner crypto.MultiSigner, aggSig []byte, bitmap []byte) {
	multiSigner, bitmap = createAndAddSignatureSharesBLS(msg, llSigner)
	aggSig, err := multiSigner.AggregateSigs(bitmap)

	assert.Nil(t, err)

	return multiSigner, aggSig, bitmap
}

func TestNewBLSMultisig_NilLowLevelSignerShouldErr(t *testing.T) {
	t.Parallel()

	ownIndex := uint16(3)
	privKey, _, pubKeys, kg := generateMultiSigParamsBLS(4, ownIndex)

	multiSig, err := multisig.NewBLSMultisig(nil, pubKeys, privKey, kg, ownIndex)

	assert.Nil(t, multiSig)
	assert.Equal(t, crypto.ErrNilLowLevelSigner, err)
}

func TestNewBLSMultisig_NilPrivKeyShouldErr(t *testing.T) {
	t.Parallel()

	ownIndex := uint16(3)
	hasher := &mock.HasherSpongeMock{}
	llSigner := &llsig.BlsMultiSigner{Hasher: hasher}
	_, _, pubKeys, kg := generateMultiSigParamsBLS(4, ownIndex)

	multiSig, err := multisig.NewBLSMultisig(llSigner, pubKeys, nil, kg, ownIndex)

	assert.Nil(t, multiSig)
	assert.Equal(t, crypto.ErrNilPrivateKey, err)
}

func TestNewBLSMultisig_NilPubKeysShouldErr(t *testing.T) {
	t.Parallel()

	ownIndex := uint16(3)
	hasher := &mock.HasherSpongeMock{}
	llSigner := &llsig.BlsMultiSigner{Hasher: hasher}
	privKey, _, _, kg := generateMultiSigParamsBLS(4, ownIndex)

	multiSig, err := multisig.NewBLSMultisig(llSigner, nil, privKey, kg, ownIndex)

	assert.Nil(t, multiSig)
	assert.Equal(t, crypto.ErrNoPublicKeySet, err)
}

func TestNewBLSMultisig_NoPubKeysSetShouldErr(t *testing.T) {
	t.Parallel()

	ownIndex := uint16(3)
	hasher := &mock.HasherSpongeMock{}
	llSigner := &llsig.BlsMultiSigner{Hasher: hasher}
	privKey, _, _, kg := generateMultiSigParamsBLS(4, ownIndex)
	pubKeys := make([]string, 0)

	multiSig, err := multisig.NewBLSMultisig(llSigner, pubKeys, privKey, kg, ownIndex)

	assert.Nil(t, multiSig)
	assert.Equal(t, crypto.ErrNoPublicKeySet, err)
}

func TestNewBLSMultisig_NilKeyGenShouldErr(t *testing.T) {
	t.Parallel()

	ownIndex := uint16(3)
	hasher := &mock.HasherSpongeMock{}
	llSigner := &llsig.BlsMultiSigner{Hasher: hasher}
	privKey, _, pubKeys, _ := generateMultiSigParamsBLS(4, ownIndex)

	multiSig, err := multisig.NewBLSMultisig(llSigner, pubKeys, privKey, nil, ownIndex)

	assert.Nil(t, multiSig)
	assert.Equal(t, crypto.ErrNilKeyGenerator, err)
}

func TestNewBLSMultisig_InvalidOwnIndexShouldErr(t *testing.T) {
	t.Parallel()

	ownIndex := uint16(3)
	hasher := &mock.HasherSpongeMock{}
	llSigner := &llsig.BlsMultiSigner{Hasher: hasher}
	privKey, _, pubKeys, kg := generateMultiSigParamsBLS(4, ownIndex)

	multiSig, err := multisig.NewBLSMultisig(llSigner, pubKeys, privKey, kg, 15)

	assert.Nil(t, multiSig)
	assert.Equal(t, crypto.ErrIndexOutOfBounds, err)
}

func TestNewBLSMultisig_OutOfBoundsIndexShouldErr(t *testing.T) {
	t.Parallel()

	ownIndex := uint16(3)
	hasher := &mock.HasherSpongeMock{}
	llSigner := &llsig.BlsMultiSigner{Hasher: hasher}
	privKey, _, pubKeys, kg := generateMultiSigParamsBLS(4, ownIndex)

	multiSig, err := multisig.NewBLSMultisig(llSigner, pubKeys, privKey, kg, 10)

	assert.Nil(t, multiSig)
	assert.Equal(t, crypto.ErrIndexOutOfBounds, err)
}

func TestNewBLSMultisig_InvalidPubKeyInListShouldErr(t *testing.T) {
	t.Parallel()

	ownIndex := uint16(3)
	hasher := &mock.HasherSpongeMock{}
	llSigner := &llsig.BlsMultiSigner{Hasher: hasher}
	privKey, _, pubKeys, kg := generateMultiSigParamsBLS(4, ownIndex)
	pubKeys[1] = "invalid"

	multiSig, err := multisig.NewBLSMultisig(llSigner, pubKeys, privKey, kg, ownIndex)

	assert.Nil(t, multiSig)
	assert.Equal(t, crypto.ErrInvalidPublicKeyString, err)
}

func TestNewBLSMultisig_EmptyPubKeyInListShouldErr(t *testing.T) {
	t.Parallel()

	ownIndex := uint16(3)
	hasher := &mock.HasherSpongeMock{}
	llSigner := &llsig.BlsMultiSigner{Hasher: hasher}
	privKey, _, pubKeys, kg := generateMultiSigParamsBLS(4, ownIndex)
	pubKeys[1] = ""

	multiSig, err := multisig.NewBLSMultisig(llSigner, pubKeys, privKey, kg, ownIndex)

	assert.Nil(t, multiSig)
	assert.Equal(t, crypto.ErrEmptyPubKeyString, err)
}

func TestNewBLSMultisig_OK(t *testing.T) {
	t.Parallel()

	ownIndex := uint16(3)
	hasher := &mock.HasherSpongeMock{}
	llSigner := &llsig.BlsMultiSigner{Hasher: hasher}
	llSignerKOSK := &llsig.BlsMultiSignerKOSK{}
	privKey, _, pubKeys, kg := generateMultiSigParamsBLS(4, ownIndex)

	t.Run("with rogue key prevention", func(t *testing.T) {
		multiSig, err := multisig.NewBLSMultisig(llSigner, pubKeys, privKey, kg, ownIndex)

		assert.Nil(t, err)
		assert.False(t, check.IfNil(multiSig))
	})
	t.Run("with KOSK", func(t *testing.T) {
		multiSig, err := multisig.NewBLSMultisig(llSignerKOSK, pubKeys, privKey, kg, ownIndex)

		assert.Nil(t, err)
		assert.False(t, check.IfNil(multiSig))
	})
}

func TestBLSMultiSigner_CreateNilPubKeysShouldErr(t *testing.T) {
	t.Parallel()

	ownIndex := uint16(3)
	hasher := &mock.HasherSpongeMock{}
	llSigner := &llsig.BlsMultiSigner{Hasher: hasher}
	privKey, _, pubKeys, kg := generateMultiSigParamsBLS(4, ownIndex)

	multiSig, _ := multisig.NewBLSMultisig(llSigner, pubKeys, privKey, kg, ownIndex)
	multiSigCreated, err := multiSig.Create(nil, ownIndex)

	assert.Equal(t, crypto.ErrNoPublicKeySet, err)
	assert.Nil(t, multiSigCreated)
}

func TestBLSMultiSigner_CreateInvalidPubKeyInListShouldErr(t *testing.T) {
	t.Parallel()

	ownIndex := uint16(3)
	hasher := &mock.HasherSpongeMock{}
	llSigner := &llsig.BlsMultiSigner{Hasher: hasher}
	privKey, _, pubKeys, kg := generateMultiSigParamsBLS(4, ownIndex)

	multiSig, _ := multisig.NewBLSMultisig(llSigner, pubKeys, privKey, kg, ownIndex)

	pubKeys[1] = "invalid"
	multiSigCreated, err := multiSig.Create(pubKeys, ownIndex)

	assert.Equal(t, crypto.ErrInvalidPublicKeyString, err)
	assert.Nil(t, multiSigCreated)
}

func TestBLSMultiSigner_CreateEmptyPubKeyInListShouldErr(t *testing.T) {
	t.Parallel()

	ownIndex := uint16(3)
	hasher := &mock.HasherSpongeMock{}
	llSigner := &llsig.BlsMultiSigner{Hasher: hasher}
	privKey, _, pubKeys, kg := generateMultiSigParamsBLS(4, ownIndex)

	multiSig, _ := multisig.NewBLSMultisig(llSigner, pubKeys, privKey, kg, ownIndex)

	pubKeys[1] = ""
	multiSigCreated, err := multiSig.Create(pubKeys, ownIndex)

	assert.Equal(t, crypto.ErrEmptyPubKeyString, err)
	assert.Nil(t, multiSigCreated)
}

func TestBLSMultiSigner_CreateOK(t *testing.T) {
	t.Parallel()

	ownIndex := uint16(3)
	hasher := &mock.HasherSpongeMock{}
	llSigner := &llsig.BlsMultiSigner{Hasher: hasher}
	llSignerKOSK := &llsig.BlsMultiSignerKOSK{}
	privKey, _, pubKeys, kg := generateMultiSigParamsBLS(4, ownIndex)

	t.Run("with rogue key prevention", func(t *testing.T) {
		multiSig, _ := multisig.NewBLSMultisig(llSigner, pubKeys, privKey, kg, ownIndex)
		multiSigCreated, err := multiSig.Create(pubKeys, ownIndex)
		assert.Nil(t, err)
		assert.NotNil(t, multiSigCreated)
	})
	t.Run("with KOSK", func(t *testing.T) {
		multiSig, _ := multisig.NewBLSMultisig(llSignerKOSK, pubKeys, privKey, kg, ownIndex)
		multiSigCreated, err := multiSig.Create(pubKeys, ownIndex)
		assert.Nil(t, err)
		assert.NotNil(t, multiSigCreated)
	})
}

func TestBLSMultiSigner_ResetOutOfBoundsIndexShouldErr(t *testing.T) {
	t.Parallel()

	ownIndex := uint16(3)
	hasher := &mock.HasherSpongeMock{}
	llSigner := &llsig.BlsMultiSigner{Hasher: hasher}
	llSignerKOSK := &llsig.BlsMultiSignerKOSK{}
	privKey, _, pubKeys, kg := generateMultiSigParamsBLS(4, ownIndex)

	t.Run("with rogue key prevention", func(t *testing.T) {
		multiSig, _ := multisig.NewBLSMultisig(llSigner, pubKeys, privKey, kg, ownIndex)

		err := multiSig.Reset(pubKeys, 10)
		assert.Equal(t, crypto.ErrIndexOutOfBounds, err)
	})
	t.Run("with KOSK", func(t *testing.T) {
		multiSig, _ := multisig.NewBLSMultisig(llSignerKOSK, pubKeys, privKey, kg, ownIndex)

		err := multiSig.Reset(pubKeys, 10)
		assert.Equal(t, crypto.ErrIndexOutOfBounds, err)
	})
}

func TestBLSMultiSigner_ResetNilPubKeysShouldErr(t *testing.T) {
	t.Parallel()

	ownIndex := uint16(3)
	hasher := &mock.HasherSpongeMock{}
	llSigner := &llsig.BlsMultiSigner{Hasher: hasher}
	llSignerKOSK := &llsig.BlsMultiSignerKOSK{}
	privKey, _, pubKeys, kg := generateMultiSigParamsBLS(4, ownIndex)

	t.Run("with rogue key prevention", func(t *testing.T) {
		multiSig, _ := multisig.NewBLSMultisig(llSigner, pubKeys, privKey, kg, ownIndex)
		err := multiSig.Reset(nil, ownIndex)

		assert.Equal(t, crypto.ErrNilPublicKeys, err)
	})
	t.Run("with KOSK", func(t *testing.T) {
		multiSig, _ := multisig.NewBLSMultisig(llSignerKOSK, pubKeys, privKey, kg, ownIndex)
		err := multiSig.Reset(nil, ownIndex)

		assert.Equal(t, crypto.ErrNilPublicKeys, err)
	})
}

func TestBLSMultiSigner_ResetInvalidPubKeyInListShouldErr(t *testing.T) {
	t.Parallel()

	ownIndex := uint16(3)
	hasher := &mock.HasherSpongeMock{}
	llSigner := &llsig.BlsMultiSigner{Hasher: hasher}
	llSignerKOSK := &llsig.BlsMultiSignerKOSK{}
	privKey, _, pubKeys, kg := generateMultiSigParamsBLS(4, ownIndex)

	t.Run("with rogue key prevention", func(t *testing.T) {
		multiSig, _ := multisig.NewBLSMultisig(llSigner, pubKeys, privKey, kg, ownIndex)
		pubKeysCopy := append([]string{}, pubKeys...)
		pubKeysCopy[1] = "invalid"

		err := multiSig.Reset(pubKeysCopy, ownIndex)

		assert.Equal(t, crypto.ErrInvalidPublicKeyString, err)
	})
	t.Run("with KOSK", func(t *testing.T) {
		multiSig, _ := multisig.NewBLSMultisig(llSignerKOSK, pubKeys, privKey, kg, ownIndex)
		pubKeysCopy := append([]string{}, pubKeys...)
		pubKeysCopy[1] = "invalid"

		err := multiSig.Reset(pubKeysCopy, ownIndex)

		assert.Equal(t, crypto.ErrInvalidPublicKeyString, err)
	})
}

func TestBLSMultiSigner_ResetEmptyPubKeyInListShouldErr(t *testing.T) {
	t.Parallel()

	ownIndex := uint16(3)
	hasher := &mock.HasherSpongeMock{}
	llSigner := &llsig.BlsMultiSigner{Hasher: hasher}
	llSignerKOSK := &llsig.BlsMultiSignerKOSK{}
	privKey, _, pubKeys, kg := generateMultiSigParamsBLS(4, ownIndex)

	t.Run("with rogue key prevention", func(t *testing.T) {
		multiSig, _ := multisig.NewBLSMultisig(llSigner, pubKeys, privKey, kg, ownIndex)
		pubKeysCopy := append([]string{}, pubKeys...)
		pubKeysCopy[1] = ""
		err := multiSig.Reset(pubKeysCopy, ownIndex)

		assert.Equal(t, crypto.ErrEmptyPubKeyString, err)
	})
	t.Run("with KOSK", func(t *testing.T) {
		multiSig, _ := multisig.NewBLSMultisig(llSignerKOSK, pubKeys, privKey, kg, ownIndex)
		pubKeysCopy := append([]string{}, pubKeys...)
		pubKeysCopy[1] = ""
		err := multiSig.Reset(pubKeysCopy, ownIndex)

		assert.Equal(t, crypto.ErrEmptyPubKeyString, err)
	})
}

func TestBLSMultiSigner_ResetOK(t *testing.T) {
	t.Parallel()

	ownIndex := uint16(3)
	hasher := &mock.HasherSpongeMock{}
	llSigner := &llsig.BlsMultiSigner{Hasher: hasher}
	llSignerKOSK := &llsig.BlsMultiSignerKOSK{}
	privKey, _, pubKeys, kg := generateMultiSigParamsBLS(4, ownIndex)

	t.Run("with rogue key prevention", func(t *testing.T) {
		multiSig, _ := multisig.NewBLSMultisig(llSigner, pubKeys, privKey, kg, ownIndex)

		err := multiSig.Reset(pubKeys, ownIndex)
		assert.Nil(t, err)
	})
	t.Run("with KOSK", func(t *testing.T) {
		multiSig, _ := multisig.NewBLSMultisig(llSignerKOSK, pubKeys, privKey, kg, ownIndex)

		err := multiSig.Reset(pubKeys, ownIndex)
		assert.Nil(t, err)
	})
}

func TestBLSMultiSigner_CreateSignatureShareNilMessageShouldErr(t *testing.T) {
	t.Parallel()

	ownIndex := uint16(3)
	hasher := &mock.HasherSpongeMock{}
	llSigner := &llsig.BlsMultiSigner{Hasher: hasher}
	llSignerKOSK := &llsig.BlsMultiSignerKOSK{}
	privKey, _, pubKeys, kg := generateMultiSigParamsBLS(4, ownIndex)

	t.Run("with rogue key prevention", func(t *testing.T) {
		multiSig, _ := multisig.NewBLSMultisig(llSigner, pubKeys, privKey, kg, ownIndex)
		sigShare, err := multiSig.CreateSignatureShare(nil, []byte(""))

		assert.Nil(t, sigShare)
		assert.Equal(t, crypto.ErrNilMessage, err)
	})
	t.Run("with KOSK", func(t *testing.T) {
		multiSig, _ := multisig.NewBLSMultisig(llSignerKOSK, pubKeys, privKey, kg, ownIndex)
		sigShare, err := multiSig.CreateSignatureShare(nil, []byte(""))

		assert.Nil(t, sigShare)
		assert.Equal(t, crypto.ErrNilMessage, err)
	})
}

func TestBLSMultiSigner_CreateSignatureShareOK(t *testing.T) {
	t.Parallel()

	ownIndex := uint16(3)
	hasher := &mock.HasherSpongeMock{}
	llSigner := &llsig.BlsMultiSigner{Hasher: hasher}
	llSignerKOSK := &llsig.BlsMultiSignerKOSK{}
	privKey, _, pubKeys, kg := generateMultiSigParamsBLS(4, ownIndex)
	msg := []byte("message")

	t.Run("with rogue key prevention", func(t *testing.T) {
		multiSig, _ := multisig.NewBLSMultisig(llSigner, pubKeys, privKey, kg, ownIndex)
		sigShare, err := multiSig.CreateSignatureShare(msg, []byte(""))

		verifErr := multiSig.VerifySignatureShare(ownIndex, sigShare, msg, []byte(""))

		assert.Nil(t, err)
		assert.NotNil(t, sigShare)
		assert.Nil(t, verifErr)
	})
	t.Run("with KOSK", func(t *testing.T) {
		multiSig, _ := multisig.NewBLSMultisig(llSignerKOSK, pubKeys, privKey, kg, ownIndex)
		sigShare, err := multiSig.CreateSignatureShare(msg, []byte(""))

		verifErr := multiSig.VerifySignatureShare(ownIndex, sigShare, msg, []byte(""))

		assert.Nil(t, err)
		assert.NotNil(t, sigShare)
		assert.Nil(t, verifErr)
	})
}

func TestBLSMultiSigner_VerifySignatureShareNilSigShouldErr(t *testing.T) {
	t.Parallel()

	ownIndex := uint16(3)
	hasher := &mock.HasherSpongeMock{}
	llSigner := &llsig.BlsMultiSigner{Hasher: hasher}
	llSignerKOSK := &llsig.BlsMultiSignerKOSK{}
	privKey, _, pubKeys, kg := generateMultiSigParamsBLS(4, ownIndex)
	msg := []byte("message")

	t.Run("with rogue key prevention", func(t *testing.T) {
		_, multiSig := createSignerAndSigShareBLS(pubKeys, privKey, kg, ownIndex, msg, llSigner)

		verifErr := multiSig.VerifySignatureShare(ownIndex, nil, msg, []byte(""))

		assert.Equal(t, crypto.ErrNilSignature, verifErr)
	})
	t.Run("with KOSK", func(t *testing.T) {
		_, multiSig := createSignerAndSigShareBLS(pubKeys, privKey, kg, ownIndex, msg, llSignerKOSK)

		verifErr := multiSig.VerifySignatureShare(ownIndex, nil, msg, []byte(""))

		assert.Equal(t, crypto.ErrNilSignature, verifErr)
	})
}

func TestBLSMultiSigner_VerifySignatureShareInvalidSignatureShouldErr(t *testing.T) {
	t.Parallel()

	ownIndex := uint16(3)
	hasher := &mock.HasherSpongeMock{}
	llSigner := &llsig.BlsMultiSigner{Hasher: hasher}
	llSignerKOSK := &llsig.BlsMultiSignerKOSK{}
	privKey, _, pubKeys, kg := generateMultiSigParamsBLS(4, ownIndex)
	msg := []byte("message")

	t.Run("with rogue key prevention", func(t *testing.T) {
		sigShare, multiSig := createSignerAndSigShareBLS(pubKeys, privKey, kg, ownIndex, msg, llSigner)
		verifErr := multiSig.VerifySignatureShare(0, sigShare, msg, []byte(""))

		assert.NotNil(t, verifErr)
		assert.Contains(t, verifErr.Error(), "signature is invalid")
	})
	t.Run("with KOSK", func(t *testing.T) {
		sigShare, multiSig := createSignerAndSigShareBLS(pubKeys, privKey, kg, ownIndex, msg, llSignerKOSK)
		verifErr := multiSig.VerifySignatureShare(0, sigShare, msg, []byte(""))

		assert.NotNil(t, verifErr)
		assert.Contains(t, verifErr.Error(), "signature is invalid")
	})
}

func TestBLSMultiSigner_VerifySignatureShareOK(t *testing.T) {
	t.Parallel()

	ownIndex := uint16(3)
	hasher := &mock.HasherSpongeMock{}
	llSigner := &llsig.BlsMultiSigner{Hasher: hasher}
	llSignerKOSK := &llsig.BlsMultiSignerKOSK{}
	privKey, _, pubKeys, kg := generateMultiSigParamsBLS(4, ownIndex)
	msg := []byte("message")

	t.Run("with rogue key prevention", func(t *testing.T) {
		sigShare, multiSig := createSignerAndSigShareBLS(pubKeys, privKey, kg, ownIndex, msg, llSigner)

		verifErr := multiSig.VerifySignatureShare(ownIndex, sigShare, msg, []byte(""))

		assert.Nil(t, verifErr)
	})
	t.Run("with KOSK", func(t *testing.T) {
		sigShare, multiSig := createSignerAndSigShareBLS(pubKeys, privKey, kg, ownIndex, msg, llSignerKOSK)

		verifErr := multiSig.VerifySignatureShare(ownIndex, sigShare, msg, []byte(""))

		assert.Nil(t, verifErr)
	})
}

func TestBLSMultiSigner_AddSignatureShareNilSigShouldErr(t *testing.T) {
	t.Parallel()

	ownIndex := uint16(3)
	hasher := &mock.HasherSpongeMock{}
	llSigner := &llsig.BlsMultiSigner{Hasher: hasher}
	llSignerKOSK := &llsig.BlsMultiSignerKOSK{}
	privKey, _, pubKeys, kg := generateMultiSigParamsBLS(4, ownIndex)

	t.Run("with rogue key prevention", func(t *testing.T) {
		multiSig, _ := multisig.NewBLSMultisig(llSigner, pubKeys, privKey, kg, ownIndex)

		err := multiSig.StoreSignatureShare(ownIndex, nil)

		assert.Equal(t, crypto.ErrNilSignature, err)
	})
	t.Run("with KOSK", func(t *testing.T) {
		multiSig, _ := multisig.NewBLSMultisig(llSignerKOSK, pubKeys, privKey, kg, ownIndex)

		err := multiSig.StoreSignatureShare(ownIndex, nil)

		assert.Equal(t, crypto.ErrNilSignature, err)
	})
}

func TestBLSMultiSigner_AddSignatureShareIndexOutOfBoundsIndexShouldErr(t *testing.T) {
	t.Parallel()

	ownIndex := uint16(3)
	hasher := &mock.HasherSpongeMock{}
	llSigner := &llsig.BlsMultiSigner{Hasher: hasher}
	llSignerKOSK := &llsig.BlsMultiSignerKOSK{}
	privKey, _, pubKeys, kg := generateMultiSigParamsBLS(4, ownIndex)

	t.Run("with rogue key prevention", func(t *testing.T) {
		sigShare, multiSig := createSignerAndSigShareBLS(pubKeys, privKey, kg, ownIndex, []byte("message"), llSigner)

		err := multiSig.StoreSignatureShare(15, sigShare)

		assert.Equal(t, crypto.ErrIndexOutOfBounds, err)
	})
	t.Run("with KOSK", func(t *testing.T) {
		sigShare, multiSig := createSignerAndSigShareBLS(pubKeys, privKey, kg, ownIndex, []byte("message"), llSignerKOSK)

		err := multiSig.StoreSignatureShare(15, sigShare)

		assert.Equal(t, crypto.ErrIndexOutOfBounds, err)
	})
}

func TestBLSMultiSigner_SignatureShareOutOfBoundsIndexShouldErr(t *testing.T) {
	t.Parallel()

	ownIndex := uint16(3)
	hasher := &mock.HasherSpongeMock{}
	llSigner := &llsig.BlsMultiSigner{Hasher: hasher}
	llSignerKOSK := &llsig.BlsMultiSignerKOSK{}
	privKey, _, pubKeys, kg := generateMultiSigParamsBLS(4, ownIndex)
	msg := []byte("message")

	t.Run("with rogue key prevention", func(t *testing.T) {
		sigShare, multiSig := createSignerAndSigShareBLS(pubKeys, privKey, kg, ownIndex, msg, llSigner)
		_ = multiSig.StoreSignatureShare(ownIndex, sigShare)
		sigShareRead, err := multiSig.SignatureShare(15)

		assert.Nil(t, sigShareRead)
		assert.Equal(t, crypto.ErrIndexOutOfBounds, err)
	})
	t.Run("with KOSK", func(t *testing.T) {
		sigShare, multiSig := createSignerAndSigShareBLS(pubKeys, privKey, kg, ownIndex, msg, llSignerKOSK)
		_ = multiSig.StoreSignatureShare(ownIndex, sigShare)
		sigShareRead, err := multiSig.SignatureShare(15)

		assert.Nil(t, sigShareRead)
		assert.Equal(t, crypto.ErrIndexOutOfBounds, err)
	})
}

func TestBLSMultiSigner_SignatureShareNotSetIndexShouldErr(t *testing.T) {
	t.Parallel()

	ownIndex := uint16(3)
	hasher := &mock.HasherSpongeMock{}
	llSigner := &llsig.BlsMultiSigner{Hasher: hasher}
	llSignerKOSK := &llsig.BlsMultiSignerKOSK{}
	privKey, _, pubKeys, kg := generateMultiSigParamsBLS(4, ownIndex)
	msg := []byte("message")

	t.Run("with rogue key prevention", func(t *testing.T) {
		sigShare, multiSig := createSignerAndSigShareBLS(pubKeys, privKey, kg, ownIndex, msg, llSigner)
		_ = multiSig.StoreSignatureShare(ownIndex, sigShare)
		sigShareRead, err := multiSig.SignatureShare(2)

		assert.Nil(t, sigShareRead)
		assert.Equal(t, crypto.ErrNilElement, err)
	})
	t.Run("with KOSK", func(t *testing.T) {
		sigShare, multiSig := createSignerAndSigShareBLS(pubKeys, privKey, kg, ownIndex, msg, llSignerKOSK)
		_ = multiSig.StoreSignatureShare(ownIndex, sigShare)
		sigShareRead, err := multiSig.SignatureShare(2)

		assert.Nil(t, sigShareRead)
		assert.Equal(t, crypto.ErrNilElement, err)
	})
}

func TestBLSMultiSigner_SignatureShareOK(t *testing.T) {
	t.Parallel()

	ownIndex := uint16(3)
	hasher := &mock.HasherSpongeMock{}
	llSigner := &llsig.BlsMultiSigner{Hasher: hasher}
	llSignerKOSK := &llsig.BlsMultiSignerKOSK{}
	privKey, _, pubKeys, kg := generateMultiSigParamsBLS(4, ownIndex)
	msg := []byte("message")

	t.Run("with rogue key prevention", func(t *testing.T) {
		sigShare, multiSig := createSignerAndSigShareBLS(pubKeys, privKey, kg, ownIndex, msg, llSigner)
		_ = multiSig.StoreSignatureShare(ownIndex, sigShare)
		sigShareRead, err := multiSig.SignatureShare(ownIndex)

		assert.Nil(t, err)
		assert.Equal(t, sigShare, sigShareRead)
	})
	t.Run("with KOSK", func(t *testing.T) {
		sigShare, multiSig := createSignerAndSigShareBLS(pubKeys, privKey, kg, ownIndex, msg, llSignerKOSK)
		_ = multiSig.StoreSignatureShare(ownIndex, sigShare)
		sigShareRead, err := multiSig.SignatureShare(ownIndex)

		assert.Nil(t, err)
		assert.Equal(t, sigShare, sigShareRead)
	})
}

func TestBLSMultiSigner_AggregateSigsNilBitmapShouldErr(t *testing.T) {
	t.Parallel()

	grSize := uint16(6)
	ownIndex := uint16(0)
	nbSigners := uint16(3)
	message := []byte("message")
	bitmap := make([]byte, 2)
	bitmap[0] = 0x07
	hasher := &mock.HasherSpongeMock{}
	llSigner := &llsig.BlsMultiSigner{Hasher: hasher}
	llSignerKOSK := &llsig.BlsMultiSignerKOSK{}

	t.Run("with rogue key prevention", func(t *testing.T) {
		sigs, multiSigner := createSigSharesBLS(nbSigners, grSize, message, ownIndex, llSigner)

		for i := 0; i < len(sigs); i++ {
			_ = multiSigner.StoreSignatureShare(uint16(i), sigs[i])
		}

		aggSig, err := multiSigner.AggregateSigs(nil)

		assert.Nil(t, aggSig)
		assert.Equal(t, crypto.ErrNilBitmap, err)
	})
	t.Run("with KOSK", func(t *testing.T) {
		sigs, multiSigner := createSigSharesBLS(nbSigners, grSize, message, ownIndex, llSignerKOSK)

		for i := 0; i < len(sigs); i++ {
			_ = multiSigner.StoreSignatureShare(uint16(i), sigs[i])
		}

		aggSig, err := multiSigner.AggregateSigs(nil)

		assert.Nil(t, aggSig)
		assert.Equal(t, crypto.ErrNilBitmap, err)
	})
}

func TestBLSMultiSigner_AggregateSigsInvalidBitmapShouldErr(t *testing.T) {
	t.Parallel()

	grSize := uint16(21)
	ownIndex := uint16(0)
	nbSigners := uint16(3)
	message := []byte("message")
	bitmap := make([]byte, 3)
	bitmap[0] = 0x07
	hasher := &mock.HasherSpongeMock{}
	llSigner := &llsig.BlsMultiSigner{Hasher: hasher}
	llSignerKOSK := &llsig.BlsMultiSignerKOSK{}
	bitmap = []byte{0x07}

	t.Run("with rogue key prevention", func(t *testing.T) {
		sigs, multiSigner := createSigSharesBLS(nbSigners, grSize, message, ownIndex, llSigner)

		for i := 0; i < len(sigs); i++ {
			_ = multiSigner.StoreSignatureShare(uint16(i), sigs[i])
		}

		aggSig, err := multiSigner.AggregateSigs(bitmap)

		assert.Nil(t, aggSig)
		assert.Equal(t, crypto.ErrBitmapMismatch, err)
	})
	t.Run("with KOSK", func(t *testing.T) {
		sigs, multiSigner := createSigSharesBLS(nbSigners, grSize, message, ownIndex, llSignerKOSK)

		for i := 0; i < len(sigs); i++ {
			_ = multiSigner.StoreSignatureShare(uint16(i), sigs[i])
		}

		aggSig, err := multiSigner.AggregateSigs(bitmap)

		assert.Nil(t, aggSig)
		assert.Equal(t, crypto.ErrBitmapMismatch, err)
	})
}

func TestBLSMultiSigner_AggregateSigsMissingSigShareShouldErr(t *testing.T) {
	t.Parallel()

	grSize := uint16(6)
	ownIndex := uint16(0)
	nbSigners := uint16(3)
	message := []byte("message")
	bitmap := make([]byte, 2)
	bitmap[0] = 0x07
	hasher := &mock.HasherSpongeMock{}
	llSigner := &llsig.BlsMultiSigner{Hasher: hasher}
	llSignerKOSK := &llsig.BlsMultiSignerKOSK{}

	t.Run("with rogue key prevention", func(t *testing.T) {
		sigs, multiSigner := createSigSharesBLS(nbSigners, grSize, message, ownIndex, llSigner)

		for i := 0; i < len(sigs)-1; i++ {
			_ = multiSigner.StoreSignatureShare(uint16(i), sigs[i])
		}

		aggSig, err := multiSigner.AggregateSigs(bitmap)

		assert.Nil(t, aggSig)
		assert.Equal(t, crypto.ErrNilSignature, err)
	})
	t.Run("with KOSK", func(t *testing.T) {
		sigs, multiSigner := createSigSharesBLS(nbSigners, grSize, message, ownIndex, llSignerKOSK)

		for i := 0; i < len(sigs)-1; i++ {
			_ = multiSigner.StoreSignatureShare(uint16(i), sigs[i])
		}

		aggSig, err := multiSigner.AggregateSigs(bitmap)

		assert.Nil(t, aggSig)
		assert.Equal(t, crypto.ErrNilSignature, err)
	})
}

func TestBLSMultiSigner_AggregateSigsZeroSelectionBitmapShouldErr(t *testing.T) {
	t.Parallel()

	grSize := uint16(6)
	ownIndex := uint16(0)
	nbSigners := uint16(3)
	message := []byte("message")
	bitmap := make([]byte, 2)
	bitmap[0] = 0x07
	hasher := &mock.HasherSpongeMock{}
	llSigner := &llsig.BlsMultiSigner{Hasher: hasher}
	llSignerKOSK := &llsig.BlsMultiSignerKOSK{}

	t.Run("with rogue key prevention", func(t *testing.T) {
		sigs, multiSigner := createSigSharesBLS(nbSigners, grSize, message, ownIndex, llSigner)

		for i := 0; i < len(sigs)-1; i++ {
			_ = multiSigner.StoreSignatureShare(uint16(i), sigs[i])
		}
		bitmap[0] = 0
		aggSig, err := multiSigner.AggregateSigs(bitmap)

		assert.Nil(t, aggSig)
		assert.Equal(t, crypto.ErrNilSignaturesList, err)
	})
	t.Run("with KOSK", func(t *testing.T) {
		sigs, multiSigner := createSigSharesBLS(nbSigners, grSize, message, ownIndex, llSignerKOSK)

		for i := 0; i < len(sigs)-1; i++ {
			_ = multiSigner.StoreSignatureShare(uint16(i), sigs[i])
		}
		bitmap[0] = 0
		aggSig, err := multiSigner.AggregateSigs(bitmap)

		assert.Nil(t, aggSig)
		assert.Equal(t, crypto.ErrNilSignaturesList, err)
	})
}

func TestBLSMultiSigner_AggregateSigsOK(t *testing.T) {
	t.Parallel()

	grSize := uint16(6)
	ownIndex := uint16(0)
	nbSigners := uint16(3)
	message := []byte("message")
	bitmap := make([]byte, 2)
	bitmap[0] = 0x07
	hasher := &mock.HasherSpongeMock{}
	llSigner := &llsig.BlsMultiSigner{Hasher: hasher}
	llSignerKOSK := &llsig.BlsMultiSignerKOSK{}

	t.Run("with rogue key prevention", func(t *testing.T) {
		sigs, multiSigner := createSigSharesBLS(nbSigners, grSize, message, ownIndex, llSigner)

		for i := 0; i < len(sigs); i++ {
			_ = multiSigner.StoreSignatureShare(uint16(i), sigs[i])
		}

		aggSig, err := multiSigner.AggregateSigs(bitmap)

		assert.Nil(t, err)
		assert.NotNil(t, aggSig)
	})
	t.Run("with KOSK", func(t *testing.T) {
		sigs, multiSigner := createSigSharesBLS(nbSigners, grSize, message, ownIndex, llSignerKOSK)

		for i := 0; i < len(sigs); i++ {
			_ = multiSigner.StoreSignatureShare(uint16(i), sigs[i])
		}

		aggSig, err := multiSigner.AggregateSigs(bitmap)

		assert.Nil(t, err)
		assert.NotNil(t, aggSig)
	})
}

func TestBLSMultiSigner_SetAggregatedSigNilSigShouldErr(t *testing.T) {
	t.Parallel()
	msg := []byte("message")
	hasher := &mock.HasherSpongeMock{}
	llSigner := &llsig.BlsMultiSigner{Hasher: hasher}
	llSignerKOSK := &llsig.BlsMultiSignerKOSK{}

	t.Run("with rogue key prevention", func(t *testing.T) {
		multiSigner, _, _ := createAggregatedSigBLS(msg, llSigner, t)
		err := multiSigner.SetAggregatedSig(nil)

		assert.Equal(t, crypto.ErrNilSignature, err)
	})
	t.Run("with KOSK", func(t *testing.T) {
		multiSigner, _, _ := createAggregatedSigBLS(msg, llSignerKOSK, t)
		err := multiSigner.SetAggregatedSig(nil)

		assert.Equal(t, crypto.ErrNilSignature, err)
	})
}

func TestBLSMultiSigner_SetAggregatedSigInvalidScalarShouldErr(t *testing.T) {
	t.Parallel()

	msg := []byte("message")
	hasher := &mock.HasherSpongeMock{}
	llSigner := &llsig.BlsMultiSigner{Hasher: hasher}
	llSignerKOSK := &llsig.BlsMultiSignerKOSK{}

	t.Run("with rogue key prevention", func(t *testing.T) {
		multiSigner, _, _ := createAggregatedSigBLS(msg, llSigner, t)
		aggSig := []byte("invalid agg signature xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
		err := multiSigner.SetAggregatedSig(aggSig)

		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "err blsSignatureDeserialize")
	})
	t.Run("with KOSK", func(t *testing.T) {
		multiSigner, _, _ := createAggregatedSigBLS(msg, llSignerKOSK, t)
		aggSig := []byte("invalid agg signature xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
		err := multiSigner.SetAggregatedSig(aggSig)

		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "err blsSignatureDeserialize")
	})
}

func TestBLSMultiSigner_SetAggregatedSigOK(t *testing.T) {
	t.Parallel()

	msg := []byte("message")
	hasher := &mock.HasherSpongeMock{}
	llSigner := &llsig.BlsMultiSigner{Hasher: hasher}
	llSignerKOSK := &llsig.BlsMultiSignerKOSK{}

	t.Run("with rogue key prevention", func(t *testing.T) {
		multiSigner, aggSig, _ := createAggregatedSigBLS(msg, llSigner, t)
		err := multiSigner.SetAggregatedSig(aggSig)

		assert.Nil(t, err)
	})
	t.Run("with KOSK", func(t *testing.T) {
		multiSigner, aggSig, _ := createAggregatedSigBLS(msg, llSignerKOSK, t)
		err := multiSigner.SetAggregatedSig(aggSig)

		assert.Nil(t, err)
	})
}

func TestBLSMultiSigner_VerifyNilBitmapShouldErr(t *testing.T) {
	t.Parallel()

	msg := []byte("message")
	hasher := &mock.HasherSpongeMock{}
	llSigner := &llsig.BlsMultiSigner{Hasher: hasher}
	llSignerKOSK := &llsig.BlsMultiSignerKOSK{}

	t.Run("with rogue key prevention", func(t *testing.T) {
		multiSigner, aggSig, _ := createAggregatedSigBLS(msg, llSigner, t)
		_ = multiSigner.SetAggregatedSig(aggSig)
		err := multiSigner.Verify(msg, nil)

		assert.Equal(t, crypto.ErrNilBitmap, err)
	})
	t.Run("with KOSK", func(t *testing.T) {
		multiSigner, aggSig, _ := createAggregatedSigBLS(msg, llSignerKOSK, t)
		_ = multiSigner.SetAggregatedSig(aggSig)
		err := multiSigner.Verify(msg, nil)

		assert.Equal(t, crypto.ErrNilBitmap, err)
	})
}

func TestBLSMultiSigner_VerifyBitmapMismatchShouldErr(t *testing.T) {
	t.Parallel()
	msg := []byte("message")
	hasher := &mock.HasherSpongeMock{}
	llSigner := &llsig.BlsMultiSigner{Hasher: hasher}
	llSignerKOSK := &llsig.BlsMultiSignerKOSK{}
	// set a smaller bitmap
	bitmap := make([]byte, 1)

	t.Run("with rogue key prevention", func(t *testing.T) {
		multiSigner, aggSig, _ := createAggregatedSigBLS(msg, llSigner, t)
		_ = multiSigner.SetAggregatedSig(aggSig)

		err := multiSigner.Verify(msg, bitmap)
		assert.Equal(t, crypto.ErrBitmapMismatch, err)
	})
	t.Run("with KOSK", func(t *testing.T) {
		multiSigner, aggSig, _ := createAggregatedSigBLS(msg, llSignerKOSK, t)
		_ = multiSigner.SetAggregatedSig(aggSig)

		err := multiSigner.Verify(msg, bitmap)
		assert.Equal(t, crypto.ErrBitmapMismatch, err)
	})
}

func TestBLSMultiSigner_VerifyAggSigNotSetShouldErr(t *testing.T) {
	t.Parallel()

	msg := []byte("message")
	hasher := &mock.HasherSpongeMock{}
	llSigner := &llsig.BlsMultiSigner{Hasher: hasher}
	llSignerKOSK := &llsig.BlsMultiSignerKOSK{}

	t.Run("with rogue key prevention", func(t *testing.T) {
		multiSigner, bitmap := createAndAddSignatureSharesBLS(msg, llSigner)
		err := multiSigner.Verify(bitmap, msg)

		assert.NotNil(t, err)
		assert.Equal(t, crypto.ErrNilSignature, err)
	})
	t.Run("with KOSK", func(t *testing.T) {
		multiSigner, bitmap := createAndAddSignatureSharesBLS(msg, llSignerKOSK)
		err := multiSigner.Verify(bitmap, msg)

		assert.NotNil(t, err)
		assert.Equal(t, crypto.ErrNilSignature, err)
	})
}

func TestBLSMultiSigner_VerifySigValid(t *testing.T) {
	t.Parallel()

	msg := []byte("message")
	hasher := &mock.HasherSpongeMock{}
	llSigner := &llsig.BlsMultiSigner{Hasher: hasher}
	llSignerKOSK := &llsig.BlsMultiSignerKOSK{}

	t.Run("with rogue key prevention", func(t *testing.T) {
		multiSigner, aggSig, bitmap := createAggregatedSigBLS(msg, llSigner, t)
		_ = multiSigner.SetAggregatedSig(aggSig)

		err := multiSigner.Verify(msg, bitmap)
		assert.Nil(t, err)
	})
	t.Run("with KOSK", func(t *testing.T) {
		multiSigner, aggSig, bitmap := createAggregatedSigBLS(msg, llSignerKOSK, t)
		_ = multiSigner.SetAggregatedSig(aggSig)

		err := multiSigner.Verify(msg, bitmap)
		assert.Nil(t, err)
	})
}

func TestBLSMultiSigner_VerifySigInvalid(t *testing.T) {
	t.Parallel()

	msg := []byte("message")
	hasher := &mock.HasherSpongeMock{}
	llSigner := &llsig.BlsMultiSigner{Hasher: hasher}
	llSignerKOSK := &llsig.BlsMultiSignerKOSK{}

	t.Run("with rogue key prevention", func(t *testing.T) {
		multiSigner, aggSig, bitmap := createAggregatedSigBLS(msg, llSigner, t)
		// make sig invalid
		aggSig[len(aggSig)-1] = aggSig[len(aggSig)-1] ^ 255
		_ = multiSigner.SetAggregatedSig(aggSig)
		err := multiSigner.Verify(bitmap, msg)

		assert.NotNil(t, err)
	})
	t.Run("with KOSK", func(t *testing.T) {
		multiSigner, aggSig, bitmap := createAggregatedSigBLS(msg, llSignerKOSK, t)
		// make sig invalid
		aggSig[len(aggSig)-1] = aggSig[len(aggSig)-1] ^ 255
		_ = multiSigner.SetAggregatedSig(aggSig)
		err := multiSigner.Verify(bitmap, msg)

		assert.NotNil(t, err)
	})
}

func TestBlsMultiSigner_CreateAndAddSignatureShareForKey(t *testing.T) {
	t.Parallel()

	msg := []byte("message")
	ownIndex := uint16(1)
	hasher := &mock.HasherSpongeMock{}
	llSigner := &llsig.BlsMultiSigner{Hasher: hasher}
	llSignerKOSK := &llsig.BlsMultiSignerKOSK{}
	sk, _, privKeys, pubKeys, kg := generateMultiSigParamsBLSWithPrivateKeys(4, ownIndex)

	multiSig, err := multisig.NewBLSMultisig(llSigner, pubKeys, sk, kg, ownIndex)
	require.Nil(t, err)
	multiSigCreated, err := multiSig.Create(pubKeys, ownIndex)
	require.Nil(t, err)

	multiSigKOSK, err := multisig.NewBLSMultisig(llSignerKOSK, pubKeys, sk, kg, ownIndex)
	require.Nil(t, err)
	multiSigKOSKCreated, err := multiSigKOSK.Create(pubKeys, ownIndex)
	require.Nil(t, err)

	for idx, privKey := range privKeys {
		_, err = multiSigCreated.CreateAndAddSignatureShareForKey(msg, privKey, []byte(pubKeys[idx]))
		require.Nil(t, err)
		_, err = multiSigKOSKCreated.CreateAndAddSignatureShareForKey(msg, privKey, []byte(pubKeys[idx]))
		require.Nil(t, err)
	}

	allSigSharesBitmap := []byte{15}
	sig, err := multiSigCreated.AggregateSigs(allSigSharesBitmap)
	require.Nil(t, err)
	require.True(t, len(sig) > 0)

	multiSigVerify, err := multiSig.Create(pubKeys, ownIndex)
	require.Nil(t, err)

	err = multiSigVerify.SetAggregatedSig(sig)
	require.Nil(t, err)

	err = multiSigVerify.Verify(msg, allSigSharesBitmap)
	require.Nil(t, err)

	sigKOSK, err := multiSigKOSKCreated.AggregateSigs(allSigSharesBitmap)
	require.Nil(t, err)
	require.True(t, len(sigKOSK) > 0)
	// the aggregated signatures are different
	require.NotEqual(t, sig, sigKOSK)

	multiSigKOSKVerify, err := multiSigKOSK.Create(pubKeys, ownIndex)
	require.Nil(t, err)
	err = multiSigKOSKVerify.SetAggregatedSig(sigKOSK)
	require.Nil(t, err)
	err = multiSigKOSKVerify.Verify(msg, allSigSharesBitmap)
	require.Nil(t, err)
}
