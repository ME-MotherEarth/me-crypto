package multisig

import (
	"github.com/ME-MotherEarth/me-core/core/check"
	"github.com/ME-MotherEarth/me-core/hashing"
	crypto "github.com/ME-MotherEarth/me-crypto"
	"github.com/ME-MotherEarth/me-crypto/signing/mcl"
	"github.com/ME-MotherEarth/me-crypto/signing/mcl/singlesig"
	"github.com/herumi/bls-go-binary/bls"
)

var _ crypto.LowLevelSignerBLS = (*BlsMultiSigner)(nil)

// 16bytes output hasher!
const hasherOutputSize = 16

// BlsMultiSigner provides an implements of the crypto.LowLevelSignerBLS interface
type BlsMultiSigner struct {
	singlesig.BlsSingleSigner
	Hasher hashing.Hasher
}

// SignShare produces a BLS signature share (single BLS signature) over a given message
func (bms *BlsMultiSigner) SignShare(privKey crypto.PrivateKey, message []byte) ([]byte, error) {
	return bms.Sign(privKey, message)
}

// VerifySigShare verifies a BLS signature share (single BLS signature) over a given message
func (bms *BlsMultiSigner) VerifySigShare(pubKey crypto.PublicKey, message []byte, sig []byte) error {
	return bms.Verify(pubKey, message, sig)
}

// VerifySigBytes provides an "cheap" integrity check of a signature given as a byte array
// It does not validate the signature over a message, only verifies that it is a signature
func (bms *BlsMultiSigner) VerifySigBytes(_ crypto.Suite, sig []byte) error {
	if len(sig) == 0 {
		return crypto.ErrNilSignature
	}

	_, err := sigBytesToPoint(sig)

	return err
}

// AggregateSignatures produces an aggregation of single BLS signatures over the same message
func (bms *BlsMultiSigner) AggregateSignatures(
	suite crypto.Suite,
	signatures [][]byte,
	pubKeysSigners []crypto.PublicKey,
) ([]byte, error) {
	if check.IfNil(suite) {
		return nil, crypto.ErrNilSuite
	}
	if len(signatures) == 0 {
		return nil, crypto.ErrNilSignaturesList
	}
	if len(pubKeysSigners) == 0 {
		return nil, crypto.ErrNilPublicKeys
	}
	_, ok := suite.GetUnderlyingSuite().(*mcl.SuiteBLS12)
	if !ok {
		return nil, crypto.ErrInvalidSuite
	}

	sigsBLS, err := bms.prepareSignatures(suite, signatures, pubKeysSigners)
	if err != nil {
		return nil, err
	}

	aggSigBLS := &bls.Sign{}
	aggSigBLS.Aggregate(sigsBLS)

	return aggSigBLS.Serialize(), nil
}

// VerifyAggregatedSig verifies if a BLS aggregated signature is valid over a given message
func (bms *BlsMultiSigner) VerifyAggregatedSig(
	suite crypto.Suite,
	pubKeys []crypto.PublicKey,
	aggSigBytes []byte,
	msg []byte,
) error {
	if check.IfNil(suite) {
		return crypto.ErrNilSuite
	}
	if len(pubKeys) == 0 {
		return crypto.ErrNilPublicKeys
	}
	if len(aggSigBytes) == 0 {
		return crypto.ErrNilSignature
	}
	if len(msg) == 0 {
		return crypto.ErrNilMessage
	}

	_, ok := suite.GetUnderlyingSuite().(*mcl.SuiteBLS12)
	if !ok {
		return crypto.ErrInvalidSuite
	}

	preparedPubKeys, err := preparePublicKeys(pubKeys, bms.Hasher, suite)
	if err != nil {
		return err
	}

	aggSig := &bls.Sign{}
	err = aggSig.Deserialize(aggSigBytes)
	if err != nil {
		return err
	}

	res := aggSig.FastAggregateVerify(preparedPubKeys, msg)
	if !res {
		return crypto.ErrAggSigNotValid
	}

	return nil
}

func preparePublicKeys(
	pubKeys []crypto.PublicKey,
	hasher hashing.Hasher,
	suite crypto.Suite,
) ([]bls.PublicKey, error) {
	var hPk []byte
	var prepPublicKeyPoint crypto.Point
	var pubKeyPoint crypto.Point
	prepPubKeysPoints := make([]bls.PublicKey, len(pubKeys))

	concatPKs, err := concatPubKeys(pubKeys)
	if err != nil {
		return nil, err
	}

	for i, pubKey := range pubKeys {
		if check.IfNil(pubKey) {
			return nil, crypto.ErrNilPublicKey
		}

		pubKeyPoint = pubKey.Point()

		// t_i = H(pk_i, {pk_1, ..., pk_n})
		hPk, err = hashPublicKeyPoints(hasher, pubKeyPoint, concatPKs)
		if err != nil {
			return nil, err
		}

		// t_i*pubKey_i
		prepPublicKeyPoint, err = scalarMulPk(suite, hPk, pubKeyPoint)
		if err != nil {
			return nil, err
		}

		prepPubKeyG2, ok := prepPublicKeyPoint.GetUnderlyingObj().(*bls.G2)
		if !ok {
			return nil, crypto.ErrInvalidPoint
		}
		prepPubKeysPoints[i] = *bls.CastToPublicKey(prepPubKeyG2)
	}

	return prepPubKeysPoints, nil
}

func (bms *BlsMultiSigner) prepareSignatures(
	suite crypto.Suite,
	signatures [][]byte,
	pubKeysSigners []crypto.PublicKey,
) ([]bls.Sign, error) {
	if len(signatures) == 0 {
		return nil, crypto.ErrNilSignaturesList
	}
	concatPKs, err := concatPubKeys(pubKeysSigners)
	if err != nil {
		return nil, err
	}

	var hPk []byte
	var sPointG1 *mcl.PointG1
	prepSigs := make([]bls.Sign, 0)

	for i, sig := range signatures {
		sigBLS := &bls.Sign{}
		if len(sig) == 0 {
			return nil, crypto.ErrNilSignature
		}

		err = sigBLS.Deserialize(sig)
		if err != nil {
			return nil, err
		}

		if !singlesig.IsSigValidPoint(sigBLS) {
			return nil, crypto.ErrBLSInvalidSignature
		}

		pubKeyPoint := pubKeysSigners[i].Point()
		mclPointG2, isPoint := pubKeyPoint.(*mcl.PointG2)
		if !isPoint || !singlesig.IsPubKeyPointValid(mclPointG2) {
			return nil, crypto.ErrInvalidPublicKey
		}

		sigPoint := mcl.NewPointG1()
		sigPoint.G1 = bls.CastFromSign(sigBLS)

		hPk, err = hashPublicKeyPoints(bms.Hasher, pubKeyPoint, concatPKs)
		if err != nil {
			return nil, err
		}
		// H1(pubKey_i)*sig_i
		sPointG1, err = scalarMulSig(suite, hPk, sigPoint)
		if err != nil {
			return nil, err
		}

		sigBLS = bls.CastToSign(sPointG1.G1)
		prepSigs = append(prepSigs, *sigBLS)
	}

	return prepSigs, nil
}

// concatenatePubKeys concatenates the public keys
func concatPubKeys(pubKeys []crypto.PublicKey) ([]byte, error) {
	if len(pubKeys) == 0 {
		return nil, crypto.ErrNilPublicKeys
	}

	var point crypto.Point
	var pointBytes []byte
	var err error
	sizeBytesPubKey := pubKeys[0].Suite().PointLen()
	result := make([]byte, 0, len(pubKeys)*sizeBytesPubKey)

	for _, pk := range pubKeys {
		if check.IfNil(pk) {
			return nil, crypto.ErrNilPublicKey
		}

		point = pk.Point()
		if check.IfNil(point) {
			return nil, crypto.ErrNilPublicKeyPoint
		}

		pointBytes, err = point.MarshalBinary()
		if err != nil {
			return nil, err
		}

		result = append(result, pointBytes...)
	}

	return result, nil
}

// hashPublicKeyPoints hashes the concatenation of public keys with the given public key poiint
func hashPublicKeyPoints(hasher hashing.Hasher, pubKeyPoint crypto.Point, concatPubKeys []byte) ([]byte, error) {
	if check.IfNil(hasher) {
		return nil, crypto.ErrNilHasher
	}
	if len(concatPubKeys) == 0 {
		return nil, crypto.ErrNilParam
	}
	if hasher.Size() != hasherOutputSize {
		return nil, crypto.ErrWrongSizeHasher
	}
	if check.IfNil(pubKeyPoint) {
		return nil, crypto.ErrNilPublicKeyPoint
	}

	blsPoint, ok := pubKeyPoint.GetUnderlyingObj().(*bls.G2)
	if !ok {
		return nil, crypto.ErrInvalidPoint
	}
	blsPointString := blsPoint.GetString(16)
	concatPkWithPKs := append([]byte(blsPointString), concatPubKeys...)

	// H1(pk_i, {pk_1, ..., pk_n})
	h := hasher.Compute(string(concatPkWithPKs))
	// accepted length 32, copy the hasherOutputSize bytes and have rest 0
	h32 := make([]byte, 32)
	copy(h32[hasherOutputSize:], h)

	return h32, nil
}

// IsInterfaceNil returns true if there is no value under the interface
func (bms *BlsMultiSigner) IsInterfaceNil() bool {
	return bms == nil
}
