package ante

import (
	"testing"

	kmultisig "github.com/cosmos/cosmos-sdk/crypto/keys/multisig"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	"github.com/cosmos/cosmos-sdk/crypto/types/multisig"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	"github.com/cosmos/cosmos-sdk/x/auth/types"
	"github.com/stretchr/testify/require"
)

func TestMultisigStructureGas(t *testing.T) {
	leaf := &signing.SingleSignatureData{Signature: []byte{1}}
	key := secp256k1.GenPrivKey().PubKey()
	pubkey := kmultisig.NewLegacyAminoPubKey(1, []cryptotypes.PubKey{key, key})
	for _, tc := range []struct {
		name string
		sig  *signing.MultiSignatureData
	}{
		{"nil", nil},
		{"nil bit array", &signing.MultiSignatureData{Signatures: []signing.SignatureData{leaf}}},
		{"invalid extra bits", &signing.MultiSignatureData{BitArray: &cryptotypes.CompactBitArray{ExtraBitsStored: 9, Elems: []byte{0xff}}}},
		{"trailing signatures", &signing.MultiSignatureData{BitArray: &cryptotypes.CompactBitArray{ExtraBitsStored: 2, Elems: []byte{0x80}}, Signatures: []signing.SignatureData{leaf, leaf}}},
		{"missing signature", &signing.MultiSignatureData{BitArray: &cryptotypes.CompactBitArray{ExtraBitsStored: 2, Elems: []byte{0xc0}}, Signatures: []signing.SignatureData{leaf}}},
		{"wrong key count", &signing.MultiSignatureData{BitArray: &cryptotypes.CompactBitArray{ExtraBitsStored: 3, Elems: []byte{0x80}}, Signatures: []signing.SignatureData{leaf}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.NotPanics(t, func() {
				err := ConsumeMultisignatureVerificationGas(sdk.NewInfiniteGasMeter(1, 1), tc.sig, pubkey, types.DefaultParams(), 0)
				require.Error(t, err)
			})
		})
	}
	innerKey := kmultisig.NewLegacyAminoPubKey(2, []cryptotypes.PubKey{key, key})
	outerKey := kmultisig.NewLegacyAminoPubKey(2, []cryptotypes.PubKey{key, innerKey})
	inner := multisig.NewMultisig(2)
	multisig.AddSignature(inner, leaf, 0)
	multisig.AddSignature(inner, leaf, 1)
	outer := multisig.NewMultisig(2)
	multisig.AddSignature(outer, leaf, 0)
	multisig.AddSignature(outer, inner, 1)
	meter := sdk.NewInfiniteGasMeter(1, 1)
	params := types.DefaultParams()
	require.NoError(t, ConsumeMultisignatureVerificationGas(meter, outer, outerKey, params, 0))
	require.Equal(t, 3*params.GetSigVerifyCostSecp256k1(), meter.GasConsumed())
}

func TestMultisigStructureEvents(t *testing.T) {
	leaf := &signing.SingleSignatureData{Signature: []byte("leaf")}
	inner := multisig.NewMultisig(2)
	multisig.AddSignature(inner, leaf, 0)
	outer := multisig.NewMultisig(2)
	multisig.AddSignature(outer, leaf, 0)
	multisig.AddSignature(outer, inner, 1)
	innerRaw, err := (&cryptotypes.MultiSignature{Signatures: [][]byte{leaf.Signature}}).Marshal()
	require.NoError(t, err)
	rootRaw, err := (&cryptotypes.MultiSignature{Signatures: [][]byte{leaf.Signature, leaf.Signature, innerRaw}}).Marshal()
	require.NoError(t, err)
	got, err := signatureDataToBz(outer)
	require.NoError(t, err)
	require.Equal(t, [][]byte{leaf.Signature, leaf.Signature, innerRaw, rootRaw}, got)
	inner.Signatures = append(inner.Signatures, leaf)
	_, err = signatureDataToBz(outer)
	require.Error(t, err)
}
