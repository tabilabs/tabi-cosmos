package tx

import (
	"fmt"
	"testing"

	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	"github.com/cosmos/cosmos-sdk/crypto/types/multisig"
	txtypes "github.com/cosmos/cosmos-sdk/types/tx"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	"github.com/stretchr/testify/require"
)

func TestMultisigStructureDecode(t *testing.T) {
	single := &txtypes.ModeInfo{Sum: &txtypes.ModeInfo_Single_{Single: &txtypes.ModeInfo_Single{Mode: signing.SignMode_SIGN_MODE_DIRECT}}}
	for _, count := range []int{0, 2} {
		t.Run(fmt.Sprintf("%d signatures", count), func(t *testing.T) {
			mode := &txtypes.ModeInfo{Sum: &txtypes.ModeInfo_Multi_{Multi: &txtypes.ModeInfo_Multi{
				Bitarray: cryptotypes.NewCompactBitArray(1), ModeInfos: []*txtypes.ModeInfo{single},
			}}}
			raw, err := (&cryptotypes.MultiSignature{Signatures: make([][]byte, count)}).Marshal()
			require.NoError(t, err)
			require.NotPanics(t, func() {
				_, err := ModeInfoAndSigToSignatureData(mode, raw)
				require.Error(t, err)
			})
		})
	}
	for _, mode := range []*txtypes.ModeInfo{nil, {}, {Sum: &txtypes.ModeInfo_Single_{}}, {Sum: &txtypes.ModeInfo_Multi_{}}} {
		require.NotPanics(t, func() {
			_, err := ModeInfoAndSigToSignatureData(mode, nil)
			require.Error(t, err)
		})
	}
}

func TestMultisigStructureRoundTrip(t *testing.T) {
	leaf := &signing.SingleSignatureData{SignMode: signing.SignMode_SIGN_MODE_DIRECT, Signature: []byte("signature")}
	inner := multisig.NewMultisig(8)
	multisig.AddSignature(inner, leaf, 7)
	outer := multisig.NewMultisig(2)
	multisig.AddSignature(outer, leaf, 0)
	multisig.AddSignature(outer, inner, 1)
	mode, raw := SignatureDataToModeInfoAndSig(outer)
	got, err := ModeInfoAndSigToSignatureData(mode, raw)
	require.NoError(t, err)
	require.Equal(t, outer, got)
}

func TestMultisigStructureSignerCount(t *testing.T) {
	builder := newBuilder()
	builder.tx.AuthInfo.SignerInfos = []*txtypes.SignerInfo{{ModeInfo: &txtypes.ModeInfo{Sum: &txtypes.ModeInfo_Single_{Single: &txtypes.ModeInfo_Single{}}}}}
	require.NotPanics(t, func() {
		_, err := builder.GetSignaturesV2()
		require.Error(t, err)
	})
}

func TestMultisigStructureSimulation(t *testing.T) {
	builder := newBuilder()
	builder.tx.AuthInfo.SignerInfos = []*txtypes.SignerInfo{{}}
	builder.tx.Signatures = [][]byte{nil}
	sigs, err := builder.GetSignaturesV2()
	require.NoError(t, err)
	require.Len(t, sigs, 1)
	require.Nil(t, sigs[0].Data)
}
