package multisig_test

import (
	"testing"

	kmultisig "github.com/cosmos/cosmos-sdk/crypto/keys/multisig"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	"github.com/cosmos/cosmos-sdk/crypto/types/multisig"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	"github.com/stretchr/testify/require"
)

func TestMultisigStructureRejectsSingleForNestedKey(t *testing.T) {
	key := secp256k1.GenPrivKey().PubKey()
	inner := kmultisig.NewLegacyAminoPubKey(1, []cryptotypes.PubKey{key})
	outer := kmultisig.NewLegacyAminoPubKey(1, []cryptotypes.PubKey{inner})
	sig := multisig.NewMultisig(1)
	multisig.AddSignature(sig, &signing.SingleSignatureData{Signature: []byte{1}}, 0)
	require.NotPanics(t, func() {
		err := outer.VerifyMultisignature(func(signing.SignMode) ([]byte, error) { return []byte("message"), nil }, sig)
		require.Error(t, err)
	})
}
