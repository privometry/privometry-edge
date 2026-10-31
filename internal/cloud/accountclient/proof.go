package accountclient

import (
	"crypto/ed25519"
	"encoding/json"

	cloudaccount "github.com/privometry/privometry-edge/internal/cloud/account"
	"github.com/privometry/privometry-edge/internal/signing"
)

// ProofPayloadType is the DSSE payload type of a CLI key's proof.
const ProofPayloadType = "application/vnd.privometry.account-proof+json"

// SignProof signs an AccountProof as a DSSE envelope over PAE, the way
// Privometry signs its artifacts. keyID is the key's thumbprint when
// registering and its credential ID when signing in.
func SignProof(priv ed25519.PrivateKey, keyID string, p cloudaccount.AccountProof) (*cloudaccount.Proof, error) {
	payload, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	env := signing.Sign(ProofPayloadType, payload, keyID, priv)
	return &cloudaccount.Proof{PayloadType: env.PayloadType, Payload: env.Payload,
		Signatures: []cloudaccount.ProofSignature{{KeyID: env.Signatures[0].KeyID, Sig: env.Signatures[0].Sig}}}, nil
}
