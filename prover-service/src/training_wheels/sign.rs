use aptos_crypto::{
    ed25519::{Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature},
    CryptoMaterialError, SigningKey,
};
use aptos_types::{
    keyless::{Groth16Proof, Groth16ProofAndStatement},
    transaction::authenticator::{EphemeralPublicKey, EphemeralSignature},
};
use keyless_common::PoseidonHash;

use crate::api::ProverServiceResponse;

pub fn sign(
    private_key: &Ed25519PrivateKey,
    proof: Groth16Proof,
    public_inputs_hash: PoseidonHash,
) -> Result<Ed25519Signature, CryptoMaterialError> {
    let message_to_sign: Groth16ProofAndStatement = Groth16ProofAndStatement {
        proof,
        public_inputs_hash,
    };

    private_key.sign(&message_to_sign)
}

// For debugging.
pub fn verify(
    response: &ProverServiceResponse,
    pub_key: &Ed25519PublicKey,
) -> Result<(), anyhow::Error> {
    match response {
        ProverServiceResponse::Error { .. } => {
            panic!("Should never call this fn on a response of type ProverServerResponse::Error")
        }
        ProverServiceResponse::Success {
            proof,
            public_inputs_hash,
            training_wheels_signature,
        } => {
            let ephem_tw_sig = EphemeralSignature::try_from(training_wheels_signature.as_slice())?;
            ephem_tw_sig.verify(
                &Groth16ProofAndStatement {
                    proof: *proof,
                    public_inputs_hash: *public_inputs_hash,
                },
                &EphemeralPublicKey::ed25519(pub_key.clone()),
            )
        }
    }
}
