// Test backward compatibility of proofs generated before the `ad` parameter
// was added to `Suite::nonce`.
//
// The constants below were generated with the old nonce (without `ad`).
// If the new code can still verify them, then old proofs remain valid.

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_vrf::suites::bandersnatch::{self, *};

const SEED: &[u8] = b"backward-compat-test-seed";
const INPUT_DATA: &[u8] = b"backward-compat-test-input";
const AD: &[u8] = b"backward-compat-test-ad";

fn serialize<T: CanonicalSerialize>(val: &T) -> Vec<u8> {
    let mut buf = Vec::new();
    val.serialize_compressed(&mut buf).unwrap();
    buf
}

fn secret_and_input() -> (Secret, Public, Input, Output) {
    let secret = Secret::from_seed(SEED);
    let public = secret.public();
    let input = Input::new(INPUT_DATA).unwrap();
    let output = secret.output(input);
    (secret, public, input, output)
}

#[cfg(test)]
mod generate {
    use super::*;

    // Run with: cargo test --test backward_compat generate -- --ignored --nocapture
    // to print the proof bytes for embedding.

    #[test]
    #[ignore]
    fn print_ietf_proof() {
        let (secret, _public, input, output) = secret_and_input();
        use ark_vrf::ietf::Prover;
        let proof = secret.prove(input, output, AD);
        let bytes = serialize(&proof);
        println!("IETF proof ({} bytes): {:?}", bytes.len(), bytes);
    }

    #[test]
    #[ignore]
    fn print_pedersen_proof() {
        let (secret, _public, input, output) = secret_and_input();
        use ark_vrf::pedersen::Prover;
        let (proof, _blinding) = secret.prove(input, output, AD);
        let bytes = serialize(&proof);
        println!("Pedersen proof ({} bytes): {:?}", bytes.len(), bytes);
    }
}

// Generated with the old code (nonce without `ad` parameter).
const IETF_PROOF_BYTES: &[u8] = &[
    2, 167, 216, 180, 204, 175, 208, 16, 30, 96, 42, 126, 64, 110, 133, 15, 200, 92, 39, 162, 28,
    126, 68, 235, 109, 41, 170, 166, 149, 198, 201, 22, 180, 249, 65, 193, 243, 144, 234, 51, 184,
    188, 177, 31, 14, 47, 230, 228, 48, 194, 64, 199, 199, 90, 22, 38, 32, 157, 203, 243, 24, 170,
    120, 5,
];
const PEDERSEN_PROOF_BYTES: &[u8] = &[
    224, 34, 95, 84, 42, 59, 220, 195, 67, 14, 108, 176, 237, 6, 255, 174, 90, 100, 232, 107, 101,
    56, 191, 231, 236, 34, 11, 8, 19, 239, 110, 100, 85, 249, 235, 5, 45, 177, 33, 32, 106, 190,
    159, 13, 163, 89, 58, 179, 148, 106, 166, 79, 246, 173, 70, 240, 220, 170, 169, 99, 26, 16,
    148, 44, 212, 121, 250, 1, 148, 81, 129, 126, 18, 218, 236, 73, 48, 100, 107, 81, 66, 248, 93,
    251, 49, 106, 30, 193, 124, 176, 204, 174, 144, 234, 58, 224, 99, 110, 81, 67, 25, 221, 182,
    112, 136, 199, 79, 21, 16, 108, 219, 126, 66, 151, 73, 45, 228, 81, 179, 249, 67, 104, 49, 72,
    255, 206, 22, 15, 129, 123, 61, 102, 211, 229, 174, 174, 113, 215, 219, 168, 99, 254, 244, 163,
    37, 195, 212, 148, 245, 192, 40, 223, 82, 47, 224, 254, 214, 147, 233, 27,
];

#[test]
fn ietf_backward_compat() {
    if IETF_PROOF_BYTES.is_empty() {
        panic!("IETF_PROOF_BYTES not yet populated - run the generators first");
    }
    let (_secret, public, input, output) = secret_and_input();
    let proof =
        ark_vrf::ietf::Proof::<BandersnatchSha512Ell2>::deserialize_compressed(IETF_PROOF_BYTES)
            .expect("Failed to deserialize IETF proof");
    use ark_vrf::ietf::Verifier;
    public
        .verify(input, output, AD, &proof)
        .expect("IETF proof from old code should still verify");
}

#[test]
fn pedersen_backward_compat() {
    if PEDERSEN_PROOF_BYTES.is_empty() {
        panic!("PEDERSEN_PROOF_BYTES not yet populated - run the generators first");
    }
    let (_secret, _public, input, output) = secret_and_input();
    let proof = ark_vrf::pedersen::Proof::<BandersnatchSha512Ell2>::deserialize_compressed(
        PEDERSEN_PROOF_BYTES,
    )
    .expect("Failed to deserialize Pedersen proof");
    use ark_vrf::pedersen::Verifier;
    bandersnatch::Public::verify(input, output, AD, &proof)
        .expect("Pedersen proof from old code should still verify");
}
