use crate::bls12_381::swcurve::G1Point;
use crate::bls12_381::g2::G2Point;
use crate::bls12_381::pairing::pair;

// Verifica e(sig, G1_gen) == e(H(m), pk)
pub fn verify_bls_signature(
    signature: G2Point,
    public_key: G1Point,
    message_hash: G2Point
) {
    let lhs = pair(signature, G1Point::generator());
    let rhs = pair(message_hash, public_key);
    assert(lhs.eq(rhs));
}

// ======================== TESTS (disabled - too expensive for nargo test) ========================
// Run via: nargo execute

// #[test]
fn test_verify_bls_signature_valid() {
    println(">> test_verify_bls_signature_valid");
    let sig = G2Point::generator();
    let pk  = G1Point::generator();
    let msg = G2Point::generator();
    verify_bls_signature(sig, pk, msg);
}

// #[test(should_fail)]
fn test_verify_bls_signature_invalid() {
    println(">> test_verify_bls_signature_invalid");
    let sig = G2Point::zero();
    let pk  = G1Point::generator();
    let msg = G2Point::generator();
    verify_bls_signature(sig, pk, msg);
}
