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

// ======================== TESTS GREEN ========================

#[test]
fn test_verify_bls_signature_valid() {
    println(">> test_verify_bls_signature_valid");
    // sk=1: sig=G2_gen, pk=G1_gen, msg=G2_gen
    // e(G2_gen, G1_gen) == e(G2_gen, G1_gen) trivialmente
    let sig = G2Point::generator();
    let pk  = G1Point::generator();
    let msg = G2Point::generator();
    verify_bls_signature(sig, pk, msg);
    println(">> PASS: firma valida con sk=1");
}

#[test(should_fail)]
fn test_verify_bls_signature_invalid() {
    println(">> test_verify_bls_signature_invalid");
    // sig incorrecto: usar zero en vez de G2_gen
    let sig = G2Point::zero();
    let pk  = G1Point::generator();
    let msg = G2Point::generator();
    verify_bls_signature(sig, pk, msg);
}
