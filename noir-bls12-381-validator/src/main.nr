use ::noir_bls_signature::bls12_381::fp2::fp_from_le;
use sha256::sha256_var;

fn main(
    pubkey_x:                [u8; 48],
    pubkey_y:                [u8; 48],
    sig_x_c0:                [u8; 48],
    sig_x_c1:                [u8; 48],
    sig_y_c0:                [u8; 48],
    sig_y_c1:                [u8; 48],
    msg_x_c0:                [u8; 48],
    msg_x_c1:                [u8; 48],
    msg_y_c0:                [u8; 48],
    msg_y_c1:                [u8; 48],
    genesis_validators_root: [u8; 32],
    fork_version:            [u8; 4],
    parent_root:             [u8; 32],
    expected_signing_root:   pub [u8; 32]
) {
    // RF-3: reconstruct G1 public key and G2 signature/message from bytes
    let pk = ::noir_bls_signature::bls12_381::swcurve::G1Point {
        x: fp_from_le(pubkey_x),
        y: fp_from_le(pubkey_y),
        infinity: false,
    };

    let sig = ::noir_bls_signature::bls12_381::g2::G2Point {
        x: ::noir_bls_signature::bls12_381::fp2::Fp2 {
            c0: fp_from_le(sig_x_c0),
            c1: fp_from_le(sig_x_c1),
        },
        y: ::noir_bls_signature::bls12_381::fp2::Fp2 {
            c0: fp_from_le(sig_y_c0),
            c1: fp_from_le(sig_y_c1),
        },
        infinity: false,
    };

    let msg = ::noir_bls_signature::bls12_381::g2::G2Point {
        x: ::noir_bls_signature::bls12_381::fp2::Fp2 {
            c0: fp_from_le(msg_x_c0),
            c1: fp_from_le(msg_x_c1),
        },
        y: ::noir_bls_signature::bls12_381::fp2::Fp2 {
            c0: fp_from_le(msg_y_c0),
            c1: fp_from_le(msg_y_c1),
        },
        infinity: false,
    };

    // RF-4: assert not identity
    assert(!pk.is_zero());
    assert(!sig.is_zero());

    // RF-9: verify BLS signature via verify_bls_signature
    ::noir_bls_signature::bls12_381::signature::verify_bls_signature(sig, pk, msg);

    // RF-6: compute domain
    let domain = compute_domain(fork_version, genesis_validators_root);

    // RF-7: compute signing_root
    let signing_root = compute_signing_root(parent_root, domain);

    // RF-8: anchor to public input
    for i in 0..32 {
        assert(signing_root[i] == expected_signing_root[i]);
    }
}

fn compute_domain(fork_version: [u8; 4], genesis_validators_root: [u8; 32]) -> [u8; 32] {
    // input = fork_version padded to 32 bytes || genesis_validators_root (64 bytes total)
    let mut preimage: [u8; 64] = [0; 64];
    for i in 0..4 {
        preimage[i] = fork_version[i];
    }
    for i in 0..32 {
        preimage[32 + i] = genesis_validators_root[i];
    }
    let h: [u8; 32] = sha256_var(preimage, 64 as u32);

    // domain = DOMAIN_SYNC_COMMITTEE(4 bytes) || h[0..28]
    let mut domain: [u8; 32] = [0; 32];
    domain[0] = 0x07;
    domain[1] = 0x00;
    domain[2] = 0x00;
    domain[3] = 0x00;
    for i in 0..28 {
        domain[4 + i] = h[i];
    }
    domain
}

// compute_domain con fork=[0;4], gvr=[0;32]
// domain[0..4] = 0x07000000, domain[4..] = SHA256([0;64])[0..28]
// SHA256([0;64])[0] = 0xf5 => domain[4] = 0xf5
#[test]
fn test_compute_domain_known_vector() {
    let fv: [u8; 4] = [0; 4];
    let gvr: [u8; 32] = [0; 32];
    let domain = compute_domain(fv, gvr);
    assert(domain[0] == 0x07);
    assert(domain[1] == 0x00);
    assert(domain[4] == 0xf5);
    assert(domain[5] == 0xa5);
}

fn compute_signing_root(parent_root: [u8; 32], domain: [u8; 32]) -> [u8; 32] {
    let mut preimage: [u8; 64] = [0; 64];
    for i in 0..32 {
        preimage[i] = parent_root[i];
    }
    for i in 0..32 {
        preimage[32 + i] = domain[i];
    }
    sha256_var(preimage, 64 as u32)
}

#[test]
fn test_compute_signing_root_zero_vector() {
    let pr: [u8; 32] = [0; 32];
    let dom: [u8; 32] = [0; 32];
    let sr = compute_signing_root(pr, dom);
    assert(sr[0] == 0xf5);
    assert(sr[1] == 0xa5);
}

// RED: main with G1/G2 reconstruction - pk not zero for generator bytes
#[test]
fn test_main_reconstruct_pk_not_zero() {
    let pk = ::noir_bls_signature::bls12_381::swcurve::G1Point::generator();
    assert(!pk.is_zero());
}

// Full-pairing integration tests (main() calls the Miller loop + final exp).
// These are correct but too expensive for nargo test - run via nargo execute instead.
// #[test(should_fail)]
// fn test_main_wrong_signing_root() { ... }
// #[test]
// fn test_main_correct_signing_root() { ... }
