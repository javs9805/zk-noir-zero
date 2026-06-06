fn rotr(x: u32, n: u32) -> u32 {
    (x >> n) | (x << (32 - n))
}

// u32 addition via u64 to avoid overflow
fn a32(a: u32, b: u32) -> u32 {
    (((a as u64) + (b as u64)) & 0xFFFFFFFF) as u32
}

fn sha256_compress(state: [u32; 8], block: [u8; 64]) -> [u32; 8] {
    let k: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];

    let mut w: [u32; 64] = [0; 64];
    for i in 0..16 {
        w[i] = ((block[i*4] as u32) << 24)
             | ((block[i*4+1] as u32) << 16)
             | ((block[i*4+2] as u32) << 8)
             | (block[i*4+3] as u32);
    }
    for i in 16..64 {
        let s0 = rotr(w[i-15], 7) ^ rotr(w[i-15], 18) ^ (w[i-15] >> 3);
        let s1 = rotr(w[i-2], 17) ^ rotr(w[i-2], 19) ^ (w[i-2] >> 10);
        let tmp = (w[i-16] as u64) + (s0 as u64) + (w[i-7] as u64) + (s1 as u64);
        w[i] = (tmp & 0xFFFFFFFF) as u32;
    }

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];

    for i in 0..64 {
        let s1e = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        let ch  = (e & f) ^ ((e ^ 0xFFFFFFFF) & g);
        let t1  = ((h as u64) + (s1e as u64) + (ch as u64) + (k[i] as u64) + (w[i] as u64) & 0xFFFFFFFF) as u32;
        let s0a = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2  = (((s0a as u64) + (maj as u64)) & 0xFFFFFFFF) as u32;
        h = g;
        g = f;
        f = e;
        e = (((d as u64) + (t1 as u64)) & 0xFFFFFFFF) as u32;
        d = c;
        c = b;
        b = a;
        a = (((t1 as u64) + (t2 as u64)) & 0xFFFFFFFF) as u32;
    }

    [
        a32(state[0], a), a32(state[1], b), a32(state[2], c), a32(state[3], d),
        a32(state[4], e), a32(state[5], f), a32(state[6], g), a32(state[7], h)
    ]
}

fn sha256_64(input: [u8; 64]) -> [u8; 32] {
    let init: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ];

    // Block 1: los 64 bytes de entrada
    let s1 = sha256_compress(init, input);

    // Block 2: padding 0x80 + 55 zeros + length 512 bits = 0x0000000000000200
    let mut pad: [u8; 64] = [0; 64];
    pad[0]  = 0x80;
    pad[62] = 0x02;
    pad[63] = 0x00;

    let s2 = sha256_compress(s1, pad);

    let mut out: [u8; 32] = [0; 32];
    for i in 0..8 {
        out[i*4]   = ((s2[i] >> 24) & 0xFF) as u8;
        out[i*4+1] = ((s2[i] >> 16) & 0xFF) as u8;
        out[i*4+2] = ((s2[i] >> 8)  & 0xFF) as u8;
        out[i*4+3] = (s2[i] & 0xFF) as u8;
    }
    out
}

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
        x: ::noir_bigint_bls12_381::prime_field::PrimeField::from_bytes(pubkey_x),
        y: ::noir_bigint_bls12_381::prime_field::PrimeField::from_bytes(pubkey_y),
        infinity: false,
    };

    let sig = ::noir_bls_signature::bls12_381::g2::G2Point {
        x: ::noir_bls_signature::bls12_381::fp2::Fp2 {
            c0: ::noir_bigint_bls12_381::prime_field::PrimeField::from_bytes(sig_x_c0),
            c1: ::noir_bigint_bls12_381::prime_field::PrimeField::from_bytes(sig_x_c1),
        },
        y: ::noir_bls_signature::bls12_381::fp2::Fp2 {
            c0: ::noir_bigint_bls12_381::prime_field::PrimeField::from_bytes(sig_y_c0),
            c1: ::noir_bigint_bls12_381::prime_field::PrimeField::from_bytes(sig_y_c1),
        },
        infinity: false,
    };

    let msg = ::noir_bls_signature::bls12_381::g2::G2Point {
        x: ::noir_bls_signature::bls12_381::fp2::Fp2 {
            c0: ::noir_bigint_bls12_381::prime_field::PrimeField::from_bytes(msg_x_c0),
            c1: ::noir_bigint_bls12_381::prime_field::PrimeField::from_bytes(msg_x_c1),
        },
        y: ::noir_bls_signature::bls12_381::fp2::Fp2 {
            c0: ::noir_bigint_bls12_381::prime_field::PrimeField::from_bytes(msg_y_c0),
            c1: ::noir_bigint_bls12_381::prime_field::PrimeField::from_bytes(msg_y_c1),
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
    let h = sha256_64(preimage);

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

// RED: SHA-256 de 64 ceros, primer byte debe ser 0xf5
#[test]
fn test_sha256_64_zero_vector() {
    let input: [u8; 64] = [0; 64];
    let result = sha256_64(input);
    assert(result[0] == 0xf5);
    assert(result[1] == 0xa5);
}

// RED: compute_domain con fork=[0;4], gvr=[0;32]
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

// stub RED compute_signing_root
fn compute_signing_root(parent_root: [u8; 32], domain: [u8; 32]) -> [u8; 32] {
    let mut preimage: [u8; 64] = [0; 64];
    for i in 0..32 {
        preimage[i] = parent_root[i];
    }
    for i in 0..32 {
        preimage[32 + i] = domain[i];
    }
    sha256_64(preimage)
}

// RED: signing_root = SHA256([0;64]) => primer byte 0xf5
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

// RED: main con expected_signing_root incorrecto debe fallar
#[test(should_fail)]
fn test_main_wrong_signing_root() {
    let zeros48: [u8; 48] = [0; 48];
    let zeros32: [u8; 32] = [0; 32];
    let zeros4: [u8; 4]   = [0; 4];
    // expected_signing_root incorrecto: [1, 0, ...]
    let mut wrong: [u8; 32] = [0; 32];
    wrong[0] = 1;
    main(
        zeros48, zeros48,
        zeros48, zeros48, zeros48, zeros48,
        zeros48, zeros48, zeros48, zeros48,
        zeros32, zeros4, zeros32,
        wrong
    );
}

// RED: main con signing_root correcto debe pasar
// signing_root = SHA256(parent_root=zeros32 || domain=compute_domain(zeros4,zeros32))
// compute_domain(zeros4,zeros32) = 0x07000000 || SHA256([0;64])[0..28]
// SHA256([0;64]) = f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b
// sk=1: pk=G1_gen, sig=G2_gen, msg=G2_gen => e(G2_gen, G1_gen)*e(neg(G2_gen), G1_gen) = 1
#[test]
fn test_main_correct_signing_root() {
    let zeros32: [u8; 32] = [0; 32];
    let zeros4: [u8; 4]   = [0; 4];

    // pk bytes from G1 generator
    let g1 = ::noir_bls_signature::bls12_381::swcurve::G1Point::generator();
    let pk_x = g1.x.to_bytes();
    let pk_y = g1.y.to_bytes();

    // sig and msg bytes from G2 generator (sk=1 => sig = msg = G2_gen)
    let g2 = ::noir_bls_signature::bls12_381::g2::G2Point::generator();
    let g2_x_c0 = g2.x.c0.to_bytes();
    let g2_x_c1 = g2.x.c1.to_bytes();
    let g2_y_c0 = g2.y.c0.to_bytes();
    let g2_y_c1 = g2.y.c1.to_bytes();

    // compute signing_root with zero inputs
    let domain = compute_domain(zeros4, zeros32);
    let sr = compute_signing_root(zeros32, domain);

    main(
        pk_x, pk_y,
        g2_x_c0, g2_x_c1, g2_y_c0, g2_y_c1,
        g2_x_c0, g2_x_c1, g2_y_c0, g2_y_c1,
        zeros32, zeros4, zeros32,
        sr
    );
}
