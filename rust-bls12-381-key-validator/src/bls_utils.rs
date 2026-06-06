use bls12_381_plus::{G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, multi_miller_loop};
use group::{Curve, Group};
use subtle::CtOption;

const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

pub fn hash_to_g2(msg: &[u8]) -> G2Affine {
    use bls12_381_plus::elliptic_curve::hash2curve::ExpandMsgXmd;
    G2Projective::hash::<ExpandMsgXmd<sha2::Sha256>>(msg, DST).to_affine()
}

/// e(sig, G1_gen) == e(msg, pk)  =>  e(-G1_gen, sig) * e(pk, msg) == 1
pub fn verify_bls(sig: G2Affine, pk: G1Affine, msg: G2Affine) -> bool {
    let neg_gen = -G1Affine::generator();
    let result = multi_miller_loop(&[
        (&neg_gen, &G2Prepared::from(sig)),
        (&pk, &G2Prepared::from(msg)),
    ])
    .final_exponentiation();
    bool::from(result.is_identity())
}

/// Suma G1 afines de una slice de claves comprimidas (48 bytes BE cada una).
pub fn aggregate_g1(compressed_keys: &[[u8; 48]]) -> Option<G1Affine> {
    let mut acc = G1Projective::identity();
    for key in compressed_keys {
        let opt: CtOption<G1Affine> = G1Affine::from_compressed(key);
        if bool::from(opt.is_none()) {
            return None;
        }
        acc = acc + G1Projective::from(opt.unwrap());
    }
    if bool::from(acc.is_identity()) {
        None
    } else {
        Some(acc.to_affine())
    }
}

/// Descomprime firma G2 de 96 bytes (compressed, big-endian).
pub fn decompress_g2(compressed: &[u8; 96]) -> Option<G2Affine> {
    let opt = G2Affine::from_compressed(compressed);
    if bool::from(opt.is_none()) {
        None
    } else {
        Some(opt.unwrap())
    }
}

/// Extrae coords G1 → (x_le: [u8;48], y_le: [u8;48])
pub fn g1_to_le_coords(pt: &G1Affine) -> ([u8; 48], [u8; 48]) {
    let raw = pt.to_uncompressed();
    let mut x = [0u8; 48];
    let mut y = [0u8; 48];
    x.copy_from_slice(&raw[0..48]);
    y.copy_from_slice(&raw[48..96]);
    x.reverse();
    y.reverse();
    (x, y)
}

/// Extrae coords G2 → (x_c0_le, x_c1_le, y_c0_le, y_c1_le) cada [u8;48]
/// to_uncompressed layout: [x_c1_BE | x_c0_BE | y_c1_BE | y_c0_BE]
pub fn g2_to_le_coords(pt: &G2Affine) -> ([u8; 48], [u8; 48], [u8; 48], [u8; 48]) {
    let raw = pt.to_uncompressed();
    let mut x_c1 = [0u8; 48];
    let mut x_c0 = [0u8; 48];
    let mut y_c1 = [0u8; 48];
    let mut y_c0 = [0u8; 48];
    x_c1.copy_from_slice(&raw[0..48]);
    x_c0.copy_from_slice(&raw[48..96]);
    y_c1.copy_from_slice(&raw[96..144]);
    y_c0.copy_from_slice(&raw[144..192]);
    x_c1.reverse();
    x_c0.reverse();
    y_c1.reverse();
    y_c0.reverse();
    (x_c0, x_c1, y_c0, y_c1)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RED: verificar que e(G2_gen, G1_gen) == e(G2_gen, G1_gen) — siempre true
    #[test]
    fn test_verify_bls_trivial_identity() {
        // sk=1 => pk=G1_gen, sig=G2_gen, msg=G2_gen (misma relacion que en el circuito)
        let pk = G1Affine::generator();
        let sig = G2Affine::generator();
        let msg = G2Affine::generator();
        assert!(verify_bls(sig, pk, msg));
    }

    #[test]
    fn test_verify_bls_wrong_msg_fails() {
        let pk = G1Affine::generator();
        let sig = G2Affine::generator();
        let msg = hash_to_g2(b"wrong message");
        assert!(!verify_bls(sig, pk, msg));
    }

    #[test]
    fn test_g1_to_le_coords_generator() {
        let pt = G1Affine::generator();
        let (x, y) = g1_to_le_coords(&pt);
        // Primer byte BE del generador G1_x es 0x17 => ultimo byte LE debe ser 0x17
        assert_eq!(x[47], 0x17);
        assert_ne!(x, [0u8; 48]);
        assert_ne!(y, [0u8; 48]);
    }

    #[test]
    fn test_g2_to_le_coords_generator() {
        let pt = G2Affine::generator();
        let (x_c0, x_c1, y_c0, y_c1) = g2_to_le_coords(&pt);
        assert_ne!(x_c0, [0u8; 48]);
        assert_ne!(x_c1, [0u8; 48]);
        assert_ne!(y_c0, [0u8; 48]);
        assert_ne!(y_c1, [0u8; 48]);
    }

    #[test]
    fn test_aggregate_g1_single_generator() {
        let gen_compressed = G1Affine::generator().to_compressed();
        let agg = aggregate_g1(&[gen_compressed]).unwrap();
        assert_eq!(agg, G1Affine::generator());
    }
}
