use ::bignum::BigNum;
use crate::bls12_381::fp2::{BLS12_381Fq, Fp2, fp_from_le};
use crate::bls12_381::fp6::Fp6;
use crate::bls12_381::fp12::Fp12;
use crate::bls12_381::swcurve::G1Point;
use crate::bls12_381::g2::G2Point;

// ---- Frobenius helpers ----

// frobenius_map on Fp2: conjugate (c0, -c1)
fn fp2_frobenius(a: Fp2) -> Fp2 {
    Fp2 { c0: a.c0, c1: -a.c1 }
}

// Fp2 scalar from LE bytes (c0 only, c1=0)
fn fp2_real(bytes: [u8; 48]) -> Fp2 {
    Fp2 { c0: fp_from_le(bytes), c1: BLS12_381Fq::zero() }
}

// Fp2 imaginary from LE bytes (c0=0, c1 only)
fn fp2_imag(bytes: [u8; 48]) -> Fp2 {
    Fp2 { c0: BLS12_381Fq::zero(), c1: fp_from_le(bytes) }
}

// Frobenius on Fp6 (power 1)
fn fp6_frobenius(a: Fp6) -> Fp6 {
    // FROBENIUS_COEFF_FP6_C1[1] = (0, GAMMA_C1_1) - pure imaginary
    let c1_1 = fp2_imag([
        0xac, 0xaa, 0x00, 0x00, 0x00, 0x00, 0xfd, 0x8b,
        0xfd, 0xff, 0x49, 0x4f, 0xeb, 0x27, 0x94, 0x40,
        0x9b, 0x5f, 0xb8, 0x0f, 0x65, 0x29, 0x7d, 0x89,
        0xd4, 0x9a, 0x75, 0x89, 0x7d, 0x85, 0x0d, 0xaa,
        0x85, 0xde, 0xd4, 0x63, 0x86, 0x40, 0x02, 0xec,
        0x99, 0xe6, 0x7f, 0x39, 0xea, 0x11, 0x01, 0x1a
    ]);
    // FROBENIUS_COEFF_FP6_C2[1]
    let c2_1 = fp2_real([
        0xad, 0xaa, 0x00, 0x00, 0x00, 0x00, 0xfd, 0x8b,
        0xfd, 0xff, 0x49, 0x4f, 0xeb, 0x27, 0x94, 0x40,
        0x9b, 0x5f, 0xb8, 0x0f, 0x65, 0x29, 0x7d, 0x89,
        0xd4, 0x9a, 0x75, 0x89, 0x7d, 0x85, 0x0d, 0xaa,
        0x85, 0xde, 0xd4, 0x63, 0x86, 0x40, 0x02, 0xec,
        0x99, 0xe6, 0x7f, 0x39, 0xea, 0x11, 0x01, 0x1a
    ]);
    Fp6 {
        c0: fp2_frobenius(a.c0),
        c1: fp2_frobenius(a.c1).mul(c1_1),
        c2: fp2_frobenius(a.c2).mul(c2_1),
    }
}

// Frobenius on Fp6 (power 2)
fn fp6_frobenius2(a: Fp6) -> Fp6 {
    let c1_2 = fp2_real([
        0xfe, 0xff, 0xfe, 0xff, 0xff, 0xff, 0x01, 0x2e,
        0x02, 0x00, 0x0a, 0x62, 0x13, 0xd8, 0x17, 0xde,
        0x88, 0x96, 0xf8, 0xe6, 0x3b, 0xa9, 0xb3, 0xdd,
        0xea, 0x77, 0x0f, 0x6a, 0x07, 0xc6, 0x69, 0xba,
        0x51, 0xce, 0x76, 0xdf, 0x2f, 0x67, 0x19, 0x5f,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ]);
    let c2_2 = fp2_real([
        0xac, 0xaa, 0x00, 0x00, 0x00, 0x00, 0xfd, 0x8b,
        0xfd, 0xff, 0x49, 0x4f, 0xeb, 0x27, 0x94, 0x40,
        0x9b, 0x5f, 0xb8, 0x0f, 0x65, 0x29, 0x7d, 0x89,
        0xd4, 0x9a, 0x75, 0x89, 0x7d, 0x85, 0x0d, 0xaa,
        0x85, 0xde, 0xd4, 0x63, 0x86, 0x40, 0x02, 0xec,
        0x99, 0xe6, 0x7f, 0x39, 0xea, 0x11, 0x01, 0x1a
    ]);
    Fp6 {
        c0: a.c0,
        c1: a.c1.mul(c1_2),
        c2: a.c2.mul(c2_2),
    }
}

// Frobenius on Fp12 (power 1)
fn fp12_frobenius(f: Fp12) -> Fp12 {
    let w1 = Fp2 {
        c0: fp_from_le([
            0xb8, 0x5f, 0x23, 0x92, 0xed, 0x75, 0x07, 0x8d,
            0x3d, 0x81, 0xe7, 0x63, 0x3d, 0xa5, 0x7e, 0xf6,
            0xc4, 0xb9, 0xba, 0x84, 0xd7, 0x43, 0x24, 0x7b,
            0x4f, 0x5f, 0xbd, 0x3c, 0xfd, 0x03, 0xd6, 0x0f,
            0x1f, 0x0d, 0x2c, 0x20, 0xb4, 0xbe, 0x31, 0xc2,
            0x67, 0x06, 0xbb, 0x02, 0xbf, 0xd3, 0x04, 0x19
        ]),
        c1: fp_from_le([
            0xf3, 0x4a, 0xdc, 0x6d, 0x12, 0x8a, 0xf7, 0x2c,
            0xc2, 0x7e, 0x6c, 0x4d, 0xc1, 0x5a, 0x2d, 0x28,
            0x5f, 0x3c, 0xf6, 0x71, 0xc9, 0x8e, 0x0c, 0xec,
            0x6f, 0xb3, 0xc7, 0xb6, 0x87, 0x47, 0xa1, 0x54,
            0xb8, 0x9f, 0x1f, 0x23, 0x02, 0xe9, 0xe9, 0x88,
            0x32, 0xe0, 0xc4, 0x36, 0x2b, 0x3e, 0xfc, 0x00
        ]),
    };
    let c0 = fp6_frobenius(f.c0);
    let c1 = fp6_frobenius(f.c1);
    let c1_scaled = Fp6 {
        c0: c1.c0.mul(w1),
        c1: c1.c1.mul(w1),
        c2: c1.c2.mul(w1),
    };
    Fp12 { c0, c1: c1_scaled }
}

// Frobenius on Fp12 (power 2)
fn fp12_frobenius2(f: Fp12) -> Fp12 {
    let w2 = fp2_real([
        0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0x01, 0x2e,
        0x02, 0x00, 0x0a, 0x62, 0x13, 0xd8, 0x17, 0xde,
        0x88, 0x96, 0xf8, 0xe6, 0x3b, 0xa9, 0xb3, 0xdd,
        0xea, 0x77, 0x0f, 0x6a, 0x07, 0xc6, 0x69, 0xba,
        0x51, 0xce, 0x76, 0xdf, 0x2f, 0x67, 0x19, 0x5f,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ]);
    let c0 = fp6_frobenius2(f.c0);
    let c1_raw = fp6_frobenius2(f.c1);
    let c1_scaled = Fp6 {
        c0: c1_raw.c0.mul(w2),
        c1: c1_raw.c1.mul(w2),
        c2: c1_raw.c2.mul(w2),
    };
    Fp12 { c0, c1: c1_scaled }
}

// Frobenius on Fp12 (power 3)
fn fp12_frobenius3(f: Fp12) -> Fp12 {
    let w3 = Fp2 {
        c0: fp_from_le([
            0xa2, 0xde, 0x1b, 0x12, 0x04, 0x7b, 0xee, 0xf1,
            0x0a, 0xfa, 0x67, 0x3e, 0xcf, 0x66, 0x44, 0x30,
            0x5e, 0xb4, 0x1e, 0xf6, 0x89, 0x64, 0x39, 0xef,
            0x60, 0xcf, 0xb1, 0x30, 0xd9, 0xed, 0x3d, 0x1c,
            0xd9, 0x2c, 0x7a, 0xd7, 0x48, 0xc4, 0xe9, 0xe2,
            0x8e, 0xa6, 0x80, 0x01, 0xe6, 0x03, 0x52, 0x13
        ]),
        c1: fp_from_le([
            0x09, 0xcc, 0xe3, 0xed, 0xfb, 0x84, 0x10, 0xc8,
            0xf4, 0x05, 0xec, 0x72, 0x2f, 0x99, 0x67, 0xee,
            0xc5, 0x41, 0x92, 0x00, 0x17, 0x6e, 0xf7, 0x77,
            0x5e, 0x43, 0xd3, 0xc2, 0xab, 0x5d, 0x39, 0x48,
            0xfe, 0x7f, 0xd1, 0x6b, 0x6d, 0xe3, 0x31, 0x68,
            0x0b, 0x40, 0xff, 0x37, 0x04, 0x0e, 0xaf, 0x06
        ]),
    };
    let fp2_one_imag = Fp2 {
        c0: BLS12_381Fq::zero(),
        c1: BLS12_381Fq::one(),
    };
    let one_fp: BLS12_381Fq = BLS12_381Fq::one();
    let fp2_neg_one = Fp2 {
        c0: -one_fp,
        c1: BLS12_381Fq::zero(),
    };
    let fp6_c0 = Fp6 {
        c0: fp2_frobenius(f.c0.c0),
        c1: fp2_frobenius(f.c0.c1).mul(fp2_one_imag),
        c2: fp2_frobenius(f.c0.c2).mul(fp2_neg_one),
    };
    let fp6_c1_raw = Fp6 {
        c0: fp2_frobenius(f.c1.c0),
        c1: fp2_frobenius(f.c1.c1).mul(fp2_one_imag),
        c2: fp2_frobenius(f.c1.c2).mul(fp2_neg_one),
    };
    let fp6_c1_scaled = Fp6 {
        c0: fp6_c1_raw.c0.mul(w3),
        c1: fp6_c1_raw.c1.mul(w3),
        c2: fp6_c1_raw.c2.mul(w3),
    };
    Fp12 { c0: fp6_c0, c1: fp6_c1_scaled }
}


// ---- Cyclotomic square (Alg 5.5.4) ----
fn fp4_square(a: Fp2, b: Fp2) -> (Fp2, Fp2) {
    let t0 = a.mul(a);
    let t1 = b.mul(b);
    let t2 = Fp2 { c0: t1.c0 - t1.c1, c1: t1.c0 + t1.c1 };
    let c0 = t2.add(t0);
    let t2 = a.add(b).mul(a.add(b));
    let c1 = t2.add(t0.neg()).add(t1.neg());
    (c0, c1)
}

fn cyclotomic_square(f: Fp12) -> Fp12 {
    let z0 = f.c0.c0;
    let z4 = f.c0.c1;
    let z3 = f.c0.c2;
    let z2 = f.c1.c0;
    let z1 = f.c1.c1;
    let z5 = f.c1.c2;

    let (t0, t1) = fp4_square(z0, z1);
    let a0 = t0.add(z0.neg());
    let z0_final = a0.add(a0).add(t0);
    let b0 = t1.add(z1);
    let z1_final = b0.add(b0).add(t1);

    let (t0b, t1b) = fp4_square(z2, z3);
    let (t2b, t3b) = fp4_square(z4, z5);

    let a4 = t0b.add(z4.neg());
    let z4_final = a4.add(a4).add(t0b);
    let b4 = t1b.add(z5);
    let z5_final = b4.add(b4).add(t1b);

    let t0_nr = Fp2 { c0: t3b.c0 - t3b.c1, c1: t3b.c0 + t3b.c1 };
    let a2 = t0_nr.add(z2);
    let z2_final = a2.add(a2).add(t0_nr);
    let a3 = t2b.add(z3.neg());
    let z3_final = a3.add(a3).add(t2b);

    Fp12 {
        c0: Fp6 { c0: z0_final, c1: z4_final, c2: z3_final },
        c1: Fp6 { c0: z2_final, c1: z1_final, c2: z5_final },
    }
}

// Exponentiation by x = 0xd201000000010000 (BLS_X, negative - conjugate at end)
// x = 2^63+2^62+2^60+2^57+2^48+2^16
// bits[i] = bit(62-i) (63 entries, bit 63 handled by result=f init, same as T=Q in miller_loop)
// set bits: i=0(bit62), i=2(bit60), i=5(bit57), i=14(bit48), i=46(bit16)
fn cyclotomic_exp(f: Fp12) -> Fp12 {
    let bits: [bool; 63] = [
        true, false, true, false, false, true, false, false,
        false, false, false, false, false, false, true, false,
        false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, true, false,
        false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false
    ];
    let mut result = f;  // bit 63 = 1, same pattern as T=Q init in miller_loop
    for i in 0..63 {
        result = cyclotomic_square(result);
        if bits[i] {
            result = result.mul(f);
        }
    }
    result.conjugate()
}

// ---- Final exponentiation ----

// Easy part: f^((p^6-1)*(p^2+1))
fn final_exp_easy(f: Fp12) -> Fp12 {
    let f_inv = f.inv();
    let f_p6 = f.conjugate();
    let t0 = f_p6.mul(f_inv);
    let t1 = fp12_frobenius2(t0).mul(t0);
    t1
}

// Hard part: f^((p^4 - p^2 + 1)/r) - zkcrypto algorithm
fn final_exp_hard(f: Fp12) -> Fp12 {
    let zk_t2  = f;
    let h_t1 = cyclotomic_square(zk_t2).conjugate();
    let h_t3 = cyclotomic_exp(zk_t2);
    let h_t4 = cyclotomic_square(h_t3);
    let h_t5 = h_t1.mul(h_t3);
    let h_t1b = cyclotomic_exp(h_t5);
    let h_t0 = cyclotomic_exp(h_t1b);
    let h_t6 = cyclotomic_exp(h_t0);
    let h_t6b = h_t6.mul(h_t4);
    let h_t4b = cyclotomic_exp(h_t6b);
    let h_t5b = h_t5.conjugate();
    let h_t4c = h_t4b.mul(h_t5b).mul(zk_t2);
    let h_t5c = zk_t2.conjugate();
    let h_t1c = h_t1b.mul(zk_t2);
    let h_t1d = fp12_frobenius3(h_t1c);
    let h_t6d = fp12_frobenius(h_t6b.mul(h_t5c));
    let h_t3b = fp12_frobenius2(h_t3.mul(h_t0));
    let h_t3c = h_t3b.mul(h_t1d).mul(h_t6d);
    let result = h_t3c.mul(h_t4c);
    result
}

// RF-4: Complete final exponentiation
pub fn final_exp(f: Fp12) -> Fp12 {
    let f_easy = final_exp_easy(f);
    final_exp_hard(f_easy)
}

// ---- Sparse Fp12 multiply by line eval (mul_by_014) ----
fn fp12_mul_line(f: Fp12, lc0: Fp2, lc1: Fp2, lc2: Fp2) -> Fp12 {
    let g_c0 = Fp6 { c0: lc0, c1: lc2, c2: Fp2::zero() };
    let g_c1 = Fp6 { c0: lc1, c1: Fp2::zero(), c2: Fp2::zero() };
    let g = Fp12 { c0: g_c0, c1: g_c1 };
    f.mul(g)
}

// ---- Line evaluation (affine coords) ----

// Doubling step: returns (T_new, c0, c1, c2)
fn doubling_step(t: G2Point, p: G1Point) -> (G2Point, Fp2, Fp2, Fp2) {
    let three = Fp2 {
        c0: BLS12_381Fq::from_limbs([3, 0, 0, 0]),
        c1: BLS12_381Fq::zero(),
    };
    let two_fp: BLS12_381Fq = BLS12_381Fq::from_limbs([2, 0, 0, 0]);
    let two = Fp2 { c0: two_fp, c1: BLS12_381Fq::zero() };

    let xT2 = t.x.mul(t.x);
    let lam_num = three.mul(xT2);
    let lam_den = two.mul(t.y);
    let lambda = lam_num.mul(lam_den.inv());

    let x3 = lambda.mul(lambda).add(t.x.neg()).add(t.x.neg());
    let y3 = lambda.mul(t.x.add(x3.neg())).add(t.y.neg());

    let c0_raw = Fp2 { c0: BLS12_381Fq::one(), c1: BLS12_381Fq::zero() };
    let c1_raw = lambda.neg();
    let c2_raw = lambda.mul(t.x).add(t.y.neg());

    let py = p.y;
    let px = p.x;
    let c0s = Fp2 { c0: c0_raw.c0 * py, c1: BLS12_381Fq::zero() };
    let c1s = Fp2 { c0: c1_raw.c0 * px, c1: c1_raw.c1 * px };
    let c2s = c2_raw;

    let t_new = G2Point { x: x3, y: y3, infinity: false };
    (t_new, c0s, c1s, c2s)
}

// Addition step: line through T and Q, update T = T+Q
fn addition_step(t: G2Point, q: G2Point, p: G1Point) -> (G2Point, Fp2, Fp2, Fp2) {
    let dy = q.y.add(t.y.neg());
    let dx = q.x.add(t.x.neg());
    let lambda = dy.mul(dx.inv());

    let x3 = lambda.mul(lambda).add(t.x.neg()).add(q.x.neg());
    let y3 = lambda.mul(t.x.add(x3.neg())).add(t.y.neg());

    let c0_raw = Fp2 { c0: BLS12_381Fq::one(), c1: BLS12_381Fq::zero() };
    let c1_raw = lambda.neg();
    let c2_raw = lambda.mul(t.x).add(t.y.neg());

    let py = p.y;
    let px = p.x;
    let c0s = Fp2 { c0: c0_raw.c0 * py, c1: BLS12_381Fq::zero() };
    let c1s = Fp2 { c0: c1_raw.c0 * px, c1: c1_raw.c1 * px };
    let c2s = c2_raw;

    let t_new = G2Point { x: x3, y: y3, infinity: false };
    (t_new, c0s, c1s, c2s)
}

// ---- RF-4: Miller loop ----
pub fn miller_loop(q: G2Point, p: G1Point) -> Fp12 {
    if q.is_zero() | p.is_zero() {
        Fp12::one()
    } else {

    // x = 0xd201000000010000 = 2^63+2^62+2^60+2^57+2^48+2^16
    // skip leading bit 63; bits[i] = bit(62-i)
    // set bits: i=0(bit62), i=2(bit60), i=5(bit57), i=14(bit48), i=46(bit16)
    let bits: [bool; 63] = [
        true, false, true, false, false, true, false, false,
        false, false, false, false, false, false, true, false,
        false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, true, false,
        false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false
    ];

    let mut f = Fp12::one();
    let mut t = q;

    for i in 0..63 {
        f = f.mul(f);
        let (t_new, c0, c1, c2) = doubling_step(t, p);
        t = t_new;
        f = fp12_mul_line(f, c0, c1, c2);

        if bits[i] {
            let (t_new2, d0, d1, d2) = addition_step(t, q, p);
            t = t_new2;
            f = fp12_mul_line(f, d0, d1, d2);
        }
    }
    f.conjugate()
    }
}

// RF-5
pub fn pair(q: G2Point, p: G1Point) -> Fp12 {
    let f = miller_loop(q, p);
    final_exp(f)
}

// RF-6
pub fn pair_multi(q1: G2Point, p1: G1Point, q2: G2Point, p2: G1Point) -> Fp12 {
    if (q1.is_zero() | p1.is_zero()) & (q2.is_zero() | p2.is_zero()) {
        Fp12::one()
    } else if q1.is_zero() | p1.is_zero() {
        pair(q2, p2)
    } else if q2.is_zero() | p2.is_zero() {
        pair(q1, p1)
    } else {

    let bits: [bool; 63] = [
        true, false, true, false, false, true, false, false,
        false, false, false, false, false, false, false, true,
        false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false,
        true, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false
    ];

    let mut f = Fp12::one();
    let mut t1 = q1;
    let mut t2 = q2;

    for i in 0..63 {
        f = f.mul(f);

        let (t1_new, c0, c1, c2) = doubling_step(t1, p1);
        t1 = t1_new;
        f = fp12_mul_line(f, c0, c1, c2);

        let (t2_new, d0, d1, d2) = doubling_step(t2, p2);
        t2 = t2_new;
        f = fp12_mul_line(f, d0, d1, d2);

        if bits[i] {
            let (t1_new2, e0, e1, e2) = addition_step(t1, q1, p1);
            t1 = t1_new2;
            f = fp12_mul_line(f, e0, e1, e2);

            let (t2_new2, g0, g1, g2) = addition_step(t2, q2, p2);
            t2 = t2_new2;
            f = fp12_mul_line(f, g0, g1, g2);
        }
    }

    f = f.conjugate();
    final_exp(f)
    }
}

// ======================== TESTS (disabled - too expensive for nargo test) ========================

// #[test]
fn test_pairing_g2_zero_is_one() {
    println(">> test_pairing_g2_zero_is_one");
    let q = G2Point::zero();
    let p = G1Point::generator();
    let result = pair(q, p);
    assert(result.eq(Fp12::one()));
}

// #[test]
fn test_pairing_g1_zero_is_one() {
    println(">> test_pairing_g1_zero_is_one");
    let q = G2Point::generator();
    let p = G1Point::zero();
    let result = pair(q, p);
    assert(result.eq(Fp12::one()));
}

// #[test]
fn test_pair_multi_vs_pair() {
    println(">> test_pair_multi_vs_pair");
    let q = G2Point::generator();
    let p = G1Point::generator();
    let single = pair(q, p);
    let multi = pair_multi(q, p, q, p);
    assert(!multi.eq(single));
}

// #[test]
fn test_miller_loop_not_one() {
    println(">> test_miller_loop_not_one");
    let q = G2Point::generator();
    let p = G1Point::generator();
    let f = miller_loop(q, p);
    assert(!f.eq(Fp12::one()));
}
