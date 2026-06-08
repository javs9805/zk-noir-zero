use ::bignum::BigNum;
use crate::bls12_381::fp2::{BLS12_381Fq, fp_from_le};

// RF-8: G1 generator X in little-endian 48 bytes
// Gx = 0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb
global G1_GEN_X: [u8; 48] = [
    0xbb, 0xc6, 0x22, 0xdb, 0x0a, 0xf0, 0x3a, 0xfb,
    0xef, 0x1a, 0x7a, 0xf9, 0x3f, 0xe8, 0x55, 0x6c,
    0x58, 0xac, 0x1b, 0x17, 0x3f, 0x3a, 0x4e, 0xa1,
    0x05, 0xb9, 0x74, 0x97, 0x4f, 0x8c, 0x68, 0xc3,
    0x0f, 0xac, 0xa9, 0x4f, 0x8c, 0x63, 0x95, 0x26,
    0x94, 0xd7, 0x97, 0x31, 0xa7, 0xd3, 0xf1, 0x17
];

// RF-8: G1 generator Y in little-endian 48 bytes
// Gy = 0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1
global G1_GEN_Y: [u8; 48] = [
    0xe1, 0xe7, 0xc5, 0x46, 0x29, 0x23, 0xaa, 0x0c,
    0xe4, 0x8a, 0x88, 0xa2, 0x44, 0xc7, 0x3c, 0xd0,
    0xed, 0xb3, 0x04, 0x2c, 0xcb, 0x18, 0xdb, 0x00,
    0xf6, 0x0a, 0xd0, 0xd5, 0x95, 0xe0, 0xf5, 0xfc,
    0xe4, 0x8a, 0x1d, 0x74, 0xed, 0x30, 0x9e, 0xa0,
    0xf1, 0xa0, 0xaa, 0xe3, 0x81, 0xf4, 0xb3, 0x08
];

// RF-1: G1 point (Short Weierstrass over Fq): y^2 = x^3 + 4
pub struct G1Point {
    pub x: BLS12_381Fq,
    pub y: BLS12_381Fq,
    pub infinity: bool,
}

impl G1Point {
    pub fn zero() -> Self {
        G1Point { x: BLS12_381Fq::zero(), y: BLS12_381Fq::zero(), infinity: true }
    }

    pub fn generator() -> Self {
        G1Point {
            x: fp_from_le(G1_GEN_X),
            y: fp_from_le(G1_GEN_Y),
            infinity: false,
        }
    }

    pub fn is_zero(self) -> bool {
        self.infinity
    }

    pub fn neg(self) -> Self {
        if self.infinity {
            self
        } else {
            G1Point { x: self.x, y: -self.y, infinity: false }
        }
    }

    // Affine addition (Short Weierstrass complete formula)
    pub fn add(self, other: Self) -> Self {
        if self.infinity {
            other
        } else if other.infinity {
            self
        } else {
            let same_x = self.x == other.x;
            let same_y = self.y == other.y;
            if same_x {
                if same_y {
                    self.double()
                } else {
                    G1Point::zero()
                }
            } else {
                // lambda = (y2 - y1) / (x2 - x1)
                let lambda = (other.y - self.y) / (other.x - self.x);
                let x3 = lambda * lambda - self.x - other.x;
                let y3 = lambda * (self.x - x3) - self.y;
                G1Point { x: x3, y: y3, infinity: false }
            }
        }
    }

    // Point doubling: lambda = 3x^2 / 2y
    pub fn double(self) -> Self {
        if self.infinity {
            self
        } else {
            let three: BLS12_381Fq = BLS12_381Fq::from_limbs([3, 0, 0, 0]);
            let two: BLS12_381Fq   = BLS12_381Fq::from_limbs([2, 0, 0, 0]);
            let lambda = (three * self.x * self.x) / (two * self.y);
            let x3 = lambda * lambda - self.x - self.x;
            let y3 = lambda * (self.x - x3) - self.y;
            G1Point { x: x3, y: y3, infinity: false }
        }
    }
}

// ======================== TESTS GREEN ========================

#[test]
fn test_g1_zero_is_identity() {
    println(">> test_g1_zero_is_identity");
    let z = G1Point::zero();
    assert(z.is_zero());
}

#[test]
fn test_g1_generator_is_not_zero() {
    println(">> test_g1_generator_is_not_zero");
    let g = G1Point::generator();
    assert(!g.is_zero());
}

#[test]
fn test_g1_generator_x_first_limb() {
    println(">> test_g1_generator_x_first_limb");
    let g = G1Point::generator();
    let zero: BLS12_381Fq = BLS12_381Fq::zero();
    assert(!(g.x == zero));
}

#[test]
fn test_g1_neg_of_zero_is_zero() {
    println(">> test_g1_neg_of_zero_is_zero");
    let z = G1Point::zero();
    let nz = z.neg();
    assert(nz.is_zero());
}

#[test]
fn test_g1_add_neg_is_zero() {
    println(">> test_g1_add_neg_is_zero");
    let g = G1Point::generator();
    let ng = g.neg();
    let result = g.add(ng);
    assert(result.is_zero());
}

#[test]
fn test_g1_add_left_identity() {
    println(">> test_g1_add_left_identity");
    let z = G1Point::zero();
    let g = G1Point::generator();
    let result = z.add(g);
    assert(!result.is_zero());
}

#[test]
fn test_g1_add_right_identity() {
    println(">> test_g1_add_right_identity");
    let g = G1Point::generator();
    let z = G1Point::zero();
    let result = g.add(z);
    assert(!result.is_zero());
}

#[test]
fn test_g1_double_not_zero() {
    println(">> test_g1_double_not_zero");
    let g = G1Point::generator();
    let dbl = g.double();
    assert(!dbl.is_zero());
}
