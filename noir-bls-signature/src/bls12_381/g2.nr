use ::noir_bigint_bls12_381::prime_field::PrimeField;
use crate::bls12_381::fp2::Fp2;

// RF-8: G2 generator x.c0 (BE->LE 48 bytes)
global G2_GEN_X_C0: [u8; 48] = [
    0xb8, 0xbd, 0x21, 0xc1, 0xc8, 0x56, 0x80, 0xd4,
    0xef, 0xbb, 0x05, 0xa8, 0x26, 0x03, 0xac, 0x0b,
    0x77, 0xd1, 0xe3, 0x7a, 0x64, 0x0b, 0x51, 0xb4,
    0x02, 0x3b, 0x40, 0xfa, 0xd4, 0x7a, 0xe4, 0xc6,
    0x51, 0x10, 0xc5, 0x2d, 0x27, 0x05, 0x08, 0x26,
    0x91, 0x0a, 0x8f, 0xf0, 0xb2, 0xa2, 0x4a, 0x02
];

global G2_GEN_X_C1: [u8; 48] = [
    0x7e, 0x2b, 0x04, 0x5d, 0x05, 0x7d, 0xac, 0xe5,
    0x57, 0x5d, 0x94, 0x13, 0x12, 0xf1, 0x4c, 0x33,
    0x49, 0x50, 0x7f, 0xdc, 0xbb, 0x61, 0xda, 0xb5,
    0x1a, 0xb6, 0x20, 0x99, 0xd0, 0xd0, 0x6b, 0x59,
    0x65, 0x4f, 0x27, 0x88, 0xa0, 0xd3, 0xac, 0x7d,
    0x60, 0x9f, 0x71, 0x52, 0x60, 0x2b, 0xe0, 0x13
];

global G2_GEN_Y_C0: [u8; 48] = [
    0x01, 0x28, 0xb8, 0x08, 0x86, 0x54, 0x93, 0xe1,
    0x89, 0xa2, 0xac, 0x3b, 0xcc, 0xc9, 0x3a, 0x92,
    0x2c, 0xd1, 0x60, 0x51, 0x69, 0x9a, 0x42, 0x6d,
    0xa7, 0xd3, 0xbd, 0x8c, 0xaa, 0x9b, 0xfd, 0xad,
    0x1a, 0x35, 0x2e, 0xda, 0xc6, 0xcd, 0xc9, 0x8c,
    0x11, 0x6e, 0x7d, 0x72, 0x27, 0xd5, 0xe5, 0x0c
];

global G2_GEN_Y_C1: [u8; 48] = [
    0xbe, 0x79, 0x5f, 0xf0, 0x5f, 0x07, 0xa9, 0xaa,
    0xa1, 0x1d, 0xec, 0x5c, 0x27, 0x0d, 0x37, 0x3f,
    0xab, 0x99, 0x2e, 0x57, 0xab, 0x92, 0x74, 0x26,
    0xaf, 0x63, 0xa7, 0x85, 0x7e, 0x28, 0x3e, 0xcb,
    0x99, 0x8b, 0xc2, 0x2b, 0xb0, 0xd2, 0xac, 0x32,
    0xcc, 0x34, 0xa7, 0x2e, 0xa0, 0xc4, 0x06, 0x06
];

// RF-2: punto en G2 (Short Weierstrass sobre Fp2): y^2 = x^3 + 4(1+u)
pub struct G2Point {
    pub x: Fp2,
    pub y: Fp2,
    pub infinity: bool,
}

impl G2Point {
    pub fn zero() -> Self {
        G2Point { x: Fp2::zero(), y: Fp2::zero(), infinity: true }
    }

    pub fn generator() -> Self {
        G2Point {
            x: Fp2 {
                c0: PrimeField::from_bytes(G2_GEN_X_C0),
                c1: PrimeField::from_bytes(G2_GEN_X_C1),
            },
            y: Fp2 {
                c0: PrimeField::from_bytes(G2_GEN_Y_C0),
                c1: PrimeField::from_bytes(G2_GEN_Y_C1),
            },
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
            G2Point { x: self.x, y: self.y.neg(), infinity: false }
        }
    }

    pub fn add(self, other: Self) -> Self {
        if self.infinity {
            other
        } else if other.infinity {
            self
        } else {
            let same_x = self.x.eq(other.x);
            let same_y = self.y.eq(other.y);
            if same_x {
                if same_y { self.double() } else { G2Point::zero() }
            } else {
                let dy = other.y.add(self.y.neg());
                let dx = other.x.add(self.x.neg());
                let lambda = dy.mul(dx.inv());
                let x3 = lambda.mul(lambda).add(self.x.neg()).add(other.x.neg());
                let y3 = lambda.mul(self.x.add(x3.neg())).add(self.y.neg());
                G2Point { x: x3, y: y3, infinity: false }
            }
        }
    }

    pub fn double(self) -> Self {
        if self.infinity {
            self
        } else {
            let three = Fp2 {
                c0: PrimeField { limbs: [3, 0, 0, 0, 0, 0, 0] }.to_montgomery(),
                c1: PrimeField { limbs: [0; 7] },
            };
            let two = Fp2 {
                c0: PrimeField { limbs: [2, 0, 0, 0, 0, 0, 0] }.to_montgomery(),
                c1: PrimeField { limbs: [0; 7] },
            };
            let x2 = self.x.mul(self.x);
            let lambda = three.mul(x2).mul(two.mul(self.y).inv());
            let x3 = lambda.mul(lambda).add(self.x.neg()).add(self.x.neg());
            let y3 = lambda.mul(self.x.add(x3.neg())).add(self.y.neg());
            G2Point { x: x3, y: y3, infinity: false }
        }
    }
}

// ======================== TESTS GREEN ========================

#[test]
fn test_g2_zero_is_identity() {
    println(">> test_g2_zero_is_identity");
    let z = G2Point::zero();
    assert(z.is_zero());
}

#[test]
fn test_g2_generator_is_not_zero() {
    println(">> test_g2_generator_is_not_zero");
    let g = G2Point::generator();
    assert(!g.is_zero());
}

#[test]
fn test_g2_generator_x_c0_nonzero() {
    println(">> test_g2_generator_x_c0_nonzero");
    let g = G2Point::generator();
    let xc0 = g.x.c0.from_montgomery();
    assert(xc0.limbs[0] != 0);
}

#[test]
fn test_g2_neg_of_zero_is_zero() {
    println(">> test_g2_neg_of_zero_is_zero");
    let z = G2Point::zero();
    assert(z.neg().is_zero());
}

#[test]
fn test_g2_add_neg_is_zero() {
    println(">> test_g2_add_neg_is_zero");
    let g = G2Point::generator();
    let result = g.add(g.neg());
    assert(result.is_zero());
}

#[test]
fn test_g2_add_left_identity() {
    println(">> test_g2_add_left_identity");
    let z = G2Point::zero();
    let g = G2Point::generator();
    assert(!z.add(g).is_zero());
}

#[test]
fn test_g2_add_right_identity() {
    println(">> test_g2_add_right_identity");
    let g = G2Point::generator();
    let z = G2Point::zero();
    assert(!g.add(z).is_zero());
}

#[test]
fn test_g2_double_not_zero() {
    println(">> test_g2_double_not_zero");
    let g = G2Point::generator();
    assert(!g.double().is_zero());
}
