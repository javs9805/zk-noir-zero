use ::noir_bigint_bls12_381::prime_field::PrimeField;

// RF-8: coordenada X del generador G1 de BLS12-381 en little-endian 48 bytes
// Gx = 0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb
global G1_GEN_X: [u8; 48] = [
    0xbb, 0xc6, 0x22, 0xdb, 0x0a, 0xf0, 0x3a, 0xfb,
    0xef, 0x1a, 0x7a, 0xf9, 0x3f, 0xe8, 0x55, 0x6c,
    0x58, 0xac, 0x1b, 0x17, 0x3f, 0x3a, 0x4e, 0xa1,
    0x05, 0xb9, 0x74, 0x97, 0x4f, 0x8c, 0x68, 0xc3,
    0x0f, 0xac, 0xa9, 0x4f, 0x8c, 0x63, 0x95, 0x26,
    0x94, 0xd7, 0x97, 0x31, 0xa7, 0xd3, 0xf1, 0x17
];

// RF-8: coordenada Y del generador G1 de BLS12-381 en little-endian 48 bytes
// Gy = 0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1
global G1_GEN_Y: [u8; 48] = [
    0xe1, 0xe7, 0xc5, 0x46, 0x29, 0x23, 0xaa, 0x0c,
    0xe4, 0x8a, 0x88, 0xa2, 0x44, 0xc7, 0x3c, 0xd0,
    0xed, 0xb3, 0x04, 0x2c, 0xcb, 0x18, 0xdb, 0x00,
    0xf6, 0x0a, 0xd0, 0xd5, 0x95, 0xe0, 0xf5, 0xfc,
    0xe4, 0x8a, 0x1d, 0x74, 0xed, 0x30, 0x9e, 0xa0,
    0xf1, 0xa0, 0xaa, 0xe3, 0x81, 0xf4, 0xb3, 0x08
];

// RF-1: punto en G1 (Short Weierstrass sobre Fp): y^2 = x^3 + 4
pub struct G1Point {
    pub x: PrimeField,
    pub y: PrimeField,
    pub infinity: bool,
}

impl G1Point {
    pub fn zero() -> Self {
        G1Point { x: PrimeField { limbs: [0; 7] }, y: PrimeField { limbs: [0; 7] }, infinity: true }
    }

    pub fn generator() -> Self {
        G1Point {
            x: PrimeField::from_bytes(G1_GEN_X),
            y: PrimeField::from_bytes(G1_GEN_Y),
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
            G1Point { x: self.x, y: self.y.neg(), infinity: false }
        }
    }

    // Suma affine completa (Short Weierstrass)
    pub fn add(self, other: Self) -> Self {
        if self.infinity {
            other
        } else if other.infinity {
            self
        } else {
            let same_x = self.x.eq(other.x);
            let same_y = self.y.eq(other.y);
            if same_x {
                if same_y {
                    self.double()
                } else {
                    G1Point::zero()
                }
            } else {
                let dy = other.y.add(self.y.neg());
                let dx = other.x.add(self.x.neg());
                let lambda = dy.mul(dx.inv());
                let x3 = lambda.mul(lambda).add(self.x.neg()).add(other.x.neg());
                let y3 = lambda.mul(self.x.add(x3.neg())).add(self.y.neg());
                G1Point { x: x3, y: y3, infinity: false }
            }
        }
    }

    // Duplicacion: 2*P via formula lambda = 3x^2 / 2y
    pub fn double(self) -> Self {
        if self.infinity {
            self
        } else {
            let three  = PrimeField { limbs: [3, 0, 0, 0, 0, 0, 0] }.to_montgomery();
            let two    = PrimeField { limbs: [2, 0, 0, 0, 0, 0, 0] }.to_montgomery();
            let x2     = self.x.mul(self.x);
            let num    = three.mul(x2);
            let den    = two.mul(self.y);
            let lambda = num.mul(den.inv());
            let x3 = lambda.mul(lambda).add(self.x.neg()).add(self.x.neg());
            let y3 = lambda.mul(self.x.add(x3.neg())).add(self.y.neg());
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
    let xc = g.x.from_montgomery();
    assert(xc.limbs[0] != 0);
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
