use ::noir_bigint_bls12_381::prime_field::PrimeField;

// Fp2 = Fp[u] / (u^2 + 1)
// elemento: c0 + c1*u, con c0,c1 en Montgomery form
pub struct Fp2 {
    pub c0: PrimeField,
    pub c1: PrimeField,
}

impl Fp2 {
    pub fn zero() -> Self {
        Fp2 { c0: PrimeField { limbs: [0;7] }, c1: PrimeField { limbs: [0;7] } }
    }

    pub fn one() -> Self {
        Fp2 {
            c0: PrimeField { limbs: [1, 0, 0, 0, 0, 0, 0] }.to_montgomery(),
            c1: PrimeField { limbs: [0;7] },
        }
    }

    pub fn is_zero(self) -> bool {
        let z: [Field; 7] = [0;7];
        let c0z = (self.c0.limbs[0] == z[0]) & (self.c0.limbs[1] == z[1]) &
                  (self.c0.limbs[2] == z[2]) & (self.c0.limbs[3] == z[3]) &
                  (self.c0.limbs[4] == z[4]) & (self.c0.limbs[5] == z[5]) &
                  (self.c0.limbs[6] == z[6]);
        let c1z = (self.c1.limbs[0] == z[0]) & (self.c1.limbs[1] == z[1]) &
                  (self.c1.limbs[2] == z[2]) & (self.c1.limbs[3] == z[3]) &
                  (self.c1.limbs[4] == z[4]) & (self.c1.limbs[5] == z[5]) &
                  (self.c1.limbs[6] == z[6]);
        c0z & c1z
    }

    pub fn eq(self, other: Self) -> bool {
        self.c0.eq(other.c0) & self.c1.eq(other.c1)
    }

    pub fn add(self, other: Self) -> Self {
        Fp2 { c0: self.c0.add(other.c0), c1: self.c1.add(other.c1) }
    }

    pub fn neg(self) -> Self {
        Fp2 { c0: self.c0.neg(), c1: self.c1.neg() }
    }

    // (a+bu)(c+du) = (ac - bd) + (ad+bc)u   [u^2 = -1]
    // Karatsuba: t0=a*c, t1=b*d, c0=t0-t1, c1=(a+b)*(c+d)-t0-t1
    pub fn mul(self, other: Self) -> Self {
        let t0 = self.c0.mul(other.c0);
        let t1 = self.c1.mul(other.c1);
        let c0 = t0.add(t1.neg());
        let ab = self.c0.add(self.c1);
        let cd = other.c0.add(other.c1);
        let c1 = ab.mul(cd).add(t0.neg()).add(t1.neg());
        Fp2 { c0, c1 }
    }

    // inv(a+bu) = (a - bu) / (a^2 + b^2)
    pub fn inv(self) -> Self {
        let norm = self.c0.mul(self.c0).add(self.c1.mul(self.c1));
        let inv_norm = norm.inv();
        Fp2 { c0: self.c0.mul(inv_norm), c1: self.c1.neg().mul(inv_norm) }
    }
}

// ======================== TESTS GREEN ========================

#[test]
fn test_fp2_zero_is_zero() {
    println(">> test_fp2_zero_is_zero");
    let z = Fp2::zero();
    assert(z.is_zero());
}

#[test]
fn test_fp2_one_is_not_zero() {
    println(">> test_fp2_one_is_not_zero");
    let o = Fp2::one();
    assert(!o.is_zero());
}

#[test]
fn test_fp2_add_zero_identity() {
    println(">> test_fp2_add_zero_identity");
    let z = Fp2::zero();
    let o = Fp2::one();
    let r = z.add(o);
    assert(r.eq(o));
}

#[test]
fn test_fp2_neg_add_zero() {
    println(">> test_fp2_neg_add_zero");
    let o = Fp2::one();
    let no = o.neg();
    let r = o.add(no);
    assert(r.is_zero());
}

#[test]
fn test_fp2_mul_one_identity() {
    println(">> test_fp2_mul_one_identity");
    let o = Fp2::one();
    let r = o.mul(o);
    assert(r.eq(o));
}

#[test]
fn test_fp2_mul_u_squared_is_neg_one() {
    println(">> test_fp2_mul_u_squared_is_neg_one");
    let u = Fp2 {
        c0: PrimeField { limbs: [0; 7] },
        c1: PrimeField { limbs: [1, 0, 0, 0, 0, 0, 0] }.to_montgomery(),
    };
    let u2 = u.mul(u);
    let neg_one = Fp2::one().neg();
    assert(u2.eq(neg_one));
}

#[test]
fn test_fp2_inv_times_self_is_one() {
    println(">> test_fp2_inv_times_self_is_one");
    let o = Fp2::one();
    let inv_o = o.inv();
    let r = o.mul(inv_o);
    assert(r.eq(o));
}
