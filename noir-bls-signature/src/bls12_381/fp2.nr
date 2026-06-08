use ::bignum::BigNum;
use ::bignum::BLS12_381_Fq;

// BLS12-381 base field Fq via noir-bignum v0.10.0 pre-defined concrete struct.
// Inverse uses an unconstrained oracle + 1 constrained multiplication (~15K gates)
// vs the previous Fermat exp(p-2) approach (~19M gates per inverse).
pub type BLS12_381Fq = BLS12_381_Fq;

// Convert 48 little-endian bytes (as used in our constants) to a field element.
pub fn fp_from_le(bytes: [u8; 48]) -> BLS12_381Fq {
    BLS12_381_Fq::from_le_bytes(bytes)
}

// Fp2 = Fp[u] / (u^2 + 1)
// element: c0 + c1*u
pub struct Fp2 {
    pub c0: BLS12_381Fq,
    pub c1: BLS12_381Fq,
}

impl Fp2 {
    pub fn zero() -> Self {
        Fp2 { c0: BLS12_381_Fq::zero(), c1: BLS12_381_Fq::zero() }
    }

    pub fn one() -> Self {
        Fp2 { c0: BLS12_381_Fq::one(), c1: BLS12_381_Fq::zero() }
    }

    pub fn is_zero(self) -> bool {
        let zero: BLS12_381Fq = BLS12_381_Fq::zero();
        (self.c0 == zero) & (self.c1 == zero)
    }

    pub fn eq(self, other: Self) -> bool {
        (self.c0 == other.c0) & (self.c1 == other.c1)
    }

    pub fn add(self, other: Self) -> Self {
        Fp2 { c0: self.c0 + other.c0, c1: self.c1 + other.c1 }
    }

    pub fn neg(self) -> Self {
        Fp2 { c0: -self.c0, c1: -self.c1 }
    }

    // (a+bu)(c+du) = (ac - bd) + (ad+bc)u   [u^2 = -1]
    // Karatsuba: t0=a*c, t1=b*d, c0=t0-t1, c1=(a+b)*(c+d)-t0-t1
    pub fn mul(self, other: Self) -> Self {
        let t0 = self.c0 * other.c0;
        let t1 = self.c1 * other.c1;
        let c0 = t0 - t1;
        let c1 = (self.c0 + self.c1) * (other.c0 + other.c1) - t0 - t1;
        Fp2 { c0, c1 }
    }

    // inv(a+bu) = (a - bu) / (a^2 + b^2)
    // Uses bignum constrained division: 1 oracle hint + 1 constrained mul per inverse.
    pub fn inv(self) -> Self {
        let norm = self.c0 * self.c0 + self.c1 * self.c1;
        let one: BLS12_381Fq = BLS12_381_Fq::one();
        let inv_norm = one / norm;
        Fp2 { c0: self.c0 * inv_norm, c1: (-self.c1) * inv_norm }
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
        c0: BLS12_381_Fq::zero(),
        c1: BLS12_381_Fq::one(),
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
