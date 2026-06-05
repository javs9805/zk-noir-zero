use crate::bls12_381::fp6::{Fp6, mul_by_xi};

// Fp12 = Fp6[w] / (w^2 - v)
// elemento: c0 + c1*w, con c0,c1 en Fp6
pub struct Fp12 {
    pub c0: Fp6,
    pub c1: Fp6,
}

// mul_by_v en Fp6: a*v = xi*a2 + a0*v + a1*v^2
fn fp6_mul_by_v(a: Fp6) -> Fp6 {
    Fp6 { c0: mul_by_xi(a.c2), c1: a.c0, c2: a.c1 }
}

impl Fp12 {
    pub fn zero() -> Self {
        Fp12 { c0: Fp6::zero(), c1: Fp6::zero() }
    }

    pub fn one() -> Self {
        Fp12 { c0: Fp6::one(), c1: Fp6::zero() }
    }

    pub fn is_zero(self) -> bool {
        self.c0.is_zero() & self.c1.is_zero()
    }

    pub fn eq(self, other: Self) -> bool {
        self.c0.eq(other.c0) & self.c1.eq(other.c1)
    }

    pub fn add(self, other: Self) -> Self {
        Fp12 { c0: self.c0.add(other.c0), c1: self.c1.add(other.c1) }
    }

    pub fn neg(self) -> Self {
        Fp12 { c0: self.c0.neg(), c1: self.c1.neg() }
    }

    // (a+bw)(c+dw) = (ac + bd*v) + (ad+bc)*w
    pub fn mul(self, other: Self) -> Self {
        let ac = self.c0.mul(other.c0);
        let bd = self.c1.mul(other.c1);
        let c0 = ac.add(fp6_mul_by_v(bd));
        let c1 = self.c0.mul(other.c1).add(self.c1.mul(other.c0));
        Fp12 { c0, c1 }
    }

    // inv(a+bw) = (a - b*w) / (a^2 - b^2*v)
    pub fn inv(self) -> Self {
        let norm = self.c0.mul(self.c0).add(fp6_mul_by_v(self.c1.mul(self.c1)).neg());
        let inv_norm = norm.inv();
        Fp12 { c0: self.c0.mul(inv_norm), c1: self.c1.neg().mul(inv_norm) }
    }

    pub fn conjugate(self) -> Self {
        Fp12 { c0: self.c0, c1: self.c1.neg() }
    }
}

// ======================== TESTS GREEN ========================

#[test]
fn test_fp12_zero_is_zero() {
    println(">> test_fp12_zero_is_zero");
    let z = Fp12::zero();
    assert(z.is_zero());
}

#[test]
fn test_fp12_one_is_not_zero() {
    println(">> test_fp12_one_is_not_zero");
    let o = Fp12::one();
    assert(!o.is_zero());
}

#[test]
fn test_fp12_add_zero_identity() {
    println(">> test_fp12_add_zero_identity");
    let z = Fp12::zero();
    let o = Fp12::one();
    let r = z.add(o);
    assert(r.eq(o));
}

#[test]
fn test_fp12_neg_add_zero() {
    println(">> test_fp12_neg_add_zero");
    let o = Fp12::one();
    let r = o.add(o.neg());
    assert(r.is_zero());
}

#[test]
fn test_fp12_mul_one_identity() {
    println(">> test_fp12_mul_one_identity");
    let o = Fp12::one();
    let r = o.mul(o);
    assert(r.eq(o));
}

#[test]
fn test_fp12_inv_times_self_is_one() {
    println(">> test_fp12_inv_times_self_is_one");
    let o = Fp12::one();
    let r = o.mul(o.inv());
    assert(r.eq(o));
}

#[test]
fn test_fp12_conjugate_mul_is_norm() {
    println(">> test_fp12_conjugate_mul_is_norm");
    let o = Fp12::one();
    let r = o.mul(o.conjugate());
    assert(r.eq(o));
}
