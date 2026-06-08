use ::bignum::BigNum;
use crate::bls12_381::fp2::{BLS12_381Fq, Fp2};

// Fp6 = Fp2[v] / (v^3 - xi), xi = 1+u
// element: c0 + c1*v + c2*v^2
pub struct Fp6 {
    pub c0: Fp2,
    pub c1: Fp2,
    pub c2: Fp2,
}

// mul by xi = 1+u: xi*(c0+c1*u) = (c0-c1) + (c0+c1)*u
pub fn mul_by_xi(a: Fp2) -> Fp2 {
    Fp2 { c0: a.c0 - a.c1, c1: a.c0 + a.c1 }
}

impl Fp6 {
    pub fn zero() -> Self {
        Fp6 { c0: Fp2::zero(), c1: Fp2::zero(), c2: Fp2::zero() }
    }

    pub fn one() -> Self {
        Fp6 { c0: Fp2::one(), c1: Fp2::zero(), c2: Fp2::zero() }
    }

    pub fn is_zero(self) -> bool {
        self.c0.is_zero() & self.c1.is_zero() & self.c2.is_zero()
    }

    pub fn eq(self, other: Self) -> bool {
        self.c0.eq(other.c0) & self.c1.eq(other.c1) & self.c2.eq(other.c2)
    }

    pub fn add(self, other: Self) -> Self {
        Fp6 { c0: self.c0.add(other.c0), c1: self.c1.add(other.c1), c2: self.c2.add(other.c2) }
    }

    pub fn neg(self) -> Self {
        Fp6 { c0: self.c0.neg(), c1: self.c1.neg(), c2: self.c2.neg() }
    }

    // (a0+a1*v+a2*v^2)*(b0+b1*v+b2*v^2), v^3=xi
    // c0 = a0*b0 + xi*(a1*b2 + a2*b1)
    // c1 = a0*b1 + a1*b0 + xi*(a2*b2)
    // c2 = a0*b2 + a1*b1 + a2*b0
    pub fn mul(self, other: Self) -> Self {
        let a0b0 = self.c0.mul(other.c0);
        let a1b1 = self.c1.mul(other.c1);
        let a2b2 = self.c2.mul(other.c2);

        let c0 = a0b0.add(mul_by_xi(
            self.c1.mul(other.c2).add(self.c2.mul(other.c1))
        ));
        let c1 = self.c0.mul(other.c1)
                     .add(self.c1.mul(other.c0))
                     .add(mul_by_xi(a2b2));
        let c2 = self.c0.mul(other.c2)
                     .add(a1b1)
                     .add(self.c2.mul(other.c0));
        Fp6 { c0, c1, c2 }
    }

    // inv(a0+a1*v+a2*v^2):
    //   d0 = a0^2 - xi*a2*a1
    //   d1 = xi*a2^2 - a0*a1
    //   d2 = a1^2 - a0*a2
    //   t  = (a0*d0 + xi*(a2*d1 + a1*d2))^{-1} in Fp2
    //   inv = (d0*t, d1*t, d2*t)
    pub fn inv(self) -> Self {
        let d0 = self.c0.mul(self.c0).add(mul_by_xi(self.c2.mul(self.c1)).neg());
        let d1 = mul_by_xi(self.c2.mul(self.c2)).add(self.c0.mul(self.c1).neg());
        let d2 = self.c1.mul(self.c1).add(self.c0.mul(self.c2).neg());
        let t = self.c0.mul(d0)
                    .add(mul_by_xi(self.c2.mul(d1).add(self.c1.mul(d2))))
                    .inv();
        Fp6 { c0: d0.mul(t), c1: d1.mul(t), c2: d2.mul(t) }
    }
}

// ======================== TESTS GREEN ========================

#[test]
fn test_fp6_zero_is_zero() {
    println(">> test_fp6_zero_is_zero");
    let z = Fp6::zero();
    assert(z.is_zero());
}

#[test]
fn test_fp6_one_is_not_zero() {
    println(">> test_fp6_one_is_not_zero");
    let o = Fp6::one();
    assert(!o.is_zero());
}

#[test]
fn test_fp6_add_zero_identity() {
    println(">> test_fp6_add_zero_identity");
    let z = Fp6::zero();
    let o = Fp6::one();
    let r = z.add(o);
    assert(r.eq(o));
}

#[test]
fn test_fp6_neg_add_zero() {
    println(">> test_fp6_neg_add_zero");
    let o = Fp6::one();
    let no = o.neg();
    let r = o.add(no);
    assert(r.is_zero());
}

#[test]
fn test_fp6_mul_one_identity() {
    println(">> test_fp6_mul_one_identity");
    let o = Fp6::one();
    let r = o.mul(o);
    assert(r.eq(o));
}

#[test]
fn test_fp6_mul_v_cubed_is_xi() {
    println(">> test_fp6_mul_v_cubed_is_xi");
    let one_fp: BLS12_381Fq = BLS12_381Fq::one();
    let xi = Fp2 { c0: one_fp, c1: one_fp };
    let v = Fp6 { c0: Fp2::zero(), c1: Fp2::one(), c2: Fp2::zero() };
    let v3 = v.mul(v).mul(v);
    let expected = Fp6 { c0: xi, c1: Fp2::zero(), c2: Fp2::zero() };
    assert(v3.eq(expected));
}

#[test]
fn test_fp6_inv_times_self_is_one() {
    println(">> test_fp6_inv_times_self_is_one");
    let o = Fp6::one();
    let r = o.mul(o.inv());
    assert(r.eq(o));
}
