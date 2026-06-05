pub mod prime_field;

// RF-1: BigUint56 - entero de 392 bits en 7 limbs de 56 bits (Field)
struct BigUint56 {
    limbs: [Field; 7]
}

impl BigUint56 {
    // RF-2: 48 bytes little-endian -> 7 limbs de 56 bits
    // limb[i] = bytes[i*7 .. i*7+7] como u56 LE; limb[6] = bytes[42..48] (6 bytes)
    fn from_bytes(bytes: [u8; 48]) -> Self {
        let mut limbs: [Field; 7] = [0; 7];
        for i in 0..6 {
            let b = i * 7;
            limbs[i] = (bytes[b] as Field) + (bytes[b+1] as Field)*256 + (bytes[b+2] as Field)*65536 + (bytes[b+3] as Field)*16777216 + (bytes[b+4] as Field)*4294967296 + (bytes[b+5] as Field)*1099511627776 + (bytes[b+6] as Field)*281474976710656;
        }
        limbs[6] = (bytes[42] as Field) + (bytes[43] as Field)*256 + (bytes[44] as Field)*65536 + (bytes[45] as Field)*16777216 + (bytes[46] as Field)*4294967296 + (bytes[47] as Field)*1099511627776;
        BigUint56 { limbs }
    }
}

// RF-3: mul - multiplicacion ancha 7x7 -> 14 limbs
impl BigUint56 {
    fn mul(self, other: BigUint56) -> [Field; 14] {
        let limb_max: u128 = 72057594037927936; // 2^56
        let mut acc: [u128; 14] = [0; 14];
        for i in 0..7 {
            for j in 0..7 {
                acc[i+j] = acc[i+j] + (self.limbs[i] as u128) * (other.limbs[j] as u128);
            }
        }
        let mut result: [Field; 14] = [0; 14];
        let mut carry: u128 = 0;
        for k in 0..14 {
            let total: u128 = acc[k] + carry;
            carry = total / limb_max;
            result[k] = (total % limb_max) as Field;
        }
        result
    }
}

// RF-3: adc, sbb, lt, eq
impl BigUint56 {
    // suma con acarreo: limb[i] = (a[i] + b[i] + carry) mod 2^56
    fn adc(self, other: BigUint56) -> (BigUint56, bool) {
        let mut limbs: [Field; 7] = [0; 7];
        let mut carry: u64 = 0;
        let limb_max: u64 = 72057594037927936; // 2^56
        for i in 0..7 {
            let sum: u64 = self.limbs[i] as u64 + other.limbs[i] as u64 + carry;
            carry = sum / limb_max;
            limbs[i] = (sum % limb_max) as Field;
        }
        (BigUint56 { limbs }, carry == 1)
    }

    // resta con prestamo: usa a[i] + limb_max - b[i] - borrow para evitar underflow
    fn sbb(self, other: BigUint56) -> (BigUint56, bool) {
        let mut limbs: [Field; 7] = [0; 7];
        let mut borrow: u64 = 0;
        let limb_max: u64 = 72057594037927936; // 2^56
        for i in 0..7 {
            let sub: u64 = self.limbs[i] as u64 + limb_max - other.limbs[i] as u64 - borrow;
            // sub in [0, limb_max-1] -> necesito borrow; sub in [limb_max, 2*limb_max-1] -> no borrow
            borrow = 1 - sub / limb_max;
            limbs[i] = (sub % limb_max) as Field;
        }
        (BigUint56 { limbs }, borrow == 1)
    }

    // self < other: equivalente a sbb completo y verificar borrow final
    fn lt(self, other: BigUint56) -> bool {
        let mut borrow: u64 = 0;
        let limb_max: u64 = 72057594037927936;
        for i in 0..7 {
            let sub: u64 = self.limbs[i] as u64 + limb_max - other.limbs[i] as u64 - borrow;
            borrow = 1 - sub / limb_max;
        }
        borrow == 1
    }

    // igualdad limb a limb
    fn eq(self, other: BigUint56) -> bool {
        (self.limbs[0] == other.limbs[0]) &
        (self.limbs[1] == other.limbs[1]) &
        (self.limbs[2] == other.limbs[2]) &
        (self.limbs[3] == other.limbs[3]) &
        (self.limbs[4] == other.limbs[4]) &
        (self.limbs[5] == other.limbs[5]) &
        (self.limbs[6] == other.limbs[6])
    }
}

// FASE RED: RF-3 - adc, sbb, lt, eq
#[test]
fn test_adc_no_carry() {
    // 1 + 1 = 2, sin carry
    let a = BigUint56::from_bytes([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    let b = BigUint56::from_bytes([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    let (r, carry) = a.adc(b);
    assert(r.limbs[0] == 2);  // FALLA: stub devuelve 0
    assert(carry == false);
}

#[test]
fn test_adc_carry_between_limbs() {
    // limb[0] = 2^56 - 1 (max 56 bits) + 1 => limb[0]=0, carry al limb[1]
    // bytes 0..7 todos 0xFF -> limb[0] = 2^56-1 = 72057594037927935
    let mut bytes_a: [u8; 48] = [0; 48];
    bytes_a[0] = 255; bytes_a[1] = 255; bytes_a[2] = 255; bytes_a[3] = 255;
    bytes_a[4] = 255; bytes_a[5] = 255; bytes_a[6] = 255;
    let a = BigUint56::from_bytes(bytes_a);
    let mut bytes_b: [u8; 48] = [0; 48];
    bytes_b[0] = 1;
    let b = BigUint56::from_bytes(bytes_b);
    let (r, _) = a.adc(b);
    assert(r.limbs[0] == 0);   // FALLA: stub devuelve 0 pero por razon incorrecta
    assert(r.limbs[1] == 1);   // FALLA: stub devuelve 0
}

#[test]
fn test_sbb_no_borrow() {
    // 5 - 3 = 2, sin borrow
    let a = BigUint56::from_bytes([5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    let b = BigUint56::from_bytes([3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    let (r, borrow) = a.sbb(b);
    assert(r.limbs[0] == 2);   // FALLA: stub devuelve 0
    assert(borrow == false);
}

#[test]
fn test_lt() {
    let a = BigUint56::from_bytes([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    let b = BigUint56::from_bytes([2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    assert(a.lt(b) == true);   // FALLA: stub devuelve false
    assert(b.lt(a) == false);
}

#[test]
fn test_eq() {
    let a = BigUint56::from_bytes([7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    let b = BigUint56::from_bytes([7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    let c = BigUint56::from_bytes([9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    assert(a.eq(b) == true);   // FALLA: stub devuelve false
    assert(a.eq(c) == false);
}
#[test]
fn test_biguint56_from_bytes_le() {
    // byte[0] = 1, resto = 0 -> limb[0] debe ser 1 (LE: byte[0] es el menos significativo)
    let mut bytes: [u8; 48] = [0; 48];
    bytes[0] = 1;

    let n = BigUint56::from_bytes(bytes);

    // limb[0] = bytes[0..7] como u56 little-endian -> debe ser 1
    assert(n.limbs[0] == 1);

    // RF-1: los 7 limbs existen y el resto son 0
    assert(n.limbs[1] == 0);
    assert(n.limbs[6] == 0);
}

// FASE RED: RF-3 - mul
#[test]
fn test_mul_simple() {
    // 2 * 3 = 6 -> result[0] == 6, resto 0
    let a = BigUint56::from_bytes([2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    let b = BigUint56::from_bytes([3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    let r = a.mul(b);
    assert(r[0] == 6);   // FALLA: stub devuelve 0
    assert(r[1] == 0);
    assert(r[7] == 0);
}

#[test]
fn test_mul_cross_limb() {
    // limb[0] = 2^56 - 1 (max), limb[1] = 0; * 2 -> low = 2*(2^56-1) mod 2^56 = 2^57 - 2
    // result[0] = (2^57 - 2) mod 2^56 = 2^56 - 2, result[1] = 1 (carry)
    let mut bytes: [u8; 48] = [0; 48];
    bytes[0] = 255; bytes[1] = 255; bytes[2] = 255; bytes[3] = 255;
    bytes[4] = 255; bytes[5] = 255; bytes[6] = 255;
    let a = BigUint56::from_bytes(bytes);
    let b = BigUint56::from_bytes([2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    let r = a.mul(b);
    // (2^56 - 1) * 2 = 2^57 - 2 = 1*2^56 + (2^56 - 2)
    assert(r[0] == 72057594037927934);  // 2^56 - 2 -- FALLA: stub devuelve 0
    assert(r[1] == 1);                  // carry -- FALLA
}
