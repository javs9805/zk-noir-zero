// RF-4: PrimeField (Fp) con representacion Montgomery para BLS12-381
// p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab

// RF-8: P = prima BLS12-381 en 7 limbs de 56 bits LE
global P: [Field; 7] = [
    71776119061195435,
    72056156633169849,
    45307236177944235,
    68544734907805906,
    21300664356785028,
    64908892020651587,
    28591897852287
];

// RF-8: P_INV = -p^{-1} mod 2^56
global P_INV: u64 = 68679881432301565;

pub struct PrimeField {
    pub limbs: [Field; 7]
}

impl PrimeField {
    // CIOS Montgomery reduction: t (14 limbs) -> t * R^{-1} mod p (7 limbs)
    fn montgomery_reduce(t: [Field; 14]) -> Self {
        let limb_max: u128 = 72057594037927936; // 2^56
        let mut r: [u128; 15] = [0; 15];
        for k in 0..14 {
            r[k] = t[k] as u128;
        }
        let p: [u128; 7] = [
            P[0] as u128, P[1] as u128, P[2] as u128, P[3] as u128,
            P[4] as u128, P[5] as u128, P[6] as u128
        ];
        let p_inv: u128 = P_INV as u128;
        for i in 0..7 {
            let m: u128 = (r[i] * p_inv) % limb_max;
            let mut carry: u128 = 0;
            for j in 0..7 {
                let cur: u128 = r[i+j] + m * p[j] + carry;
                carry = cur / limb_max;
                r[i+j] = cur % limb_max;
            }
            r[i+7] = r[i+7] + carry;
        }
        let mut limbs: [Field; 7] = [0; 7];
        for k in 0..7 {
            limbs[k] = r[k+7] as Field;
        }
        PrimeField { limbs }
    }
}

// RF-8: R = 2^392 mod p en 7 limbs de 56 bits LE
global R_MOD_P: [Field; 7] = [
    60798595024551096,
    3622259990376729,
    37051381696303840,
    61378535280305823,
    5233379158039362,
    330574054414735,
    6011450162426
];

// RF-8: R2 = R^2 mod p en 7 limbs de 56 bits LE
global R2_MOD_P: [Field; 7] = [
    30711783484518637,
    66504807957151074,
    2589452219307610,
    26304752879875744,
    37819976824973938,
    71315239126305397,
    13801018140505
];

// RF-4: from_montgomery: PrimeField (montgomery) -> PrimeField (canonical)
// Computa t = self * 1 = self, luego reduce (elimina el factor R)
impl PrimeField {
    pub fn from_montgomery(self) -> PrimeField {
        let mut t: [Field; 14] = [0; 14];
        for i in 0..7 {
            t[i] = self.limbs[i];
        }
        PrimeField::montgomery_reduce(t)
    }

    // RF-4: to_montgomery: valor canonico -> forma Montgomery (multiplica por R2 via montgomery_reduce)
    pub fn to_montgomery(self) -> PrimeField {
        let limb_max: u128 = 72057594037927936; // 2^56
        let r2: [u128; 7] = [
            R2_MOD_P[0] as u128, R2_MOD_P[1] as u128, R2_MOD_P[2] as u128, R2_MOD_P[3] as u128,
            R2_MOD_P[4] as u128, R2_MOD_P[5] as u128, R2_MOD_P[6] as u128
        ];
        let a: [u128; 7] = [
            self.limbs[0] as u128, self.limbs[1] as u128, self.limbs[2] as u128, self.limbs[3] as u128,
            self.limbs[4] as u128, self.limbs[5] as u128, self.limbs[6] as u128
        ];
        let mut acc: [u128; 14] = [0; 14];
        for i in 0..7 {
            for j in 0..7 {
                acc[i+j] = acc[i+j] + a[i] * r2[j];
            }
        }
        let mut carry: u128 = 0;
        let mut wide: [Field; 14] = [0; 14];
        for k in 0..14 {
            let total: u128 = acc[k] + carry;
            carry = total / limb_max;
            wide[k] = (total % limb_max) as Field;
        }
        PrimeField::montgomery_reduce(wide)
    }
}

// RF-7: add, neg en Fp (operan sobre valores ya en forma Montgomery)
impl PrimeField {
    pub fn add(self, other: PrimeField) -> PrimeField {
        let limb_max: u64 = 72057594037927936; // 2^56
        let p: [u64; 7] = [
            P[0] as u64, P[1] as u64, P[2] as u64, P[3] as u64,
            P[4] as u64, P[5] as u64, P[6] as u64
        ];
        // suma con acarreo
        let mut limbs: [Field; 7] = [0; 7];
        let mut carry: u64 = 0;
        for i in 0..7 {
            let sum: u64 = self.limbs[i] as u64 + other.limbs[i] as u64 + carry;
            carry = sum / limb_max;
            limbs[i] = (sum % limb_max) as Field;
        }
        // resta condicional: limbs - P
        let mut sub_limbs: [Field; 7] = [0; 7];
        let mut borrow: u64 = 0;
        for i in 0..7 {
            let sub: u64 = limbs[i] as u64 + limb_max - p[i] - borrow;
            borrow = 1 - sub / limb_max;
            sub_limbs[i] = (sub % limb_max) as Field;
        }
        // usar original solo si no hubo carry Y hubo borrow (resultado < P)
        let use_original = (carry == 0) & (borrow == 1);
        let mut result: [Field; 7] = [0; 7];
        for i in 0..7 {
            result[i] = if use_original { limbs[i] } else { sub_limbs[i] };
        }
        PrimeField { limbs: result }
    }

    pub fn neg(self) -> PrimeField {
        let is_zero = (self.limbs[0] == 0) & (self.limbs[1] == 0) & (self.limbs[2] == 0) &
                      (self.limbs[3] == 0) & (self.limbs[4] == 0) & (self.limbs[5] == 0) &
                      (self.limbs[6] == 0);
        if is_zero {
            PrimeField { limbs: [0; 7] }
        } else {
            // P - self con sbb
            let limb_max: u64 = 72057594037927936;
            let p: [u64; 7] = [
                P[0] as u64, P[1] as u64, P[2] as u64, P[3] as u64,
                P[4] as u64, P[5] as u64, P[6] as u64
            ];
            let mut limbs: [Field; 7] = [0; 7];
            let mut borrow: u64 = 0;
            for i in 0..7 {
                let sub: u64 = p[i] + limb_max - self.limbs[i] as u64 - borrow;
                borrow = 1 - sub / limb_max;
                limbs[i] = (sub % limb_max) as Field;
            }
            PrimeField { limbs }
        }
    }

    pub fn mul(self, other: PrimeField) -> PrimeField {
        let limb_max: u128 = 72057594037927936; // 2^56
        let a: [u128; 7] = [
            self.limbs[0] as u128, self.limbs[1] as u128, self.limbs[2] as u128, self.limbs[3] as u128,
            self.limbs[4] as u128, self.limbs[5] as u128, self.limbs[6] as u128
        ];
        let b: [u128; 7] = [
            other.limbs[0] as u128, other.limbs[1] as u128, other.limbs[2] as u128, other.limbs[3] as u128,
            other.limbs[4] as u128, other.limbs[5] as u128, other.limbs[6] as u128
        ];
        let mut acc: [u128; 14] = [0; 14];
        for i in 0..7 {
            for j in 0..7 {
                acc[i+j] = acc[i+j] + a[i] * b[j];
            }
        }
        let mut carry: u128 = 0;
        let mut wide: [Field; 14] = [0; 14];
        for k in 0..14 {
            let total: u128 = acc[k] + carry;
            carry = total / limb_max;
            wide[k] = (total % limb_max) as Field;
        }
        PrimeField::montgomery_reduce(wide)
    }

    // RF-7: exp por cuadrado repetido, exponent como bits LSB-first de 381 bits
    pub fn exp(self, bits: [bool; 381]) -> PrimeField {
        // 1 en forma Montgomery = R_MOD_P
        let mut result = PrimeField { limbs: R_MOD_P };
        let mut base = self;
        for i in 0..381 {
            if bits[i] {
                result = result.mul(base);
            }
            base = base.mul(base);
        }
        result
    }

    pub fn eq(self, other: PrimeField) -> bool {
        (self.limbs[0] == other.limbs[0]) &
        (self.limbs[1] == other.limbs[1]) &
        (self.limbs[2] == other.limbs[2]) &
        (self.limbs[3] == other.limbs[3]) &
        (self.limbs[4] == other.limbs[4]) &
        (self.limbs[5] == other.limbs[5]) &
        (self.limbs[6] == other.limbs[6])
    }

    // inv via Fermat: a^(p-2) mod p; bits de p-2 en LSB-first
    pub fn inv(self) -> PrimeField {
        let bits: [bool; 381] = [
            // byte 0 = 0xa9
            true, false, false, true, false, true, false, true,
            // byte 1 = 0xaa
            false, true, false, true, false, true, false, true,
            // bytes 2-5 = 0xff
            true, true, true, true, true, true, true, true,
            true, true, true, true, true, true, true, true,
            true, true, true, true, true, true, true, true,
            true, true, true, true, true, true, true, true,
            // byte 6 = 0xfe
            false, true, true, true, true, true, true, true,
            // byte 7 = 0xb9
            true, false, false, true, true, true, false, true,
            // bytes 8-9 = 0xff
            true, true, true, true, true, true, true, true,
            true, true, true, true, true, true, true, true,
            // byte 10 = 0x53
            true, true, false, false, true, false, true, false,
            // byte 11 = 0xb1
            true, false, false, false, true, true, false, true,
            // byte 12 = 0xfe
            false, true, true, true, true, true, true, true,
            // byte 13 = 0xff
            true, true, true, true, true, true, true, true,
            // byte 14 = 0xab
            true, true, false, true, false, true, false, true,
            // byte 15 = 0x1e
            false, true, true, true, true, false, false, false,
            // byte 16 = 0x24
            false, false, true, false, false, true, false, false,
            // byte 17 = 0xf6
            false, true, true, false, true, true, true, true,
            // byte 18 = 0xb0
            false, false, false, false, true, true, false, true,
            // byte 19 = 0xf6
            false, true, true, false, true, true, true, true,
            // byte 20 = 0xa0
            false, false, false, false, false, true, false, true,
            // byte 21 = 0xd2
            false, true, false, false, true, false, true, true,
            // byte 22 = 0x30
            false, false, false, false, true, true, false, false,
            // byte 23 = 0x67
            true, true, true, false, false, true, true, false,
            // byte 24 = 0xbf
            true, true, true, true, true, true, false, true,
            // byte 25 = 0x12
            false, true, false, false, true, false, false, false,
            // byte 26 = 0x85
            true, false, true, false, false, false, false, true,
            // byte 27 = 0xf3
            true, true, false, false, true, true, true, true,
            // byte 28 = 0x84
            false, false, true, false, false, false, false, true,
            // byte 29 = 0x4b
            true, true, false, true, false, false, true, false,
            // byte 30 = 0x77
            true, true, true, false, true, true, true, false,
            // byte 31 = 0x64
            false, false, true, false, false, true, true, false,
            // byte 32 = 0xd7
            true, true, true, false, true, false, true, true,
            // byte 33 = 0xac
            false, false, true, true, false, true, false, true,
            // byte 34 = 0x4b
            true, true, false, true, false, false, true, false,
            // byte 35 = 0x43
            true, true, false, false, false, false, true, false,
            // byte 36 = 0xb6
            false, true, true, false, true, true, false, true,
            // byte 37 = 0xa7
            true, true, true, false, false, true, false, true,
            // byte 38 = 0x1b
            true, true, false, true, true, false, false, false,
            // byte 39 = 0x4b
            true, true, false, true, false, false, true, false,
            // byte 40 = 0x9a
            false, true, false, true, true, false, false, true,
            // byte 41 = 0xe6
            false, true, true, false, false, true, true, true,
            // byte 42 = 0x7f
            true, true, true, true, true, true, true, false,
            // byte 43 = 0x39
            true, false, false, true, true, true, false, false,
            // byte 44 = 0xea
            false, true, false, true, false, true, true, true,
            // byte 45 = 0x11
            true, false, false, false, true, false, false, false,
            // byte 46 = 0x01
            true, false, false, false, false, false, false, false,
            // byte 47 = 0x1a (5 bits)
            false, true, false, true, true
        ];
        self.exp(bits)
    }
}

#[test]
fn test_fp_exp_two_cubed() {
    // 2^3 = 8 en Fp; bits de 3 LSB-first = [1, 1, 0, ...]
    let mut bits: [bool; 381] = [false; 381];
    bits[0] = true;
    bits[1] = true;
    let two_mont = PrimeField { limbs: [2, 0, 0, 0, 0, 0, 0] }.to_montgomery();
    let result = two_mont.exp(bits);
    let canon = result.from_montgomery();
    assert(canon.limbs[0] == 8);
    assert(canon.limbs[1] == 0);
    assert(canon.limbs[6] == 0);
}

#[test]
fn test_fp_mul_one_times_one() {
    // 1 * 1 = 1 en Fp (en Montgomery form)
    let one_mont = PrimeField { limbs: [1, 0, 0, 0, 0, 0, 0] }.to_montgomery();
    let result = one_mont.mul(one_mont);
    let canon = result.from_montgomery();
    assert(canon.limbs[0] == 1);
    assert(canon.limbs[1] == 0);
    assert(canon.limbs[6] == 0);
}

#[test]
fn test_fp_mul_two_times_three() {
    // 2 * 3 = 6 en Fp
    let two_mont = PrimeField { limbs: [2, 0, 0, 0, 0, 0, 0] }.to_montgomery();
    let three_mont = PrimeField { limbs: [3, 0, 0, 0, 0, 0, 0] }.to_montgomery();
    let result = two_mont.mul(three_mont);
    let canon = result.from_montgomery();
    assert(canon.limbs[0] == 6);
    assert(canon.limbs[1] == 0);
    assert(canon.limbs[6] == 0);
}

#[test]
fn test_fp_add_one_plus_one() {
    let one = PrimeField { limbs: [1, 0, 0, 0, 0, 0, 0] };
    let a = one.to_montgomery();
    let two_mont = a.add(a);
    let two_mont_expected = PrimeField { limbs: [2, 0, 0, 0, 0, 0, 0] }.to_montgomery();
    assert(two_mont.limbs[0] == two_mont_expected.limbs[0]);
    assert(two_mont.limbs[6] == two_mont_expected.limbs[6]);
}

#[test]
fn test_fp_neg() {
    // neg(1) en Fp = p - 1; to_montgomery(p-1) + to_montgomery(1) debe dar 0 en Fp
    let one_mont = PrimeField { limbs: [1, 0, 0, 0, 0, 0, 0] }.to_montgomery();
    let neg_one = one_mont.neg();
    // neg de 1 en Montgomery debe ser != 1 en Montgomery (es p-1)
    assert(neg_one.limbs[0] != one_mont.limbs[0]);
    let sum = neg_one.add(one_mont);
    let sum_canon = sum.from_montgomery();
    assert(sum_canon.limbs[0] == 0);
    assert(sum_canon.limbs[6] == 0);
}

#[test]
fn test_to_from_montgomery_roundtrip() {
    // 1 en forma canonica -> to_montgomery -> from_montgomery debe volver a 1
    let one = PrimeField { limbs: [1, 0, 0, 0, 0, 0, 0] };
    let mont = one.to_montgomery();
    // mont.limbs debe ser R mod p
    assert(mont.limbs[0] == R_MOD_P[0]);
    assert(mont.limbs[6] == R_MOD_P[6]);
    let back = mont.from_montgomery();
    assert(back.limbs[0] == 1);
    assert(back.limbs[1] == 0);
    assert(back.limbs[6] == 0);
}

#[test]
fn test_montgomery_reduce_zero() {
    let result = PrimeField::montgomery_reduce([0; 14]);
    assert(result.limbs[0] == 0);
    assert(result.limbs[6] == 0);
}

impl PrimeField {
    // Decodifica 48 bytes LE en 7 limbs de 56 bits y convierte a forma Montgomery
    pub fn from_bytes(bytes: [u8; 48]) -> Self {
        let mut limbs: [Field; 7] = [0; 7];
        for i in 0..6 {
            let b = i * 7;
            limbs[i] = (bytes[b] as Field) + (bytes[b+1] as Field)*256 + (bytes[b+2] as Field)*65536 + (bytes[b+3] as Field)*16777216 + (bytes[b+4] as Field)*4294967296 + (bytes[b+5] as Field)*1099511627776 + (bytes[b+6] as Field)*281474976710656;
        }
        limbs[6] = (bytes[42] as Field) + (bytes[43] as Field)*256 + (bytes[44] as Field)*65536 + (bytes[45] as Field)*16777216 + (bytes[46] as Field)*4294967296 + (bytes[47] as Field)*1099511627776;
        PrimeField { limbs }.to_montgomery()
    }
}

#[test]
fn test_fp_from_bytes_one() {
    // bytes LE de 1: bytes[0]=1, resto 0
    let mut bytes: [u8; 48] = [0; 48];
    bytes[0] = 1;
    let fp = PrimeField::from_bytes(bytes);
    // en Montgomery form: fp.limbs debe ser R_MOD_P
    assert(fp.limbs[0] == R_MOD_P[0]);
    assert(fp.limbs[6] == R_MOD_P[6]);
}

#[test]
fn test_fp_from_bytes_roundtrip() {
    // from_bytes(1) -> from_montgomery debe dar 1
    let mut bytes: [u8; 48] = [0; 48];
    bytes[0] = 1;
    let fp = PrimeField::from_bytes(bytes);
    let canon = fp.from_montgomery();
    assert(canon.limbs[0] == 1);
    assert(canon.limbs[1] == 0);
    assert(canon.limbs[6] == 0);
}

// RF-6: to_bytes stub (RED)
impl PrimeField {
    // Convierte a canonico, serializa 7 limbs de 56 bits en 48 bytes LE
    fn to_bytes(self) -> [u8; 48] {
        let canon = self.from_montgomery();
        let mut bytes: [u8; 48] = [0; 48];
        for i in 0..6 {
            let limb: u64 = canon.limbs[i] as u64;
            for j in 0..7 {
                bytes[i * 7 + j] = ((limb >> ((j * 8) as u64)) & 0xff) as u8;
            }
        }
        let limb6: u64 = canon.limbs[6] as u64;
        for j in 0..6 {
            bytes[42 + j] = ((limb6 >> ((j * 8) as u64)) & 0xff) as u8;
        }
        bytes
    }

    // Convierte a bits LE (381 bits): usa to_bytes internamente
    fn to_bits(self) -> [bool; 381] {
        let bytes = self.to_bytes();
        let mut bits: [bool; 381] = [false; 381];
        for i in 0..47 {
            let b: u8 = bytes[i];
            for j in 0..8 {
                bits[i * 8 + j] = ((b >> (j as u8)) & 1) == 1;
            }
        }
        // byte 47: bits 376..381 (5 bits)
        let b47: u8 = bytes[47];
        for j in 0..5 {
            bits[376 + j] = ((b47 >> (j as u8)) & 1) == 1;
        }
        bits
    }
}

#[test]
fn test_fp_to_bytes_one() {
    // from_bytes(1) -> to_bytes debe dar bytes[0]=1, resto 0
    let mut bytes_in: [u8; 48] = [0; 48];
    bytes_in[0] = 1;
    let fp = PrimeField::from_bytes(bytes_in);
    let bytes_out = fp.to_bytes();
    assert(bytes_out[0] == 1);
    assert(bytes_out[1] == 0);
    assert(bytes_out[47] == 0);
}

#[test]
fn test_fp_to_bits_one() {
    // from_bytes(1) -> to_bits: bit[0]=true, resto false
    let mut bytes_in: [u8; 48] = [0; 48];
    bytes_in[0] = 1;
    let fp = PrimeField::from_bytes(bytes_in);
    let bits = fp.to_bits();
    assert(bits[0] == true);
    assert(bits[1] == false);
    assert(bits[380] == false);
}
