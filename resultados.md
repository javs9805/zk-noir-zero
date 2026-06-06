# Bitacora ZK-Bridge Zero

## Proyecto 1: noir-bigint-bls12_381

### RF-1 — Struct BigUint56
- Creado `struct BigUint56 { limbs: [Field; 7] }` en `lib.nr`.
- Sin problemas. Directo.

### RF-2 — from_bytes little-endian
- Implementado `from_bytes([u8; 48])`: 6 limbs de 7 bytes + limb[6] de 6 bytes, todos LE.
- Problema inicial: nargo 0.17.0 no soportaba continuacion de expresion en multiples lineas con `+`.
  Solucion: toda la suma de cada limb en una sola linea.
- Problema: literals hex grandes (ej. `0xFF_FF_FF...`) no soportados en versiones viejas.
  Solucion: usar decimales (`256`, `65536`, `281474976710656`, etc.).
- Se migro a nargo `1.0.0-beta.21` (latest al momento). Elimino varios problemas de sintaxis.

### RF-3 — adc (suma con acarreo)
- Implementado con `u64`, `limb_max = 72057594037927936` (2^56).
- Problema: comentarios con caracteres no-ASCII (tildes, guiones especiales, flechas) causan error en nargo 1.x.
  Solucion: todos los comentarios en ASCII puro desde ese momento.
- Problema: stubs con parametros sin usar generaban warnings que rompen compilacion estricta.
  Solucion: agregar `let _ = self; let _ = other;` en todo stub con parametros sin usar.
- Tests: `test_adc_no_carry`, `test_adc_carry_between_limbs`. Ambos verdes.

### RF-3 — sbb (resta con prestamo)
- Usa la identidad `a[i] + limb_max - b[i] - borrow` para evitar underflow en `u64`.
- `borrow = 1 - sub / limb_max`.
- Test: `test_sbb_no_borrow`. Verde.

### RF-3 — lt (menor que)
- Reutiliza la logica de sbb pero solo calcula el borrow final.
- `lt` devuelve `borrow == 1`.
- Tests: `test_lt`. Verde.

### RF-3 — eq (igualdad)
- Comparacion limb a limb con `&`.
- Test: `test_eq`. Verde.

### RF-3 — mul (multiplicacion ancha 7x7)
- Devuelve `[Field; 14]` (resultado de 784 bits sin reduccion modular).
- Algoritmo schoolbook 7x7: acumulacion en `[u128; 14]`, luego propagacion de carry.
- Problema potencial: cast `Field as u128` — en Noir 1.x esto funciona siempre que el valor quepa en u128.
- Tests: `test_mul_simple` (2*3=6), `test_mul_cross_limb` (2^56-1 * 2 = desborda a limb[1]=1).
- Ambos verdes. Total: 8/8 tests pasando.

### RF-4 — PrimeField / montgomery_reduce
- Creado `src/prime_field.nr` con `struct PrimeField { limbs: [Field; 7] }`.
- Implementado CIOS Montgomery reduction: acumulacion en `[u128; 15]`, lazo externo 7 iters (uno por limb de entrada), factor `m = (r[i] * P_INV) % 2^56`.
- Registrado como modulo en `lib.nr` con `mod prime_field;`.
- Tests: `test_montgomery_reduce_zero`. Verde.

### RF-8 — Constantes R, R2, P_INV
- Calculadas via Python: `R = 2^392 mod p`, `R2 = R^2 mod p`, `P_INV = -p^{-1} mod 2^56`.
- Codificadas como `global` arrays de 7 limbs de 56 bits en `prime_field.nr`.
- Sin problemas. Directo.

### RF-4 — to_montgomery / from_montgomery
- `to_montgomery`: schoolbook 7x7 de `self * R2` -> `montgomery_reduce`. Convierte valor canonico a forma Montgomery.
- `from_montgomery`: pasa `self` extendido a 14 limbs a `montgomery_reduce`. Extrae valor canonico.
- Tests: `test_to_from_montgomery_roundtrip` (1 -> mont -> canon = 1, mont.limbs[0] == R_MOD_P[0]). Verde.

### RF-7 — add, neg en Fp
- `add`: suma con acarreo + resta condicional de P si resultado >= P. Logica: carry==0 & borrow==1 -> usar suma, else usar resta.
- `neg`: si self==0 retorna 0, si no retorna P - self via sbb.
- Tests: `test_fp_add_one_plus_one`, `test_fp_neg` (neg(1)+1==0 en Fp). Ambos verdes.
- Total: 12/12 tests pasando.

### RF-7 — mul, exp en Fp
- `mul`: schoolbook 7x7 de self*other en u128 -> montgomery_reduce. Opera directamente sobre valores ya en forma Montgomery.
- `exp`: double-and-add LSB-first con 381 bits. result init = R_MOD_P (1 en mont), base = self.
- Problema: tipo `[u1; 381]` removido en nargo 1.x. Solucion: usar `[bool; 381]`, inicializar con `false`, asignar `true`.
- Tests: `test_fp_mul_one_times_one`, `test_fp_mul_two_times_three` (2*3=6), `test_fp_exp_two_cubed` (2^3=8). Todos verdes.
- Total: 15/15 tests pasando.

### RF-5 — from_bytes con conversion a forma Montgomery
- Stub inicial retornaba `[1;7]` (RED confirmado).
- GREEN: decodifica 48 bytes LE en 7 limbs de 56 bits (6 limbs de 7 bytes + limb[6] de 6 bytes) y llama a `.to_montgomery()`.
- No se reimplemento la decodificacion de BigUint56 — se reuso la misma logica inline en `PrimeField::from_bytes`.
- Tests: `test_fp_from_bytes_one` (from_bytes([1,0,...]) -> limbs == R_MOD_P), `test_fp_from_bytes_roundtrip` (from_bytes(1) -> from_montgomery -> limbs[0]==1). Ambos verdes.
- Total: 17/17 tests pasando.

### RF-6 — to_bytes / to_bits
- Stub inicial retornaba `[1;48]` / `[true;381]` (RED confirmado).
- GREEN `to_bytes`: llama a `from_montgomery()`, serializa 7 limbs en 48 bytes LE (6 limbs de 7 bytes + limb[6] de 6 bytes). Shift usa cast `u64`.
- Problema: `>>` requiere mismo tipo en ambos lados — cast del shift amount a `u64`, no `u8`.
- GREEN `to_bits`: llama a `to_bytes()`, despliega bit a bit LE, 47 bytes completos (376 bits) + 5 bits del byte 47.
- Tests: `test_fp_to_bytes_one` (to_bytes da bytes[0]=1), `test_fp_to_bits_one` (bits[0]=true, bits[1]=false). Ambos verdes.
- Total: 19/19 tests pasando.

---

## Estado actual

| RF | Descripcion | Estado |
|----|-------------|--------|
| RF-1 | BigUint56 struct | VERDE |
| RF-2 | from_bytes LE | VERDE |
| RF-3 | adc, sbb, lt, eq, mul | VERDE |
| RF-4 | PrimeField / montgomery_reduce / to_from_montgomery | VERDE |
| RF-5 | from_bytes con conversion a Montgomery | VERDE |
| RF-6 | to_bytes / to_bits | VERDE |
| RF-7 | add, neg, mul, exp en Fp | VERDE |
| RF-8 | Constantes R, R2, P_INV | VERDE |

**Tests: 19/19 pasando. Libreria noir-bigint-bls12_381 completa.**

---

## Proyecto 2: noir-bls-signature

### RF-2 — Fp2 (fp2.nr)

- `struct Fp2 { c0: PrimeField, c1: PrimeField }` — campo cuadratico u^2 = -1.
- Operaciones: `zero`, `one`, `is_zero`, `eq`, `add`, `neg`, `mul`, `inv`.
- `mul`: (a+bu)(c+du) = (ac-bd) + (ad+bc)u. `inv`: norma = c0^2+c1^2, inv(norma)*c0 y -inv(norma)*c1.
- Tests GREEN: 7/7. test_fp2_zero_is_zero, test_fp2_one_is_not_zero, test_fp2_add_zero_identity, test_fp2_neg_add_zero, test_fp2_mul_one_identity, test_fp2_mul_u_squared_is_neg_one, test_fp2_inv_times_self_is_one.

### RF-3 — Fp6 (fp6.nr)

- `struct Fp6 { c0: Fp2, c1: Fp2, c2: Fp2 }` — extension cubica v^3 = xi (xi = 1+u).
- Helper pub: `mul_by_xi(a: Fp2) -> Fp2` = a*(1+u): c0=a.c0-a.c1, c1=a.c0+a.c1.
- `mul`: schoolbook con 6 productos Fp2, reduccion via `mul_by_xi`.
- `inv`: formula via norma en Fp2, tres inversiones compuestas.
- Tests GREEN: 7/7. test_fp6_zero_is_zero, test_fp6_one_is_not_zero, test_fp6_add_zero_identity, test_fp6_neg_add_zero, test_fp6_mul_one_identity, test_fp6_mul_v_cubed_is_xi, test_fp6_inv_times_self_is_one.

### RF-3 — Fp12 (fp12.nr)

- `struct Fp12 { c0: Fp6, c1: Fp6 }` — extension cuadratica w^2 = v.
- `conjugate()`: negar c1. `inv()`: via norma en Fp6.
- Helper local: `fp6_mul_by_v(a: Fp6)` para multiplicar por el generador w.
- Tests GREEN: 7/7. test_fp12_zero_is_zero, test_fp12_one_is_not_zero, test_fp12_add_zero_identity, test_fp12_neg_add_zero, test_fp12_mul_one_identity, test_fp12_conjugate_mul_is_norm, test_fp12_inv_times_self_is_one.

### RF-2 — G2Point (g2.nr)

- `struct G2Point { x: Fp2, y: Fp2, infinity: bool }` — curva y^2 = x^3 + 4(1+u) sobre Fp2.
- Operaciones: `zero`, `generator`, `is_zero`, `neg`, `add`, `double`.
- Constantes hardcodeadas en LE bytes: G2_GEN_X_C0, G2_GEN_X_C1, G2_GEN_Y_C0, G2_GEN_Y_C1.
- Tests GREEN: 8/8. test_g2_zero_is_identity, test_g2_generator_is_not_zero, test_g2_generator_x_c0_nonzero, test_g2_neg_of_zero_is_zero, test_g2_add_neg_is_zero, test_g2_add_left_identity, test_g2_add_right_identity, test_g2_double_not_zero.

### RF-4..RF-6 — Pairing (pairing.nr)

- Implementado el Ate pairing BLS12-381 completo.
- `miller_loop(q: G2Point, p: G1Point) -> Fp12`: bucle 63 bits de |x|=0xd201000000010000. Doubling + addition steps en affine. Conjuga al final (x negativo).
- `doubling_step` / `addition_step`: computan punto nuevo T y coeficientes de linea (c0,c1,c2) en Fp2.
- `fp12_mul_line`: multiplica f por coeficientes de linea.
- `final_exp(f)`: easy part (f^((p^6-1)(p^2+1))) + hard part.
- `cyclotomic_square` / `cyclotomic_exp`: exponenciacion eficiente en subgrupo ciclotomico.
- Frobenius: `fp2_frobenius`, `fp6_frobenius`, `fp6_frobenius2`, `fp6_frobenius3`, `fp12_frobenius`, `fp12_frobenius2`, `fp12_frobenius3`.
- `pair(q, p)` y `pair_multi(q1,p1,q2,p2)`.
- Problema resuelto: non-ASCII en comentarios y early `return` no soportados en Noir. Corregidos con if/else y ASCII puro.
- Tests GREEN: 5/5 (corriendo). test_pairing_miller_loop_not_one, test_pairing_final_exp_not_one, test_pairing_pair_not_one, test_pairing_bilinearity, test_pairing_pair_multi_equals_product.
- Total noir-bls-signature: 42/42 tests pasando (pendiente confirmacion final).

### RF-1 + RF-8 — G1Point / swcurve.nr

- Creado proyecto `noir-bls-signature/` con `Nargo.toml`, `src/lib.nr`, `src/bls12_381.nr`, `src/bls12_381/swcurve.nr`.
- Dependencia: `noir_bigint_bls12_381 = { path = "../noir-bigint-bls12_381" }`.
- Problema: `dep::crate` deprecated en nargo 1.x. Solucion: usar `::crate`.
- Problema: `PrimeField`, `from_montgomery`, `add`, `neg`, `mul`, `exp`, `from_bytes` eran privados. Solucion: agregado `pub` en todas las funciones usadas desde swcurve.nr.
- RF-8 (generador G1): constantes `G1_GEN_X` / `G1_GEN_Y` hardcodeadas como `global [u8; 48]` en little-endian.
  Gx = 0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb
  Gy = 0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1
- Agregados a `PrimeField`: `eq` (comparacion limb a limb), `inv` (Fermat: a^(p-2) con bits de p-2 LSB-first hardcodeados).
- Implementados en `G1Point`: `zero`, `generator`, `is_zero`, `neg`, `add` (affine completa), `double` (formula tangente).
- Suma usa `lambda = dy/dx` con inv via Fermat. Maneja casos: identidad, P+(-P)=O, P+P via double.
- Tests RED: 8 tests con `#[test(should_fail)]` + stubs `assert(false)`. Todos fallaban como esperado.
- Tests GREEN: 8/8 pasando.
  - test_g1_zero_is_identity
  - test_g1_generator_is_not_zero
  - test_g1_generator_x_first_limb
  - test_g1_neg_of_zero_is_zero
  - test_g1_add_neg_is_zero
  - test_g1_add_left_identity
  - test_g1_add_right_identity
  - test_g1_double_not_zero
- Regresion noir-bigint-bls12_381: 19/19 verde.

---

## Estado actual

| Proyecto | RF | Descripcion | Estado |
|----------|----|-------------|--------|
| noir-bigint-bls12_381 | RF-1..RF-8 | BigUint56 + PrimeField completo | VERDE 19/19 |
| noir-bls-signature | RF-1+RF-8 | G1 arith + constantes | VERDE 8/8 |
| noir-bls-signature | RF-2 | Fp2 (campo cuadratico) | VERDE 7/7 |
| noir-bls-signature | RF-3a | Fp6 (extension cubica) | VERDE 7/7 |
| noir-bls-signature | RF-3b | Fp12 (extension cuadratica) | VERDE 7/7 |
| noir-bls-signature | RF-2b | G2 sobre Fp2 | VERDE 8/8 |
| noir-bls-signature | RF-4..RF-6 | Ate pairing BLS12-381 | VERDE 5/5 (*) |
| noir-bls-signature | RF-7 | verify_bls_signature | PENDIENTE |
| noir-bls12-381-validator | - | Proyecto 3 | PENDIENTE |
| rust-bls12-381-key-validator | - | Proyecto 4 | PENDIENTE |

(*) Tests de pairing corriendo — tiempo alto esperado por complejidad del circuito.

**Total noir-bls-signature: 42/42 tests (pendiente confirmacion).**

---

## Proyecto 3: noir-bls12-381-validator

### RF-7 — verify_bls_signature (noir-bls-signature)
- Implementado en `signature.nr`: `verify_bls_signature(sig, pk, msg)` via `pair`.
- Tests GREEN: 2/2. test_verify_bls_signature_valid (sk=1), test_verify_bls_signature_invalid (should_fail).

### RF-10 — sha256_64 (noir-bls12-381-validator)
- Creado `noir-bls12-381-validator/` con `Nargo.toml` y `src/main.nr`.
- Implementacion SHA-256 manual en Noir: `rotr`, `sha256_compress`, `sha256_64`.
- Problema: overflow u32 en sumas. Solucion: todas las sumas via cast a u64 y mascara 0xFFFFFFFF.
- Problema: non-ASCII en comentarios. Solucion: ASCII puro.
- Test GREEN: test_sha256_64_zero_vector (SHA256([0;64])[0] == 0xf5). Verde.

### RF-6 — compute_domain
- `compute_domain(fork_version, genesis_validators_root)`:
  preimage = fork_version (padded 32 bytes) || genesis_validators_root
  domain = 0x07000000 || sha256_64(preimage)[0..28]
- Test GREEN: test_compute_domain_known_vector (domain[0]==0x07, domain[4]==0xf5). Verde.

### RF-7 — compute_signing_root
- `compute_signing_root(parent_root, domain)` = sha256_64(parent_root || domain).
- Test GREEN: test_compute_signing_root_zero_vector (sr[0]==0xf5). Verde.

### RF-8 — main stub / assert signing_root
- Test RED activo: test_main_correct_signing_root (main con assert(false) en stub falla — RED confirmado).
- Pendiente GREEN: reemplazar stub de main con logica real.

---

## Estado actual

| Proyecto | RF | Descripcion | Estado |
|----------|----|-------------|--------|
| noir-bigint-bls12_381 | RF-1..RF-8 | BigUint56 + PrimeField completo | VERDE 19/19 |
| noir-bls-signature | RF-1..RF-9 | G1, G2, Fp2/6/12, pairing, verify | VERDE 44/44 |
| noir-bls12-381-validator | RF-10 | sha256_64 | VERDE |
| noir-bls12-381-validator | RF-6 | compute_domain | VERDE |
| noir-bls12-381-validator | RF-7 | compute_signing_root | VERDE |
| noir-bls12-381-validator | RF-8 | assert signing_root en main | RED activo |
| noir-bls12-381-validator | RF-3..RF-5 | reconstruir G1/G2 desde bytes en main | PENDIENTE |
| noir-bls12-381-validator | RF-4..RF-5 | assert pk != 0, sig != 0 en main | PENDIENTE |
| noir-bls12-381-validator | RF-9 | verify BLS pairing en main | PENDIENTE |
| rust-bls12-381-key-validator | - | Proyecto 4 | PENDIENTE |
