# ZK-Bridge — Validación ZK del Sync Committee de Ethereum

Este repositorio contiene el stack completo para demostrar en zero-knowledge que el **Sync Committee de Ethereum firmó un bloque de la Beacon Chain**, usando la curva **BLS12-381** y el lenguaje de circuitos **Noir**.

---

## Arquitectura general

```
rust-bls12-381-key-validator/      ← Herramienta Rust (off-chain)
  ├── beacon_client.rs             Consulta el Beacon Node API (Sepolia/Mainnet)
  ├── key-validator.rs             Verifica firmas BLS en Rust (referencia)
  └── generate-noir-inputs.rs      Genera Prover.toml para el circuito Noir

noir-bigint-bls12_381/             ← Librería Noir (capa 1)
  └── src/
      ├── lib.nr                   BigUint56: enteros grandes de 7 × 56 bits
      ├── prime_field.nr           PrimeField (Fp): aritmética modular en Montgomery form
      └── utils.nr                 Utilidades de bajo nivel (adc, sbb, bits, bytes)

noir-bls-signature/                ← Librería Noir (capa 2)
  └── src/bls12_381/
      ├── swcurve.nr               Curva G1 (Short Weierstrass sobre Fp)
      ├── fp2.nr / fp6.nr /fp12.nr Extensiones de campo Fp2, Fp6, Fp12
      ├── g2.nr                    Curva G2 (sobre Fp2)
      ├── pairing.nr               Emparejamiento de Ate (Miller loop + exp. final)
      ├── signature.nr             verify_bls_signature()
      └── constants.nr             Constantes de la curva

noir-bls12-381-validator/          ← Circuito ZK principal (capa 3)
  └── src/main.nr                  Circuito que prueba la validez del comité
```

El flujo de datos es: **Beacon API → Rust (genera inputs) → Noir (circuito ZK) → proof**.

---

## Proyecto 1: `noir-bigint-bls12_381`

### Descripción

Librería de aritmética de enteros grandes para Noir, especializada para la curva **BLS12-381**. Implementa el tipo `BigUint56` (384 bits representados en 7 limbs de 56 bits cada uno) y, sobre él, el tipo `PrimeField` que trabaja en **forma de Montgomery** para hacer la multiplicación modular eficiente dentro de circuitos ZK.

### Requerimientos funcionales

| # | Requerimiento |
|---|--------------|
| RF-1 | Representar enteros de hasta 392 bits (7 limbs × 56 bits) con el tipo `BigUint56`. |
| RF-2 | Convertir `BigUint56` desde/hacia arrays de bytes en **little-endian** (48 bytes para BLS12-381). |
| RF-3 | Implementar suma con acarreo (`adc`), resta con préstamo (`sbb`), multiplicación y comparación (`lt`, `eq`) sobre `BigUint56`. |
| RF-4 | Implementar `PrimeField` (Fp) usando la **representación de Montgomery** con la prima `p` de BLS12-381. |
| RF-5 | Proveer `from_bytes` / `from_bytes_48` que validen que el valor sea menor que `p` y lo conviertan a Montgomery form. |
| RF-6 | Proveer `to_bytes` / `to_bits` que saquen el valor canónico (fuera de Montgomery form). |
| RF-7 | Implementar suma (`add`), negación (`neg`), multiplicación (`mul`) y exponenciación en Fp, todos con reducción modular correcta. |
| RF-8 | Exponer las constantes `R`, `R2` y `P_INV` necesarias para Montgomery. |

### Estructura de archivos clave

- [noir-bigint-bls12_381/src/lib.nr](noir-bigint-bls12_381/src/lib.nr) — `BigUint56`, constructores, serialización
- [noir-bigint-bls12_381/src/prime_field.nr](noir-bigint-bls12_381/src/prime_field.nr) — `PrimeField`, Montgomery, operaciones de campo
- [noir-bigint-bls12_381/src/utils.nr](noir-bigint-bls12_381/src/utils.nr) — helpers de bits y bytes

---

## Proyecto 2: `noir-bls-signature`

### Descripción

Librería Noir que implementa la curva elíptica **BLS12-381** completa, incluyendo los grupos G1 y G2, las extensiones de campo Fp2/Fp6/Fp12, el **emparejamiento de Ate** y la verificación de firmas BLS. Depende de `noir-bigint-bls12_381` para la aritmética de campo base.

### Requerimientos funcionales

| # | Requerimiento |
|---|--------------|
| RF-1 | Implementar aritmética de puntos en **G1** (curva Short Weierstrass sobre Fp): suma, duplicación, negación, punto en el infinito. |
| RF-2 | Implementar aritmética de puntos en **G2** (curva Short Weierstrass sobre Fp2): mismas operaciones que G1. |
| RF-3 | Implementar la torre de extensiones de campo **Fp2 → Fp6 → Fp12** con sus operaciones algebraicas completas. |
| RF-4 | Implementar el **emparejamiento de Ate** (Miller loop + exponenciación final) sobre BLS12-381. |
| RF-5 | Exponer `pair(G2Point, G1Point) -> Fp12` para emparejamientos individuales. |
| RF-6 | Exponer `pair_multi(G2, G1, G2, G1) -> Fp12` para el producto de dos emparejamientos en una sola exponenciación final (optimización). |
| RF-7 | Implementar `verify_bls_signature(signature: G2Point, public_key: G1Point, message_hash: G2Point)` que verifique `e(σ, G1_gen) == e(H(m), pk)`. |
| RF-8 | Incluir los parámetros del generador G1 y G2 de BLS12-381 hardcodeados como constantes verificadas. |
| RF-9 | Incluir tests unitarios para operaciones básicas de curva (suma de puntos, multiplicación escalar, emparejamiento). |

### Estructura de archivos clave

- [noir-bls-signature/src/bls12_381/swcurve.nr](noir-bls-signature/src/bls12_381/swcurve.nr) — Curva G1
- [noir-bls-signature/src/bls12_381/g2.nr](noir-bls-signature/src/bls12_381/g2.nr) — Curva G2
- [noir-bls-signature/src/bls12_381/fp2.nr](noir-bls-signature/src/bls12_381/fp2.nr) — Campo Fp2
- [noir-bls-signature/src/bls12_381/fp6.nr](noir-bls-signature/src/bls12_381/fp6.nr) — Campo Fp6
- [noir-bls-signature/src/bls12_381/fp12.nr](noir-bls-signature/src/bls12_381/fp12.nr) — Campo Fp12 + identidad
- [noir-bls-signature/src/bls12_381/pairing.nr](noir-bls-signature/src/bls12_381/pairing.nr) — Emparejamiento de Ate
- [noir-bls-signature/src/bls12_381/signature.nr](noir-bls-signature/src/bls12_381/signature.nr) — `verify_bls_signature()`

---

## Proyecto 3: `noir-bls12-381-validator`

### Descripción

**Circuito ZK principal.** Demuestra en zero-knowledge que el Sync Committee de Ethereum firmó un bloque específico de la Beacon Chain. El circuito toma como entradas privadas la clave pública agregada G1, la firma agregada G2 y el punto G2 resultado del hash-to-curve, y como entrada pública el `signing_root` esperado. Internamente reconstruye el dominio Ethereum, el `signing_root` vía SHA-256, y verifica la firma BLS mediante emparejamiento bilineal.

### Requerimientos funcionales

| # | Requerimiento |
|---|--------------|
| RF-1 | Aceptar como **entradas privadas** (witness): `pubkey_x/y` (G1, 48 bytes LE), `sig_x/y_c0/c1` (G2, 4 × 48 bytes LE), `msg_x/y_c0/c1` (H(signing_root) en G2, 4 × 48 bytes LE), `genesis_validators_root` (32 bytes), `fork_version` (4 bytes), `parent_root` (32 bytes). |
| RF-2 | Aceptar como **entrada pública**: `expected_signing_root` (32 bytes). |
| RF-3 | Reconstruir el punto G1 (clave pública) y el punto G2 (firma) desde sus bytes LE, usando `Fp::from_bytes_48`. |
| RF-4 | Verificar que la clave pública G1 **no es el punto identidad** (`!public_key.is_zero()`). |
| RF-5 | Verificar que la firma G2 **no es el punto identidad** (`!signature.is_zero()`). |
| RF-6 | Computar el **dominio Ethereum**: `domain = DOMAIN_SYNC_COMMITTEE (0x07000000) ∥ SHA256(fork_version_pad32 ∥ genesis_validators_root)[0..28]`. |
| RF-7 | Computar el **signing_root**: `signing_root = SHA256(parent_root ∥ domain)`. |
| RF-8 | **Anclar el signing_root al valor público**: `assert(signing_root == expected_signing_root)`. Esto garantiza que el prover usó los datos correctos de la chain. |
| RF-9 | Verificar la firma BLS mediante el emparejamiento: `e(σ, G1_gen) · e(-H(m), pk) == Fp12::one()` usando `pair_multi`. |
| RF-10 | Implementar `sha256` interna para exactamente 64 bytes de entrada (dos bloques de compresión SHA-256 estándar). |

### Entradas del circuito

```toml
# Entradas privadas
pubkey_x         = [u8; 48]   # coord X de la clave G1 (little-endian)
pubkey_y         = [u8; 48]   # coord Y de la clave G1 (little-endian)
sig_x_c0         = [u8; 48]   # Fp2.x.c0 de la firma G2
sig_x_c1         = [u8; 48]   # Fp2.x.c1 de la firma G2
sig_y_c0         = [u8; 48]   # Fp2.y.c0 de la firma G2
sig_y_c1         = [u8; 48]   # Fp2.y.c1 de la firma G2
msg_x_c0         = [u8; 48]   # H(signing_root) G2 — Fp2.x.c0
msg_x_c1         = [u8; 48]   # H(signing_root) G2 — Fp2.x.c1
msg_y_c0         = [u8; 48]   # H(signing_root) G2 — Fp2.y.c0
msg_y_c1         = [u8; 48]   # H(signing_root) G2 — Fp2.y.c1
genesis_validators_root = [u8; 32]
fork_version     = [u8; 4]
parent_root      = [u8; 32]

# Entrada pública
expected_signing_root = pub [u8; 32]
```

### Estructura de archivos clave

- [noir-bls12-381-validator/src/main.nr](noir-bls12-381-validator/src/main.nr) — Circuito completo
- [noir-bls12-381-validator/Prover.toml](noir-bls12-381-validator/Prover.toml) — Inputs de ejemplo (Sepolia)
- [noir-bls12-381-validator/Verifier.toml](noir-bls12-381-validator/Verifier.toml) — Input público para verificación
- [noir-bls12-381-validator/Nargo.toml](noir-bls12-381-validator/Nargo.toml) — Dependencias del circuito

---

## Proyecto 4: `rust-bls12-381-key-validator`

### Descripción

Herramienta Rust **off-chain** que actúa como capa de preparación de datos. Se conecta al Beacon Node API de Ethereum, descarga los datos del Sync Committee y del bloque actual, verifica la firma BLS en Rust (como referencia), y genera automáticamente el `Prover.toml` y `Verifier.toml` listos para ejecutar el circuito Noir.

### Requerimientos funcionales

| # | Requerimiento |
|---|--------------|
| RF-1 | Conectarse al **Beacon Node API** (configurable: Sepolia/Mainnet) y obtener: sync committee (pubkeys + bits de participación), bloque actual (slot, parent_root, sync_aggregate_signature), genesis (genesisValidatorsRoot), fork (currentVersion). |
| RF-2 | **Agregar las claves G1** de los validadores participantes (filtrando por bits de participación = 1) para obtener la clave pública agregada del comité. |
| RF-3 | Descomprimir la firma G2 agregada (96 bytes big-endian) en sus coordenadas afines Fp2. |
| RF-4 | Calcular `domain` y `signing_root` con la misma lógica que el circuito Noir (SHA-256, DOMAIN_SYNC_COMMITTEE). |
| RF-5 | Calcular `H(signing_root)` via **Hash-to-Curve G2** con DST `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_` (IETF RFC 9380). |
| RF-6 | Verificar la firma BLS en Rust (`e(G1_gen, σ) == e(pk, H(m))`) para confirmar que los datos son válidos antes de pasarlos al circuito. |
| RF-7 | Generar `Prover.toml` con **todos los bytes en little-endian** (nota: `bls12_381_plus` devuelve big-endian, hay que revertir cada array de 48 bytes). |
| RF-8 | Generar `Verifier.toml` con el `expected_signing_root` en bytes. |
| RF-9 | Guardar `data.json` con todos los datos crudos de la API para reproducibilidad y debugging. |

---

## Flujo completo de ejecución

### Prerrequisitos

```bash
# Noir / Nargo
curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash
noirup                          # instala la última versión estable de nargo

# Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Backend de pruebas (barretenberg)
nargo backend install aztec-barretenberg
```

### Paso 1 — Obtener datos de la Beacon Chain y generar inputs

```bash
cd rust-bls12-381-key-validator

# Descarga datos en vivo del Beacon Node y los guarda en data.json
cargo run --bin key-validator

# A partir de data.json, genera Prover.toml y Verifier.toml para el circuito
cargo run --bin generate-noir-inputs \
    data.json \
    ../noir-bls12-381-validator/Prover.toml
```

Este paso:
1. Consulta `GET /eth/v1/beacon/states/head/sync_committees`
2. Consulta `GET /eth/v1/beacon/headers/head`
3. Agrega las claves G1 de los participantes → `pubkey_x/y`
4. Descomprime la firma G2 → `sig_x/y_c0/c1`
5. Calcula `domain` y `signing_root` (SHA-256)
6. Calcula `H(signing_root)` via hash-to-curve → `msg_x/y_c0/c1`
7. Escribe `Prover.toml` con todos los valores en bytes LE y `Verifier.toml` con el `expected_signing_root`

### Paso 2 — Compilar el circuito Noir

```bash
cd ../noir-bls12-381-validator

nargo compile
```

Esto compila el circuito y genera el artefacto en `target/bls12_381_validator.json`.

### Paso 3 — Generar la prueba ZK

```bash
nargo prove
```

Nargo lee `Prover.toml`, ejecuta el circuito y genera la prueba en `proofs/bls12_381_validator.proof`.

El circuito ejecuta internamente:
1. Reconstruye G1 y G2 desde bytes LE
2. Verifica que pk ≠ identidad y sig ≠ identidad
3. Calcula `domain = 0x07000000 ∥ SHA256(fork_version_pad32 ∥ gvr)[0..28]`
4. Calcula `signing_root = SHA256(parent_root ∥ domain)`
5. Compara `signing_root == expected_signing_root` (ancla los datos a la entrada pública)
6. Verifica `e(σ, G1_gen) · e(-H(m), pk) == Fp12::one()`

### Paso 4 — Verificar la prueba

```bash
nargo verify
```

Nargo lee `Verifier.toml` (que solo contiene `expected_signing_root`) y la prueba generada, y confirma que la prueba es válida sin revelar ninguna de las entradas privadas.

---

## Diagrama del flujo criptográfico

```
Beacon Chain (Sepolia/Mainnet)
        │
        ▼
rust: key-validator          Agrega claves G1 participantes
        │                    Descomprime firma G2
        │                    SHA256 → domain → signing_root
        │                    Hash-to-Curve G2 → H(signing_root)
        ▼
Prover.toml  ←────────────── generate-noir-inputs
Verifier.toml

        │
        ▼
noir-bls12-381-validator/src/main.nr (circuito ZK)
        │
        ├─ [privado] pubkey (G1) ───────────── assert(!pk.is_zero())
        ├─ [privado] sig (G2) ──────────────── assert(!sig.is_zero())
        ├─ [privado] genesis + fork + parent → SHA256 × 2 → signing_root
        ├─ [público] expected_signing_root ─── assert(computed == expected)
        └─ [privado] H(signing_root) en G2 ─── pair_multi(sig, G1_gen, -H(m), pk) == Fp12::one()
        │
        ▼
  proof (zero-knowledge)
        │
        ▼
  nargo verify → ✓ El comité firmó el bloque sin revelar las claves
```

---

## Consideraciones importantes para el rediseño

### Endianness
`bls12_381_plus` (Rust) serializa coordenadas en **big-endian**. El circuito Noir espera **little-endian**. El generador de inputs (`generate-noir-inputs.rs`) debe revertir cada array de 48 bytes antes de escribirlo en `Prover.toml`.

### Hash-to-Curve no está en Noir
La función `H(signing_root)` que mapea el `signing_root` a un punto G2 (usando SSWU + SHA-256 con DST IETF) **no existe en Noir**. El punto G2 resultante se pre-calcula en Rust y se pasa como entrada privada. El verificador confía en que `expected_signing_root` ancla correctamente el mensaje — si el prover usa un punto G2 incorrecto, la verificación de emparejamiento fallará.

### Versión de Nargo
El circuito requiere `compiler_version = "LATEST"`. Usar `nargo --version` para confirmar compatibilidad.

### Optimización con `pair_multi`
En lugar de calcular dos emparejamientos separados y compararlos, se usa `pair_multi(σ, G1_gen, -H(m), pk)` que combina ambos en una sola exponenciación final de Fp12, reduciendo ~8 millones de gates.

### DST de Ethereum
El Domain Separation Tag es `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`. Este DST es específico del consenso de Ethereum y debe coincidir exactamente entre Rust y cualquier herramienta externa que calcule H(m).
