# Graph Report - .  (2026-06-05)

## Corpus Check
- Corpus is ~4,432 words - fits in a single context window. You may not need a graph.

## Summary
- 17 nodes · 23 edges · 5 communities detected
- Extraction: 100% EXTRACTED · 0% INFERRED · 0% AMBIGUOUS
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- [[_COMMUNITY_Community 0|Community 0]]
- [[_COMMUNITY_Community 1|Community 1]]
- [[_COMMUNITY_Community 2|Community 2]]
- [[_COMMUNITY_Community 3|Community 3]]
- [[_COMMUNITY_Community 4|Community 4]]

## God Nodes (most connected - your core abstractions)

## Surprising Connections (you probably didn't know these)
- `Fp2` --built_from--> `PrimeField (Fp)`  [EXTRACTED]
   →   _Bridges community 1 → community 2_
- `miller_loop()` --takes_input--> `G1Point (swcurve)`  [EXTRACTED]
   →   _Bridges community 1 → community 0_
- `verify_bls_signature()` --takes_input--> `G1Point (swcurve)`  [EXTRACTED]
   →   _Bridges community 1 → community 3_
- `G2Point` --coordinates_in--> `Fp2`  [EXTRACTED]
   →   _Bridges community 2 → community 3_
- `Fp12` --built_from--> `Fp6`  [EXTRACTED]
   →   _Bridges community 2 → community 0_

## Communities

### Community 0 - "Community 0"

Cohesion: 0.0
Nodes (4): Fp12, final_exp(), miller_loop(), pair()

### Community 1 - "Community 1"

Cohesion: 0.0
Nodes (4): BigUint56, G1Point (swcurve), PrimeField (Fp), montgomery_reduce()

### Community 2 - "Community 2"

Cohesion: 0.0
Nodes (3): Fp2, Fp6, mul_by_xi()

### Community 3 - "Community 3"

Cohesion: 0.0
Nodes (3): G2Point, README, verify_bls_signature()

### Community 4 - "Community 4"

Cohesion: 0.0
Nodes (2): noir_bigint_bls12_381, noir_bls_signature

## Knowledge Gaps
- **Thin community `Community 4`** (2 nodes): `noir_bigint_bls12_381`, `noir_bls_signature`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.