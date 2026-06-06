mod beacon_client;
mod bls_utils;
mod domain;

use beacon_client::{
    parse_fork_version, parse_g1_compressed, parse_g2_compressed, parse_participation_bits,
    parse_root, BeaconClient,
};
use bls_utils::{aggregate_g1, decompress_g2, hash_to_g2, verify_bls};
use domain::{compute_domain, compute_signing_root};
use serde_json::json;

const DEFAULT_BEACON_URL: &str = "https://lodestar-sepolia.chainsafe.io";

fn main() {
    let base_url = std::env::var("BEACON_URL").unwrap_or_else(|_| DEFAULT_BEACON_URL.to_string());
    println!("[key-validator] Beacon URL: {base_url}");

    let client = BeaconClient::new(&base_url);

    // RF-1: Consultar genesis, fork, header, sync_aggregate
    println!("[1/6] Consultando genesis...");
    let genesis = client.get_genesis().expect("genesis request failed");
    let gvr = parse_root(&genesis.genesis_validators_root).expect("parse genesis_validators_root");

    println!("[2/6] Consultando fork del estado head...");
    let fork = client.get_fork("head").expect("fork request failed");
    let fork_version = parse_fork_version(&fork.current_version).expect("parse fork_version");

    println!("[3/6] Consultando beacon header head...");
    let header = client.get_beacon_header("head").expect("header request failed");
    let parent_root = parse_root(&header.parent_root).expect("parse parent_root");
    let slot = header.slot.clone();
    println!("    slot={slot}, parent_root={}", &header.parent_root[..10]);

    println!("[4/6] Consultando sync_aggregate del bloque head...");
    let sync_agg = client.get_sync_aggregate("head").expect("sync_aggregate request failed");

    println!("[5/6] Consultando validadores del sync committee...");
    let validator_indices = client
        .get_sync_committee_validators("head")
        .expect("sync_committee request failed");

    let participation = parse_participation_bits(&sync_agg.sync_committee_bits);

    // RF-2: Agregar claves G1 de participantes
    println!("[6/6] Agregando claves G1...");
    let mut compressed_keys: Vec<[u8; 48]> = Vec::new();
    for (i, idx) in validator_indices.iter().enumerate() {
        let participates = participation.get(i).copied().unwrap_or(false);
        if participates {
            let pubkey_hex = client
                .get_validator_pubkey(idx)
                .expect("validator pubkey request failed");
            let key = parse_g1_compressed(&pubkey_hex).expect("parse validator pubkey");
            compressed_keys.push(key);
        }
    }

    println!("    Participantes: {}/{}", compressed_keys.len(), validator_indices.len());

    let agg_pk = aggregate_g1(&compressed_keys).expect("aggregate G1 failed");

    // RF-3: Descomprimir firma G2
    let sig_compressed = parse_g2_compressed(&sync_agg.sync_committee_signature)
        .expect("parse sync_committee_signature");
    let sig = decompress_g2(&sig_compressed).expect("decompress G2 signature failed");

    // RF-4: Calcular domain y signing_root
    let domain = compute_domain(fork_version, gvr);
    let signing_root = compute_signing_root(parent_root, domain);

    // RF-5: Hash-to-curve H(signing_root)
    let msg = hash_to_g2(&signing_root);

    // RF-6: Verificar firma BLS en Rust
    println!("[verify] Verificando firma BLS...");
    let valid = verify_bls(sig, agg_pk, msg);
    println!("[verify] Resultado: {}", if valid { "VALIDA" } else { "INVALIDA" });

    // RF-9: Guardar data.json
    let data = json!({
        "slot": slot,
        "parent_root": header.parent_root,
        "genesis_validators_root": genesis.genesis_validators_root,
        "fork_version": fork.current_version,
        "sync_committee_bits": sync_agg.sync_committee_bits,
        "sync_committee_signature": sync_agg.sync_committee_signature,
        "participant_count": compressed_keys.len(),
        "signing_root": hex::encode(signing_root),
        "bls_valid": valid,
    });

    let json_path = "data.json";
    std::fs::write(json_path, serde_json::to_string_pretty(&data).unwrap())
        .expect("write data.json");
    println!("[done] data.json guardado.");
}
