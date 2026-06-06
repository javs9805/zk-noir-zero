/// generate-noir-inputs: Lee data.json y genera Prover.toml + Verifier.toml
///
/// Uso: cargo run --bin generate-noir-inputs data.json ../noir-bls12-381-validator/Prover.toml

use bls12_381_plus::{G1Affine, G2Affine};
use std::path::PathBuf;

mod bls_utils;
mod domain;
mod beacon_client;

use bls_utils::{aggregate_g1, decompress_g2, hash_to_g2, g1_to_le_coords, g2_to_le_coords};
use domain::{compute_domain, compute_signing_root};
use beacon_client::{parse_fork_version, parse_g1_compressed, parse_g2_compressed,
    parse_root};

fn bytes_to_toml_array(bytes: &[u8]) -> String {
    let vals: Vec<String> = bytes.iter().map(|b| b.to_string()).collect();
    format!("[{}]", vals.join(", "))
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Uso: generate-noir-inputs <data.json> <Prover.toml>");
        std::process::exit(1);
    }

    let data_path = &args[1];
    let prover_path = PathBuf::from(&args[2]);
    let verifier_path = prover_path.parent().unwrap().join("Verifier.toml");

    let raw = std::fs::read_to_string(data_path)
        .unwrap_or_else(|_| panic!("No se puede leer {data_path}"));
    let data: serde_json::Value = serde_json::from_str(&raw).expect("parse data.json");

    // Parsear datos
    let gvr = parse_root(data["genesis_validators_root"].as_str().unwrap()).unwrap();
    let fork_version = parse_fork_version(data["fork_version"].as_str().unwrap()).unwrap();
    let parent_root = parse_root(data["parent_root"].as_str().unwrap()).unwrap();

    // Para reconstruir agg_pk y sig necesitamos las claves del data.json
    // data.json guarda signing_root directamente, y la firma + claves las parsea de nuevo
    // Alternativa: guardamos en data.json las coordenadas LE directamente
    // Por ahora data.json tiene signing_root precomputado y la firma comprimida

    let sig_compressed = parse_g2_compressed(
        data["sync_committee_signature"].as_str().unwrap()
    ).unwrap();
    let sig = decompress_g2(&sig_compressed).expect("decompress G2 sig");

    // Para agg_pk: data.json necesita tener las claves. Leer desde beacon si no están.
    // En esta version simplificada recalculamos desde data.json extendido (si existe).
    let agg_pk: G1Affine = if let Some(agg_hex) = data.get("agg_pubkey_compressed").and_then(|v| v.as_str()) {
        let compressed = parse_g1_compressed(agg_hex).unwrap();
        G1Affine::from_compressed(&compressed).unwrap()
    } else if let Some(keys_arr) = data.get("participant_pubkeys").and_then(|v| v.as_array()) {
        let compressed_keys: Vec<[u8; 48]> = keys_arr.iter().map(|k| {
            parse_g1_compressed(k.as_str().unwrap()).unwrap()
        }).collect();
        aggregate_g1(&compressed_keys).expect("aggregate G1")
    } else {
        panic!("data.json debe contener 'agg_pubkey_compressed' o 'participant_pubkeys'");
    };

    // RF-4: domain + signing_root
    let domain = compute_domain(fork_version, gvr);
    let signing_root = compute_signing_root(parent_root, domain);

    // RF-5: H(signing_root) via hash-to-curve
    let msg: G2Affine = hash_to_g2(&signing_root);

    // Extraer coordenadas LE
    let (pk_x, pk_y) = g1_to_le_coords(&agg_pk);
    let (sig_x_c0, sig_x_c1, sig_y_c0, sig_y_c1) = g2_to_le_coords(&sig);
    let (msg_x_c0, msg_x_c1, msg_y_c0, msg_y_c1) = g2_to_le_coords(&msg);

    // RF-7: Prover.toml
    let prover_content = format!(
        "pubkey_x = {}\n\
         pubkey_y = {}\n\
         sig_x_c0 = {}\n\
         sig_x_c1 = {}\n\
         sig_y_c0 = {}\n\
         sig_y_c1 = {}\n\
         msg_x_c0 = {}\n\
         msg_x_c1 = {}\n\
         msg_y_c0 = {}\n\
         msg_y_c1 = {}\n\
         genesis_validators_root = {}\n\
         fork_version = {}\n\
         parent_root = {}\n",
        bytes_to_toml_array(&pk_x),
        bytes_to_toml_array(&pk_y),
        bytes_to_toml_array(&sig_x_c0),
        bytes_to_toml_array(&sig_x_c1),
        bytes_to_toml_array(&sig_y_c0),
        bytes_to_toml_array(&sig_y_c1),
        bytes_to_toml_array(&msg_x_c0),
        bytes_to_toml_array(&msg_x_c1),
        bytes_to_toml_array(&msg_y_c0),
        bytes_to_toml_array(&msg_y_c1),
        bytes_to_toml_array(&gvr),
        bytes_to_toml_array(&fork_version),
        bytes_to_toml_array(&parent_root),
    );

    std::fs::write(&prover_path, &prover_content)
        .unwrap_or_else(|_| panic!("write {}", prover_path.display()));
    println!("[done] Prover.toml escrito en {}", prover_path.display());

    // RF-8: Verifier.toml
    let verifier_content = format!(
        "expected_signing_root = {}\n",
        bytes_to_toml_array(&signing_root),
    );
    std::fs::write(&verifier_path, &verifier_content)
        .unwrap_or_else(|_| panic!("write {}", verifier_path.display()));
    println!("[done] Verifier.toml escrito en {}", verifier_path.display());
}
