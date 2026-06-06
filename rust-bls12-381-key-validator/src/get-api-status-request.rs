use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::{env, error::Error, fs, time::{Duration, SystemTime, UNIX_EPOCH}};

const DEFAULT_BEACON_API_URL: &str = "https://ethereum-sepolia-beacon-api.publicnode.com";
const DEFAULT_OUTPUT_PATH: &str = "data.json";
const REQUEST_TIMEOUT_SECS: u64 = 30;
const SYNC_COMMITTEE_SIZE: usize = 512;

#[derive(Debug, Deserialize)]
struct BeaconResponse<T> {
    data: T,
}

#[derive(Debug, Deserialize)]
struct VersionData {
    version: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct SyncAggregate {
    sync_committee_bits: String,
    sync_committee_signature: String,
}

#[derive(Debug, Deserialize)]
struct BeaconBlockResponse {
    data: BeaconBlockData,
}

#[derive(Debug, Deserialize)]
struct BeaconBlockData {
    message: BeaconBlock,
}

#[derive(Debug, Deserialize)]
struct BeaconBlock {
    body: BeaconBlockBody,
}

#[derive(Debug, Deserialize)]
struct BeaconBlockBody {
    sync_aggregate: SyncAggregate,
}

#[derive(Debug, Deserialize)]
struct HeaderEnvelope {
    root: String,
    header: HeaderContainer,
}

#[derive(Debug, Deserialize)]
struct HeaderContainer {
    message: BlockHeader,
}

#[derive(Debug, Deserialize, Serialize)]
struct BlockHeader {
    slot: String,
    proposer_index: String,
    parent_root: String,
    state_root: String,
}

#[derive(Debug, Deserialize)]
struct SyncCommitteeData {
    validators: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct GenesisData {
    genesis_validators_root: String,
    genesis_fork_version: String,
}

#[derive(Debug, Deserialize)]
struct ForkData {
    previous_version: String,
    current_version: String,
    epoch: String,
}

#[derive(Debug, Deserialize)]
struct ValidatorInfo {
    validator: ValidatorData,
}

#[derive(Debug, Deserialize)]
struct ValidatorData {
    pubkey: String,
}

#[derive(Debug, Serialize)]
struct ParticipationData {
    participation: f64,
    #[serde(rename = "bitsArray")]
    bits_array: Vec<u8>,
    #[serde(rename = "totalParticipants")]
    total_participants: usize,
    #[serde(rename = "totalCommitteeSize")]
    total_committee_size: usize,
}

#[derive(Debug, Serialize)]
struct SyncCommitteeOutput {
    pubkeys: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    aggregate_pubkey: Option<String>,
}

#[derive(Debug, Serialize)]
struct BlockHeaderOutput {
    slot: String,
    proposer_index: String,
    parent_root: String,
    state_root: String,
    sync_aggregate: SyncAggregate,
}

#[derive(Debug, Serialize)]
struct BlockDataOutput {
    beacon_block_root: String,
    #[serde(rename = "parentRoot")]
    parent_root: String,
    sync_aggregate_signature: String,
    slot: u64,
}

#[derive(Debug, Serialize)]
struct GenesisInfo {
    #[serde(rename = "genesisValidatorsRoot")]
    genesis_validators_root: String,
    #[serde(rename = "genesisForkVersion")]
    genesis_fork_version: String,
}

#[derive(Debug, Serialize)]
struct ForkInfo {
    #[serde(rename = "previousVersion")]
    previous_version: String,
    #[serde(rename = "currentVersion")]
    current_version: String,
    epoch: String,
}

#[derive(Debug, Serialize)]
struct OutputData {
    timestamp: String,
    #[serde(rename = "beaconUrl")]
    beacon_url: String,
    #[serde(rename = "nodeVersion")]
    node_version: String,
    #[serde(rename = "blockRoot")]
    block_root: String,
    #[serde(rename = "blockHeader")]
    block_header: BlockHeaderOutput,
    participation: ParticipationData,
    #[serde(rename = "syncCommittee")]
    sync_committee: SyncCommitteeOutput,
    #[serde(rename = "validPublicKeys")]
    valid_public_keys: Vec<String>,
    #[serde(rename = "blockData")]
    block_data: BlockDataOutput,
    genesis: GenesisInfo,
    fork: ForkInfo,
}

fn decode_bits(bits_hex: &str) -> Result<(Vec<u8>, usize), Box<dyn Error>> {
    let clean = bits_hex.strip_prefix("0x").unwrap_or(bits_hex);
    let bytes = hex::decode(clean)?;

    let mut bits = Vec::with_capacity(SYNC_COMMITTEE_SIZE);
    for byte in bytes {
        for bit_index in 0..8 {
            bits.push((byte >> bit_index) & 1  );
        }
    }

    bits.truncate(SYNC_COMMITTEE_SIZE);
    let participants = bits.iter().map(|b| *b as usize).sum();
    Ok((bits, participants))
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() > 1 && (args[1] == "--help" || args[1] == "-h") {
        println!("Uso: {} [BEACON_URL] [OUTPUT_JSON]", args[0]);
        println!("  BEACON_URL  URL del Beacon API (opcional)");
        println!("              Por defecto: {}", DEFAULT_BEACON_API_URL);
        println!("  OUTPUT_JSON Ruta del JSON de salida (opcional)");
        println!("              Por defecto: {}", DEFAULT_OUTPUT_PATH);
        return Ok(());
    }

    let beacon_url = if args.len() > 1 {
        args[1].clone()
    } else {
        DEFAULT_BEACON_API_URL.to_string()
    };

    let output_path = if args.len() > 2 {
        args[2].clone()
    } else {
        DEFAULT_OUTPUT_PATH.to_string()
    };

    println!("Consultando Beacon API: {}", beacon_url);

    let client = Client::builder()
        .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
        .build()?;

    let version_url = format!("{}/eth/v1/node/version", beacon_url);
    let version_response: BeaconResponse<VersionData> = client.get(&version_url).send()?.error_for_status()?.json()?;

    let head_header_url = format!("{}/eth/v1/beacon/headers/head", beacon_url);
    let header_response: BeaconResponse<HeaderEnvelope> = client.get(&head_header_url).send()?.error_for_status()?.json()?;

    let head_block_url = format!("{}/eth/v2/beacon/blocks/head", beacon_url);
    let block_response: BeaconBlockResponse = client.get(&head_block_url).send()?.error_for_status()?.json()?;

    let genesis_url = format!("{}/eth/v1/beacon/genesis", beacon_url);
    let genesis_response: BeaconResponse<GenesisData> = client.get(&genesis_url).send()?.error_for_status()?.json()?;

    let fork_url = format!("{}/eth/v1/config/fork_schedule", beacon_url);
    let fork_response: BeaconResponse<Vec<ForkData>> = client.get(&fork_url).send()?.error_for_status()?.json()?;

    let sync_committee_url = format!("{}/eth/v1/beacon/states/head/sync_committees", beacon_url);
    let sync_response: BeaconResponse<SyncCommitteeData> = client.get(&sync_committee_url).send()?.error_for_status()?.json()?;

    let mut pubkeys = Vec::with_capacity(sync_response.data.validators.len());
    for validator_index_str in &sync_response.data.validators {
        let validator_url = format!(
            "{}/eth/v1/beacon/states/head/validators/{}",
            beacon_url, validator_index_str
        );

        let validator_response: BeaconResponse<ValidatorInfo> = client
            .get(&validator_url)
            .send()?
            .error_for_status()?
            .json()?;

        pubkeys.push(validator_response.data.validator.pubkey);
    }

    let block_root = header_response.data.root;
    let block_header = header_response.data.header.message;
    let sync_aggregate = block_response.data.message.body.sync_aggregate;

    let (bits_array, total_participants) = decode_bits(&sync_aggregate.sync_committee_bits)?;
    let participation = (total_participants as f64 / SYNC_COMMITTEE_SIZE as f64) * 100.0;

    let slot = block_header.slot.parse::<u64>().unwrap_or(0);

    // Determine the active fork for the current epoch (32 slots per epoch)
    let current_epoch = slot / 32;
    let active_fork = fork_response.data.iter().rfind(|f| f.epoch.parse::<u64>().unwrap_or(0) <= current_epoch)
        .unwrap_or(&fork_response.data[0]);

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

    let output = OutputData {
        timestamp: now.to_string(),
        beacon_url,
        node_version: version_response.data.version,
        block_root: block_root.clone(),
        block_header: BlockHeaderOutput {
            slot: block_header.slot,
            proposer_index: block_header.proposer_index,
            parent_root: block_header.parent_root.clone(),
            state_root: block_header.state_root,
            sync_aggregate: SyncAggregate {
                sync_committee_bits: sync_aggregate.sync_committee_bits.clone(),
                sync_committee_signature: sync_aggregate.sync_committee_signature.clone(),
            },
        },
        participation: ParticipationData {
            participation,
            bits_array,
            total_participants,
            total_committee_size: SYNC_COMMITTEE_SIZE,
        },
        sync_committee: SyncCommitteeOutput {
            pubkeys: pubkeys.clone(),
            aggregate_pubkey: None,
        },
        valid_public_keys: pubkeys,
        block_data: BlockDataOutput {
            beacon_block_root: block_root,
            parent_root: block_header.parent_root.clone(),
            sync_aggregate_signature: sync_aggregate.sync_committee_signature,
            slot,
        },
        genesis: GenesisInfo {
            genesis_validators_root: genesis_response.data.genesis_validators_root,
            genesis_fork_version: genesis_response.data.genesis_fork_version,
        },
        fork: ForkInfo {
            previous_version: active_fork.previous_version.clone(),
            current_version: active_fork.current_version.clone(),
            epoch: active_fork.epoch.clone(),
        },
    };

    let json = serde_json::to_string_pretty(&output)?;
    fs::write(&output_path, json)?;

    println!("JSON guardado en: {}", output_path);
    println!("Sync Committee: {} claves", output.sync_committee.pubkeys.len());
    println!("Participación: {:.2}%", output.participation.participation);

    Ok(())
}
