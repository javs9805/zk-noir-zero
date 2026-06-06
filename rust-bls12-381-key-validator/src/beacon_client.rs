use reqwest::blocking::Client;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct SyncCommitteeResponse {
    data: SyncCommitteeData,
}

#[derive(Debug, Deserialize)]
struct SyncCommitteeData {
    validators: Vec<String>,
    validator_aggregates: Option<Vec<serde_json::Value>>,
}

#[derive(Debug, Deserialize)]
struct BeaconHeaderResponse {
    data: BeaconHeaderData,
}

#[derive(Debug, Deserialize)]
struct BeaconHeaderData {
    header: BeaconHeaderMessage,
}

#[derive(Debug, Deserialize)]
pub struct BeaconHeaderMessage {
    pub message: BeaconBlockHeader,
}

#[derive(Debug, Deserialize)]
pub struct BeaconBlockHeader {
    pub slot: String,
    pub parent_root: String,
    pub state_root: String,
    pub body_root: String,
}

#[derive(Debug, Deserialize)]
struct GenesisResponse {
    data: GenesisData,
}

#[derive(Debug, Deserialize)]
pub struct GenesisData {
    pub genesis_validators_root: String,
}

#[derive(Debug, Deserialize)]
struct ForkResponse {
    data: ForkData,
}

#[derive(Debug, Deserialize)]
pub struct ForkData {
    pub current_version: String,
}

#[derive(Debug, Deserialize)]
struct ValidatorResponse {
    data: ValidatorData,
}

#[derive(Debug, Deserialize)]
struct ValidatorData {
    validator: ValidatorInfo,
}

#[derive(Debug, Deserialize)]
struct ValidatorInfo {
    pubkey: String,
}

#[derive(Debug, Deserialize)]
struct SignedBeaconBlock {
    data: SignedBeaconBlockData,
}

#[derive(Debug, Deserialize)]
struct SignedBeaconBlockData {
    message: BeaconBlockBody,
}

#[derive(Debug, Deserialize)]
struct BeaconBlockBody {
    body: BeaconBodyContents,
}

#[derive(Debug, Deserialize)]
struct BeaconBodyContents {
    sync_aggregate: SyncAggregate,
}

#[derive(Debug, Deserialize)]
pub struct SyncAggregate {
    pub sync_committee_bits: String,
    pub sync_committee_signature: String,
}

pub struct BeaconClient {
    client: Client,
    base_url: String,
}

impl BeaconClient {
    pub fn new(base_url: &str) -> Self {
        Self {
            client: Client::new(),
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    fn get<T: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<T, String> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .client
            .get(&url)
            .header("Accept", "application/json")
            .send()
            .map_err(|e| format!("request error: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("HTTP {} for {url}", resp.status()));
        }
        resp.json::<T>().map_err(|e| format!("json parse error: {e}"))
    }

    pub fn get_genesis(&self) -> Result<GenesisData, String> {
        let r: GenesisResponse = self.get("/eth/v1/beacon/genesis")?;
        Ok(r.data)
    }

    pub fn get_fork(&self, state_id: &str) -> Result<ForkData, String> {
        let r: ForkResponse = self.get(&format!("/eth/v1/beacon/states/{state_id}/fork"))?;
        Ok(r.data)
    }

    pub fn get_sync_committee_validators(&self, state_id: &str) -> Result<Vec<String>, String> {
        let r: SyncCommitteeResponse =
            self.get(&format!("/eth/v1/beacon/states/{state_id}/sync_committees"))?;
        Ok(r.data.validators)
    }

    pub fn get_beacon_header(&self, block_id: &str) -> Result<BeaconBlockHeader, String> {
        let r: BeaconHeaderResponse =
            self.get(&format!("/eth/v1/beacon/headers/{block_id}"))?;
        Ok(r.data.header.message)
    }

    pub fn get_sync_aggregate(&self, block_id: &str) -> Result<SyncAggregate, String> {
        let r: SignedBeaconBlock =
            self.get(&format!("/eth/v2/beacon/blocks/{block_id}"))?;
        Ok(r.data.message.body.sync_aggregate)
    }

    pub fn get_validator_pubkey(&self, validator_index: &str) -> Result<String, String> {
        let r: ValidatorResponse =
            self.get(&format!("/eth/v1/beacon/states/head/validators/{validator_index}"))?;
        Ok(r.data.validator.pubkey)
    }
}

/// Parsea bits de participacion del sync committee (bitvector hex o SSZ bytes).
/// Retorna vec<bool> de longitud 512.
pub fn parse_participation_bits(bits_hex: &str) -> Vec<bool> {
    let hex = bits_hex.trim_start_matches("0x");
    let bytes = hex::decode(hex).unwrap_or_default();
    let mut out = Vec::with_capacity(bytes.len() * 8);
    for byte in &bytes {
        for i in 0..8 {
            out.push((byte >> i) & 1 == 1);
        }
    }
    out
}

/// Parsea compressed G2 (hex, 96 bytes) → [u8; 96]
pub fn parse_g2_compressed(sig_hex: &str) -> Result<[u8; 96], String> {
    let hex = sig_hex.trim_start_matches("0x");
    let bytes = hex::decode(hex).map_err(|e| format!("hex decode: {e}"))?;
    if bytes.len() != 96 {
        return Err(format!("expected 96 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 96];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Parsea compressed G1 (hex, 48 bytes) → [u8; 48]
pub fn parse_g1_compressed(key_hex: &str) -> Result<[u8; 48], String> {
    let hex = key_hex.trim_start_matches("0x");
    let bytes = hex::decode(hex).map_err(|e| format!("hex decode: {e}"))?;
    if bytes.len() != 48 {
        return Err(format!("expected 48 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 48];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Parsea root de 32 bytes desde hex.
pub fn parse_root(hex_str: &str) -> Result<[u8; 32], String> {
    let hex = hex_str.trim_start_matches("0x");
    let bytes = hex::decode(hex).map_err(|e| format!("hex decode: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Parsea fork_version de 4 bytes desde hex.
pub fn parse_fork_version(hex_str: &str) -> Result<[u8; 4], String> {
    let hex = hex_str.trim_start_matches("0x");
    let bytes = hex::decode(hex).map_err(|e| format!("hex decode: {e}"))?;
    if bytes.len() != 4 {
        return Err(format!("expected 4 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 4];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_participation_bits_all_ones_byte() {
        let bits = parse_participation_bits("0xff");
        assert_eq!(bits.len(), 8);
        assert!(bits.iter().all(|&b| b));
    }

    #[test]
    fn test_parse_participation_bits_zero() {
        let bits = parse_participation_bits("0x00");
        assert_eq!(bits.len(), 8);
        assert!(bits.iter().all(|&b| !b));
    }

    #[test]
    fn test_parse_root_valid() {
        let r = parse_root("0x0000000000000000000000000000000000000000000000000000000000000001");
        assert!(r.is_ok());
        assert_eq!(r.unwrap()[31], 0x01);
    }

    #[test]
    fn test_parse_fork_version_valid() {
        let fv = parse_fork_version("0x90000073");
        assert!(fv.is_ok());
        assert_eq!(fv.unwrap(), [0x90, 0x00, 0x00, 0x73]);
    }

    #[test]
    fn test_parse_g1_compressed_wrong_len() {
        let r = parse_g1_compressed("0xdeadbeef");
        assert!(r.is_err());
    }
}
