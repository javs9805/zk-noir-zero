use sha2::{Digest, Sha256};

const DOMAIN_SYNC_COMMITTEE: [u8; 4] = [0x07, 0x00, 0x00, 0x00];

pub fn compute_domain(fork_version: [u8; 4], genesis_validators_root: [u8; 32]) -> [u8; 32] {
    let mut preimage = [0u8; 64];
    preimage[..4].copy_from_slice(&fork_version);
    preimage[32..].copy_from_slice(&genesis_validators_root);
    let h = Sha256::digest(&preimage);
    let mut domain = [0u8; 32];
    domain[..4].copy_from_slice(&DOMAIN_SYNC_COMMITTEE);
    domain[4..].copy_from_slice(&h[..28]);
    domain
}

pub fn compute_signing_root(parent_root: [u8; 32], domain: [u8; 32]) -> [u8; 32] {
    let mut preimage = [0u8; 64];
    preimage[..32].copy_from_slice(&parent_root);
    preimage[32..].copy_from_slice(&domain);
    let h = Sha256::digest(&preimage);
    h.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    // RED: compute_domain con zeros => domain[0]==0x07, domain[4]==0xf5
    #[test]
    fn test_compute_domain_zero_vector() {
        let domain = compute_domain([0u8; 4], [0u8; 32]);
        assert_eq!(domain[0], 0x07);
        assert_eq!(domain[1], 0x00);
        assert_eq!(domain[4], 0xf5);
        assert_eq!(domain[5], 0xa5);
    }

    // RED: compute_signing_root con zeros => sr[0]==0xf5
    #[test]
    fn test_compute_signing_root_zero_vector() {
        let sr = compute_signing_root([0u8; 32], [0u8; 32]);
        assert_eq!(sr[0], 0xf5);
        assert_eq!(sr[1], 0xa5);
    }
}
