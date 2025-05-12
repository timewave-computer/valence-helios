use beacon_electra::types::electra::{ElectraBlockBodyRoots, ElectraBlockHeader};
use borsh::{BorshDeserialize, BorshSerialize};
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct RecursionCircuitInputs {
    pub active_committee_hash: [u8; 32],
    pub electra_body_roots: ElectraBlockBodyRoots,
    pub electra_header: ElectraBlockHeader,
    pub helios_proof: Vec<u8>,
    pub helios_public_values: Vec<u8>,
    pub previous_proof: Option<Vec<u8>>,
    pub previous_public_values: Option<Vec<u8>>,
    pub previous_head: u64,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct WrapperCircuitInputs {
    pub recursive_proof: Vec<u8>,
    pub recursive_public_values: Vec<u8>,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct RecursionCircuitOutputs {
    // the execution state root
    pub root: Vec<u8>,
    // the height of the execution block
    pub height: u64,
}
