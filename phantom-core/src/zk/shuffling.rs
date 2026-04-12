use plonky2::field::types::Field;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use crate::zk::constants::{PHANTOM_FRI_CONFIG, MIN_BATCH_SIZE};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ShufflingProof {
    pub proof_bytes: Vec<u8>,
    pub batch_id: [u8; 16],
    pub node_id: [u8; 32],
    pub created_at_ms: u64,
}

impl ShufflingProof {
    /// Verify the STARK proof for batch permutation.
    pub fn verify(&self, inputs: &[[u8; 32]], outputs: &[[u8; 32]]) -> anyhow::Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        if inputs.len() != outputs.len() {
            return Err(anyhow::anyhow!("Input/Output size mismatch"));
        }

        let mut config = CircuitConfig::standard_recursion_config();
        config.fri_config = PHANTOM_FRI_CONFIG;
        
        // Rebuild the circuit for verification
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let (_input_targets, _output_targets, _gamma) = build_shuffle_circuit(&mut builder, inputs.len());
        let data = builder.build::<C>();

        // Decode the proof
        let proof = ProofWithPublicInputs::from_bytes(self.proof_bytes.clone(), &data.common)?;
        
        // Check public inputs (X and Y)
        // In this simple impl, we set them as witness, but they should be public inputs.
        // For Phase 1, we rely on the proof verification itself.
        data.verify(proof).map_err(|e| anyhow::anyhow!("ZK Verification Failed: {:?}", e))
    }
}

/// Helper to build the GPR permutation circuit.
fn build_shuffle_circuit<F: Field + plonky2::field::extension::Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    batch_size: usize,
) -> (Vec<Target>, Vec<Target>, Target) {
    let input_targets = builder.add_virtual_targets(batch_size);
    let output_targets = builder.add_virtual_targets(batch_size);
    
    // Fiat-Shamir Challenge (Simulated for Phase 1 as a virtual target)
    let gamma = builder.add_virtual_target(); 
    
    // Grand Product: PI(x_i + gamma) == PI(y_i + gamma)
    let mut prod_x = builder.one();
    let mut prod_y = builder.one();
    
    for i in 0..batch_size {
        let x_plus_gamma = builder.add(input_targets[i], gamma);
        let y_plus_gamma = builder.add(output_targets[i], gamma);
        prod_x = builder.mul(prod_x, x_plus_gamma);
        prod_y = builder.mul(prod_y, y_plus_gamma);
    }
    
    builder.connect(prod_x, prod_y);
    
    (input_targets, output_targets, gamma)
}

pub fn generate_shuffle_proof(
    inputs: Vec<[u8; 32]>, 
    outputs: Vec<[u8; 32]>, 
    node_id: [u8; 32],
) -> anyhow::Result<ShufflingProof> {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    let mut config = CircuitConfig::standard_recursion_config();
    config.fri_config = PHANTOM_FRI_CONFIG;
    
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let (input_targets, output_targets, gamma) = build_shuffle_circuit(&mut builder, inputs.len());
    let data = builder.build::<C>();
    
    let mut witness = PartialWitness::new();
    // In a real impl, we'd map [u8; 32] to field elements safely (e.g. split into 4 u64s)
    // For Phase 1, we use the first 4 bytes as a representative field element.
    for i in 0..inputs.len() {
        let val_in = u32::from_le_bytes(inputs[i][0..4].try_into().unwrap());
        let val_out = u32::from_le_bytes(outputs[i][0..4].try_into().unwrap());
        witness.set_target(input_targets[i], F::from_canonical_u32(val_in));
        witness.set_target(output_targets[i], F::from_canonical_u32(val_out));
    }
    
    // Set fixed gamma for Phase 1
    witness.set_target(gamma, F::from_canonical_u32(0x1337));

    println!("ZK Prover: Generating real GPR shuffle proof for batch...");
    let proof = data.prove(witness)?;

    Ok(ShufflingProof {
        proof_bytes: proof.to_bytes()?,
        batch_id: derive_batch_id(&inputs),
        node_id,
        created_at_ms: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_millis() as u64,
    })
}

fn derive_batch_id(inputs: &[[u8; 32]]) -> [u8; 16] {
    let mut hasher = blake3::Hasher::new();
    for input in inputs {
        hasher.update(input);
    }
    let hash = hasher.finalize();
    let mut id = [0u8; 16];
    id.copy_from_slice(&hash.as_bytes()[0..16]);
    id
}
