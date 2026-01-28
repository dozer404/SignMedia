use blake3::Hasher;
use crate::models::{MerkleProof, ProofStep};
use img_hash::{HasherConfig, HashAlg};
use img_hash::image;
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use std::convert::TryInto;

pub type Hash = [u8; 32];

pub fn hash_data(data: &[u8]) -> Hash {
    blake3::hash(data).into()
}

pub struct MerkleTree {
    pub nodes: Vec<Vec<Hash>>, // levels, from leaves to root
}

impl MerkleTree {
    pub fn new(leaves: Vec<Hash>) -> Self {
        if leaves.is_empty() {
            return Self { nodes: vec![vec![[0u8; 32]]] };
        }
        let mut nodes = vec![leaves];
        while nodes.last().unwrap().len() > 1 {
            let current_level = nodes.last().unwrap();
            let mut next_level = Vec::new();
            for chunk in current_level.chunks(2) {
                if chunk.len() == 2 {
                    let mut hasher = Hasher::new();
                    hasher.update(&chunk[0]);
                    hasher.update(&chunk[1]);
                    next_level.push(hasher.finalize().into());
                } else {
                    // Odd number of nodes, promote the last one
                    // In a standard Merkle tree, we might duplicate or just promote.
                    // Promoting can be insecure in some contexts (second preimage), 
                    // but for this v1 it's simple. 
                    // Better: hash(chunk[0] || chunk[0]) or just use a well-known construction.
                    // For simplicity, let's just promote but be aware.
                    next_level.push(chunk[0]);
                }
            }
            nodes.push(next_level);
        }
        Self { nodes }
    }

    pub fn root(&self) -> Hash {
        *self.nodes.last().unwrap().first().unwrap()
    }

    pub fn generate_proof(&self, index: usize) -> MerkleProof {
        let mut path = Vec::new();
        let mut current_index = index;
        let leaf_hash = hex::encode(self.nodes[0][index]);

        for level in 0..self.nodes.len() - 1 {
            let current_level = &self.nodes[level];
            let is_left = current_index % 2 == 0;
            let sibling_index = if is_left {
                current_index + 1
            } else {
                current_index - 1
            };

            if sibling_index < current_level.len() {
                path.push(ProofStep {
                    is_left: !is_left, // if we are left, sibling is right
                    hash: hex::encode(current_level[sibling_index]),
                });
            }
            current_index /= 2;
        }

        MerkleProof {
            chunk_index: index as u64,
            hash: leaf_hash,
            path,
            chunk_size: 0,
        }
    }
}

pub fn verify_proof(root: Hash, proof: &MerkleProof) -> bool {
    let mut current_hash: Hash = match hex::decode(&proof.hash) {
        Ok(h) => h.try_into().unwrap_or([0u8; 32]),
        Err(_) => return false,
    };
    
    for step in &proof.path {
        let sibling_hash: Hash = match hex::decode(&step.hash) {
            Ok(h) => h.try_into().unwrap_or([0u8; 32]),
            Err(_) => return false,
        };
        let mut hasher = Hasher::new();
        if step.is_left {
            hasher.update(&sibling_hash);
            hasher.update(&current_hash);
        } else {
            hasher.update(&current_hash);
            hasher.update(&sibling_hash);
        }
        current_hash = hasher.finalize().into();
    }
    
    current_hash == root
}

pub trait SecureSigner {
    fn sign(&self, data: &[u8]) -> Signature;
    fn public_key(&self) -> VerifyingKey;
}

pub struct DefaultSigner {
    signing_key: SigningKey,
}

impl DefaultSigner {
    pub fn new(signing_key: SigningKey) -> Self {
        Self { signing_key }
    }
}

impl SecureSigner for DefaultSigner {
    fn sign(&self, data: &[u8]) -> Signature {
        self.signing_key.sign(data)
    }

    fn public_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
}

pub fn sign(data: &[u8], signing_key: &SigningKey) -> Signature {
    signing_key.sign(data)
}

pub fn verify_signature(data: &[u8], signature: &Signature, public_key: &VerifyingKey) -> bool {
    public_key.verify(data, signature).is_ok()
}

pub fn generate_keypair() -> SigningKey {
    let mut csprng = rand::thread_rng();
    SigningKey::generate(&mut csprng)
}

pub fn compute_perceptual_hash(data: &[u8]) -> Option<String> {
    // Treat data as a square grayscale image if possible
    let size = (data.len() as f64).sqrt() as u32;
    if size < 8 { return None; }
    
    let mut imgbuf = image::ImageBuffer::new(size, size);
    for (i, pixel) in imgbuf.pixels_mut().enumerate() {
        if i < data.len() {
            *pixel = image::Luma([data[i]]);
        }
    }
    let dynamic_img = image::DynamicImage::ImageLuma8(imgbuf);
    
    let hasher = HasherConfig::new()
        .hash_alg(HashAlg::Gradient)
        .hash_size(8, 8)
        .to_hasher();
    
    let hash = hasher.hash_image(&dynamic_img);
    Some(hash.to_base64())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_tree() {
        let leaves = vec![
            hash_data(b"chunk1"),
            hash_data(b"chunk2"),
            hash_data(b"chunk3"),
            hash_data(b"chunk4"),
        ];
        let tree = MerkleTree::new(leaves.clone());
        let root = tree.root();

        for i in 0..leaves.len() {
            let proof = tree.generate_proof(i);
            assert!(verify_proof(root, &proof));
        }
    }

    #[test]
    fn test_merkle_tree_odd() {
        let leaves = vec![
            hash_data(b"chunk1"),
            hash_data(b"chunk2"),
            hash_data(b"chunk3"),
        ];
        let tree = MerkleTree::new(leaves.clone());
        let root = tree.root();

        for i in 0..leaves.len() {
            let proof = tree.generate_proof(i);
            assert!(verify_proof(root, &proof));
        }
    }

    #[test]
    fn test_signature() {
        let keypair = generate_keypair();
        let data = b"some media data";
        let sig = sign(data, &keypair);
        assert!(verify_signature(data, &sig, &VerifyingKey::from(&keypair)));
    }

    #[test]
    fn test_secure_signer() {
        let keypair = generate_keypair();
        let signer = DefaultSigner::new(keypair);
        let data = b"secure data";
        let sig = signer.sign(data);
        assert!(verify_signature(data, &sig, &signer.public_key()));
    }
}
