use img_hash::{image, HashAlg, HasherConfig, ImageHash};

pub fn compute_decoded_image_fingerprint(img: &image::DynamicImage) -> String {
    let hasher = HasherConfig::new()
        .hash_alg(HashAlg::Gradient)
        .hash_size(16, 16)
        .to_hasher();

    let hash = hasher.hash_image(img);
    hash.to_base64()
}

pub fn calculate_fingerprint_distance(hash1_b64: &str, hash2_b64: &str) -> Option<u32> {
    let h1: ImageHash<[u8; 32]> = ImageHash::from_base64(hash1_b64).ok()?;
    let h2: ImageHash<[u8; 32]> = ImageHash::from_base64(hash2_b64).ok()?;
    Some(h1.dist(&h2))
}
