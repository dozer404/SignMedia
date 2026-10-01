use anyhow::Result;
use signmedia::archive::ArchivalPackage;
use tempfile::tempdir;

#[test]
fn test_archive_valid_roundtrip() -> Result<()> {
    let dir = tempdir()?;
    let media_bytes = b"playable video content";
    let manifest_bytes = b"c2pa manifest store content";

    let pkg = ArchivalPackage::new(media_bytes, "video.mp4", manifest_bytes)?;
    let pkg_file = dir.path().join("archive.smed");
    pkg.pack_to_file(&pkg_file)?;

    let unpacked_pkg = ArchivalPackage::unpack_from_file(&pkg_file)?;
    assert_eq!(unpacked_pkg.playable_media_bytes, media_bytes);
    assert_eq!(unpacked_pkg.manifest_store_bytes, manifest_bytes);

    let extract_dir = dir.path().join("extracted");
    unpacked_pkg.unpack_and_extract(&extract_dir)?;

    let extracted_media = std::fs::read(extract_dir.join("video.mp4"))?;
    let extracted_manifest = std::fs::read(extract_dir.join("manifest_store.c2pa"))?;

    assert_eq!(extracted_media, media_bytes);
    assert_eq!(extracted_manifest, manifest_bytes);

    Ok(())
}

#[test]
fn test_archive_path_traversal_rejection() -> Result<()> {
    let media_bytes = b"some media";
    let manifest_bytes = b"some store";

    // Rejections at construction time
    assert!(ArchivalPackage::new(media_bytes, "../escape-marker", manifest_bytes).is_err());
    assert!(ArchivalPackage::new(media_bytes, "/etc/passwd", manifest_bytes).is_err());
    assert!(ArchivalPackage::new(media_bytes, "subdir/media.mp4", manifest_bytes).is_err());
    assert!(ArchivalPackage::new(media_bytes, "..\\escape-marker", manifest_bytes).is_err());

    Ok(())
}

#[test]
fn test_archive_colliding_name_rejection() -> Result<()> {
    let media_bytes = b"some media";
    let manifest_bytes = b"some store";

    // Playable media name cannot collide with manifest_store.c2pa
    assert!(ArchivalPackage::new(media_bytes, "manifest_store.c2pa", manifest_bytes).is_err());

    Ok(())
}

#[test]
fn test_archive_tampered_hash_rejection() -> Result<()> {
    let media_bytes = b"authentic media";
    let manifest_bytes = b"authentic manifest";

    let mut pkg = ArchivalPackage::new(media_bytes, "media.mp4", manifest_bytes)?;
    pkg.playable_media_bytes = b"tampered media".to_vec();

    assert!(pkg.verify_inventory().is_err());

    let dir = tempdir()?;
    let extract_dir = dir.path().join("extracted");
    assert!(pkg.unpack_and_extract(&extract_dir).is_err());

    Ok(())
}
