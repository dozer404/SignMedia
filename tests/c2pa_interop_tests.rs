use signmedia::c2pa_backend::{c2pa_sign_file, c2pa_verify_file, inspect_file};
use image::{ImageBuffer, Rgb};
use std::path::Path;

#[test]
fn test_c2pa_sign_verify_inspect_jpeg() {
    let temp_dir = tempfile::tempdir().unwrap();
    let input_jpg = temp_dir.path().join("sample.jpg");
    let signed_jpg = temp_dir.path().join("signed_sample.jpg");

    let img: ImageBuffer<Rgb<u8>, Vec<u8>> = ImageBuffer::new(64, 64);
    img.save(&input_jpg).unwrap();

    let cert_path = Path::new("tests/fixtures/test_cert.pem");
    let key_path = Path::new("tests/fixtures/test_key.pem");

    if let Err(e) = c2pa_sign_file(&input_jpg, &signed_jpg, "Test C2PA Image", "Alice", Some(cert_path), Some(key_path)) {
        eprintln!("c2pa_sign_file error: {:?}", e);
        panic!("c2pa_sign_file failed: {:?}", e);
    }

    assert!(signed_jpg.exists());

    let verify_json = c2pa_verify_file(&signed_jpg).unwrap();
    assert!(!verify_json.is_empty());

    let inspect_out = inspect_file(&signed_jpg).unwrap();
    assert!(inspect_out.contains("Test C2PA Image"));
}

#[test]
fn test_c2pa_missing_credentials_rejection() {
    let temp_dir = tempfile::tempdir().unwrap();
    let input_jpg = temp_dir.path().join("sample.jpg");
    let signed_jpg = temp_dir.path().join("signed_sample.jpg");

    let img: ImageBuffer<Rgb<u8>, Vec<u8>> = ImageBuffer::new(64, 64);
    img.save(&input_jpg).unwrap();

    // Calling c2pa_sign_file without cert and key must fail (R04)
    assert!(c2pa_sign_file(&input_jpg, &signed_jpg, "Test", "Alice", None, None).is_err());
}

#[test]
fn test_c2pa_verify_no_manifest_and_tampered_rejection() {
    let temp_dir = tempfile::tempdir().unwrap();
    let input_jpg = temp_dir.path().join("sample.jpg");
    let signed_jpg = temp_dir.path().join("signed_sample.jpg");

    let img: ImageBuffer<Rgb<u8>, Vec<u8>> = ImageBuffer::new(64, 64);
    img.save(&input_jpg).unwrap();

    // File without C2PA manifest must fail c2pa_verify_file (R03)
    assert!(c2pa_verify_file(&input_jpg).is_err());

    let cert_path = Path::new("tests/fixtures/test_cert.pem");
    let key_path = Path::new("tests/fixtures/test_key.pem");
    c2pa_sign_file(&input_jpg, &signed_jpg, "Test", "Alice", Some(cert_path), Some(key_path)).unwrap();

    // Tamper with signed JPEG image content
    let mut bytes = std::fs::read(&signed_jpg).unwrap();
    let last_idx = bytes.len() - 10;
    bytes[last_idx] ^= 0xFF; // Modify bytes inside image payload
    let tampered_jpg = temp_dir.path().join("tampered.jpg");
    std::fs::write(&tampered_jpg, &bytes).unwrap();

    // Verification of tampered content must fail (R03)
    assert!(c2pa_verify_file(&tampered_jpg).is_err());
}
