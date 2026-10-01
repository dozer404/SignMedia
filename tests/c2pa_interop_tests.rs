use signmedia::c2pa_backend::{c2pa_sign_file, c2pa_verify_file, inspect_file};
use image::{ImageBuffer, Rgb};

#[test]
fn test_c2pa_sign_verify_inspect_jpeg() {
    let temp_dir = tempfile::tempdir().unwrap();
    let input_jpg = temp_dir.path().join("sample.jpg");
    let signed_jpg = temp_dir.path().join("signed_sample.jpg");

    let img: ImageBuffer<Rgb<u8>, Vec<u8>> = ImageBuffer::new(64, 64);
    img.save(&input_jpg).unwrap();

    if let Err(e) = c2pa_sign_file(&input_jpg, &signed_jpg, "Test C2PA Image", "Alice", None, None) {
        eprintln!("c2pa_sign_file error: {:?}", e);
        panic!("c2pa_sign_file failed: {:?}", e);
    }

    assert!(signed_jpg.exists());

    let verify_json = c2pa_verify_file(&signed_jpg).unwrap();
    println!("verify_json = {}", verify_json);

    let inspect_out = inspect_file(&signed_jpg).unwrap();
    println!("inspect_out = {}", inspect_out);
}
