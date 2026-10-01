use signmedia::c2pa_backend::{c2pa_sign_file, c2pa_verify_file, inspect_file};
use image::{ImageBuffer, Rgb};

#[test]
fn test_conformance_full_pipeline_check() -> anyhow::Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let input_jpg = temp_dir.path().join("conformance.jpg");
    let signed_jpg = temp_dir.path().join("conformance_signed.jpg");

    let img: ImageBuffer<Rgb<u8>, Vec<u8>> = ImageBuffer::new(32, 32);
    img.save(&input_jpg)?;

    c2pa_sign_file(&input_jpg, &signed_jpg, "Conformance Asset", "SignMedia Test Suite", None, None)?;

    let report = c2pa_verify_file(&signed_jpg)?;
    assert!(report.contains("c2pa.actions"));

    let summary = inspect_file(&signed_jpg)?;
    assert!(summary.contains("Conformance Asset"));

    Ok(())
}
