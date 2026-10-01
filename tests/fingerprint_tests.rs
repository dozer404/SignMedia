use signmedia::fingerprint::{
    calculate_fingerprint_distance, compute_decoded_image_fingerprint,
};
use img_hash::image::{ImageBuffer, Rgb, DynamicImage};

#[test]
fn test_decoded_visual_fingerprint_distance() {
    let mut imgbuf1: ImageBuffer<Rgb<u8>, Vec<u8>> = ImageBuffer::new(64, 64);
    for pixel in imgbuf1.pixels_mut() {
        *pixel = Rgb([200, 200, 200]);
    }
    let dyn_img1 = DynamicImage::ImageRgb8(imgbuf1);

    let mut imgbuf2: ImageBuffer<Rgb<u8>, Vec<u8>> = ImageBuffer::new(128, 128);
    for pixel in imgbuf2.pixels_mut() {
        *pixel = Rgb([200, 200, 200]);
    }
    let dyn_img2 = DynamicImage::ImageRgb8(imgbuf2);

    let fp1 = compute_decoded_image_fingerprint(&dyn_img1);
    let fp2 = compute_decoded_image_fingerprint(&dyn_img2);

    let dist = calculate_fingerprint_distance(&fp1, &fp2).unwrap();
    // Same flat content at different resolutions should have 0 or near-0 distance
    assert!(dist <= 2);
}
