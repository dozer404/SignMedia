use anyhow::Result;
use signmedia::experiments::PqArchivalReceipt;

#[test]
fn test_pq_receipt_verification_and_tamper_protection() -> Result<()> {
    let store_bytes = b"sample c2pa manifest store bytes";
    let mock_key = [0x42u8; 32];

    let receipt = PqArchivalReceipt::new_simulated(store_bytes, &mock_key);

    // Valid store bytes verify
    assert!(receipt.verify(store_bytes)?);

    // Tampered store bytes fail verification (R09)
    let tampered_bytes = b"tampered manifest store bytes";
    assert!(!receipt.verify(tampered_bytes)?);

    // Tampered store hash field fails verification (R09)
    let mut tampered_receipt = receipt.clone();
    tampered_receipt.manifest_store_hash = hex::encode([0u8; 32]);
    assert!(!tampered_receipt.verify(store_bytes)?);

    Ok(())
}
