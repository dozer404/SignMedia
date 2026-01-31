use signmedia::models::{TrackChunkIndexEntry, TrackMetadata};
use signmedia::timecode::{time_range_to_chunk_range, chunk_range_to_time_range};

#[test]
fn test_clip_alignment() {
    // Video track: 1s chunks (GOPs)
    let video_track = TrackMetadata {
        track_id: 0,
        codec: "h264".to_string(),
        container_type: None,
        codec_extradata: None,
        width: Some(1920),
        height: Some(1080),
        sample_rate: None,
        channel_count: None,
        timebase_num: Some(1),
        timebase_den: Some(30), // 30 fps, so 1 tick = 1 frame. GOP=30 frames = 1s.
        merkle_root: "".to_string(),
        perceptual_hash: None,
        total_chunks: 10,
        chunk_size: 1000000,
        chunk_index: vec![],
    };

    let video_entries: Vec<TrackChunkIndexEntry> = (0..10).map(|i| {
        TrackChunkIndexEntry {
            chunk_index: i as u64,
            pts: Some((i as i64) * 30), // Each chunk starts 1s apart
            offset: (i as u64) * 1000000,
            size: 1000000,
        }
    }).collect();

    // Audio track: ~21.33ms frames (AAC 48kHz)
    let audio_track = TrackMetadata {
        track_id: 1,
        codec: "aac".to_string(),
        container_type: None,
        codec_extradata: None,
        width: None,
        height: None,
        sample_rate: Some(48000),
        channel_count: Some(2),
        timebase_num: Some(1),
        timebase_den: Some(1000000), // Microseconds
        merkle_root: "".to_string(),
        perceptual_hash: None,
        total_chunks: 500,
        chunk_size: 1000,
        chunk_index: vec![],
    };

    let audio_entries: Vec<TrackChunkIndexEntry> = (0..500).map(|i| {
        TrackChunkIndexEntry {
            chunk_index: i as u64,
            pts: Some((i as f64 * 1024.0 * 1000000.0 / 48000.0) as i64),
            offset: (i as u64) * 1000,
            size: 1000,
        }
    }).collect();

    // Scenario 1: Clip 2s to 6s using time
    let start_time = 2.0;
    let end_time = 6.0;

    let video_range = time_range_to_chunk_range(&video_track, &video_entries, Some(start_time), Some(end_time)).unwrap();
    let audio_range = time_range_to_chunk_range(&audio_track, &audio_entries, Some(start_time), Some(end_time)).unwrap();

    println!("Video range: {:?}, Audio range: {:?}", video_range, audio_range);

    // Video range should be 2..6 (chunks at 2s, 3s, 4s, 5s)
    assert_eq!(video_range, (2, 6));

    // Audio range starts at last frame <= 2.0s
    // 2.0s = 2,000,000us.
    // Frame at index 93: 93 * 1024 * 1000000 / 48000 = 1,984,000
    // Frame at index 94: 94 * 1024 * 1000000 / 48000 = 2,005,333
    // So start_chunk should be 93 (new logic: last chunk <= 2.0s)
    assert_eq!(audio_range.0, 93);

    // Audio range ends at first frame >= 6.0s
    // 6.0s = 6,000,000us.
    // Frame at index 281: 281 * 1024 * 1000000 / 48000 = 5,994,666
    // Frame at index 282: 282 * 1024 * 1000000 / 48000 = 6,016,000
    // So end_chunk should be 282. (No change here)
    assert_eq!(audio_range.1, 282);

    // Scenario 2: Using chunk range from video to determine time
    let video_time_range = chunk_range_to_time_range(&video_track, &video_entries, 2, 6).unwrap();
    println!("Video time range from chunks 2..6: {:?}", video_time_range);

    // NOW it should return (pts[2], pts[6])
    // start = 2.0, end = 6.0
    assert_eq!(video_time_range, (2.0, 6.0));

    // Scenario 3: Falling between chunks
    let start_time = 2.5;
    let end_time = 5.5;
    let audio_range = time_range_to_chunk_range(&audio_track, &audio_entries, Some(start_time), Some(end_time)).unwrap();

    // 2.5s = 2,500,000us.
    // Frame 117: 117 * 1024 * 1000000 / 48000 = 2,496,000
    // Frame 118: 118 * 1024 * 1000000 / 48000 = 2,517,333
    // start_chunk should be 117.
    assert_eq!(audio_range.0, 117);

    // 5.5s = 5,500,000us.
    // Frame 257: 257 * 1024 * 1000000 / 48000 = 5,482,666
    // Frame 258: 258 * 1024 * 1000000 / 48000 = 5,504,000
    // end_chunk should be 258.
    assert_eq!(audio_range.1, 258);
}
