use anyhow::{anyhow, Context, Result};
use std::fs;
use std::io::{Read, Write};
use std::process::Command;
use uuid::Uuid;

pub struct ChunkWithMeta {
    pub data: Vec<u8>,
    pub pts: Option<i64>,
}

pub struct ChunkedTrack {
    pub chunks: Vec<ChunkWithMeta>,
    pub playback: TrackPlaybackInfo,
}

pub struct TrackPlaybackInfo {
    pub codec: String,
    pub container_type: Option<String>,
    pub codec_extradata: Option<Vec<u8>>,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub sample_rate: Option<u32>,
    pub channels: Option<u16>,
    pub timebase_num: Option<u32>,
    pub timebase_den: Option<u32>,
}

pub fn chunk_media(
    reader: &mut impl Read,
    max_chunk_size: u64,
) -> Result<(Vec<ChunkWithMeta>, TrackPlaybackInfo)> {
    let tracks = chunk_media_tracks(reader, max_chunk_size)?;
    let mut iter = tracks.into_iter();
    iter.next()
        .map(|track| (track.chunks, track.playback))
        .ok_or_else(|| anyhow!("No tracks detected in input"))
}

pub fn chunk_media_tracks(
    reader: &mut impl Read,
    max_chunk_size: u64,
) -> Result<Vec<ChunkedTrack>> {
    let mut data = Vec::new();
    reader.read_to_end(&mut data)?;

    if let Some(image_type) = detect_image_type(&data) {
        return Ok(vec![ChunkedTrack {
            chunks: fallback_chunking(&data, max_chunk_size),
            playback: raw_track_info(Some(image_type)),
        }]);
    }

    if let Some(container_type) = detect_container_type(&data) {
        let streams = demux_container_streams(&data, &container_type)?;
        let mut tracks = Vec::new();
        for stream in streams {
            if let Some((chunks, playback)) = chunk_media_for_codec(
                &stream.data,
                max_chunk_size,
                Some(container_type.clone()),
                &stream.codec_name,
            ) {
                tracks.push(ChunkedTrack { chunks, playback });
            }
        }
        if !tracks.is_empty() {
            return Ok(tracks);
        }
        return Ok(vec![ChunkedTrack {
            chunks: fallback_chunking(&data, max_chunk_size),
            playback: raw_track_info(Some(container_type)),
        }]);
    }

    if let Some((chunks, playback)) = chunk_media_from_bytes(&data, max_chunk_size, None) {
        return Ok(vec![ChunkedTrack { chunks, playback }]);
    }

    Ok(vec![ChunkedTrack {
        chunks: fallback_chunking(&data, max_chunk_size),
        playback: raw_track_info(None),
    }])
}

fn raw_track_info(container_type: Option<String>) -> TrackPlaybackInfo {
    TrackPlaybackInfo {
        codec: "raw".to_string(),
        container_type,
        codec_extradata: None,
        width: None,
        height: None,
        sample_rate: None,
        channels: None,
        timebase_num: None,
        timebase_den: None,
    }
}

fn chunk_media_from_bytes(
    data: &[u8],
    max_chunk_size: u64,
    container_type: Option<String>,
) -> Option<(Vec<ChunkWithMeta>, TrackPlaybackInfo)> {
    if let Some(info) = parse_adts_frames(data) {
        let frame_duration_us = (1_000_000i64 * 1024) / info.sample_rate as i64;
        let chunks =
            group_adts_frames(data, &info.frames, max_chunk_size, frame_duration_us);
        let codec_extradata = build_aac_extradata(
            info.audio_object_type,
            info.sample_rate_index,
            info.channel_config,
        );
        return Some((
            chunks,
            TrackPlaybackInfo {
                codec: "aac".to_string(),
                container_type,
                codec_extradata: Some(codec_extradata),
                width: None,
                height: None,
                sample_rate: Some(info.sample_rate),
                channels: info.channel_config.and_then(|channels| {
                    if channels == 0 {
                        None
                    } else {
                        Some(channels)
                    }
                }),
                timebase_num: Some(1),
                timebase_den: Some(1_000_000),
            },
        ));
    }
    if let Some(info) = parse_annexb_nals(data) {
        let chunks = group_nals(data, &info.nals, max_chunk_size);
        let codec = match info.codec {
            AnnexbCodec::H264 => "h264",
            AnnexbCodec::H265 => "h265",
        };
        return Some((
            chunks,
            TrackPlaybackInfo {
                codec: codec.to_string(),
                container_type,
                codec_extradata: info.codec_extradata,
                width: info.width,
                height: info.height,
                sample_rate: None,
                channels: None,
                timebase_num: info.timebase_num,
                timebase_den: info.timebase_den,
            },
        ));
    }
    None
}

fn chunk_media_for_codec(
    data: &[u8],
    max_chunk_size: u64,
    container_type: Option<String>,
    codec_name: &str,
) -> Option<(Vec<ChunkWithMeta>, TrackPlaybackInfo)> {
    let normalized = codec_name.to_ascii_lowercase();
    match normalized.as_str() {
        "opus" => {
            if let Some(result) = chunk_ogg_opus(data, max_chunk_size, container_type.clone()) {
                return Some(result);
            }
            Some((
                fallback_chunking(data, max_chunk_size),
                TrackPlaybackInfo {
                    codec: normalized,
                    container_type,
                    codec_extradata: None,
                    width: None,
                    height: None,
                    sample_rate: None,
                    channels: None,
                    timebase_num: None,
                    timebase_den: None,
                },
            ))
        }
        "flac" => {
            if let Some(result) = chunk_flac_from_bytes(data, max_chunk_size, container_type.clone())
            {
                return Some(result);
            }
            Some((
                fallback_chunking(data, max_chunk_size),
                TrackPlaybackInfo {
                    codec: normalized,
                    container_type,
                    codec_extradata: None,
                    width: None,
                    height: None,
                    sample_rate: None,
                    channels: None,
                    timebase_num: None,
                    timebase_den: None,
                },
            ))
        }
        _ => {
            if let Some(result) =
                chunk_media_from_bytes(data, max_chunk_size, container_type.clone())
            {
                return Some(result);
            }
            if matches!(normalized.as_str(), "aac" | "h264" | "h265" | "hevc") {
                return Some((
                    fallback_chunking(data, max_chunk_size),
                    TrackPlaybackInfo {
                        codec: normalized,
                        container_type,
                        codec_extradata: None,
                        width: None,
                        height: None,
                        sample_rate: None,
                        channels: None,
                        timebase_num: None,
                        timebase_den: None,
                    },
                ));
            }
            None
        }
    }
}

fn detect_image_type(data: &[u8]) -> Option<String> {
    if data.len() >= 8 && data.starts_with(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]) {
        return Some("png".to_string());
    }
    if data.len() >= 3 && data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF {
        return Some("jpg".to_string());
    }
    if data.len() >= 6 && (data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a")) {
        return Some("gif".to_string());
    }
    if data.len() >= 12 && data.starts_with(b"RIFF") && data[8..12] == *b"WEBP" {
        return Some("webp".to_string());
    }
    if is_heif_image(data) {
        return Some("heic".to_string());
    }
    None
}

fn is_heif_image(data: &[u8]) -> bool {
    if data.len() < 16 {
        return false;
    }
    if &data[4..8] != b"ftyp" {
        return false;
    }
    if is_heif_brand(&data[8..12]) {
        return true;
    }
    let size = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if size < 16 || size > data.len() {
        return false;
    }
    let mut offset = 16;
    while offset + 4 <= size {
        if is_heif_brand(&data[offset..offset + 4]) {
            return true;
        }
        offset += 4;
    }
    false
}

fn is_heif_brand(brand: &[u8]) -> bool {
    matches!(
        brand,
        b"heic" | b"heix" | b"hevc" | b"hevx" | b"mif1" | b"msf1"
    )
}

fn detect_container_type(data: &[u8]) -> Option<String> {
    if looks_like_isobmff(data) {
        return Some("mp4".to_string());
    }
    if data.len() >= 4 && data.starts_with(&[0x1A, 0x45, 0xDF, 0xA3]) {
        let scan_len = data.len().min(4096);
        let header = &data[..scan_len];
        if header
            .windows(4)
            .any(|window| window.eq_ignore_ascii_case(b"webm"))
        {
            return Some("webm".to_string());
        }
        if header
            .windows(8)
            .any(|window| window.eq_ignore_ascii_case(b"matroska"))
        {
            return Some("mkv".to_string());
        }
        return Some("mkv".to_string());
    }
    None
}

struct DemuxedStream {
    pub codec_name: String,
    pub data: Vec<u8>,
}

fn demux_container_streams(data: &[u8], container_type: &str) -> Result<Vec<DemuxedStream>> {
    let temp_dir = std::env::temp_dir().join(format!("smed-demux-{}", Uuid::new_v4()));
    fs::create_dir_all(&temp_dir).context("Failed to create temp directory")?;
    let input_path = temp_dir.join(format!("input.{}", container_type));
    let mut file = fs::File::create(&input_path).context("Failed to create temp input file")?;
    file.write_all(data)
        .context("Failed to write temp input file")?;
    drop(file);

    #[derive(serde::Deserialize)]
    struct FfprobeStream {
        index: Option<u32>,
        codec_name: Option<String>,
        codec_type: Option<String>,
    }
    #[derive(serde::Deserialize)]
    struct FfprobeOutput {
        streams: Option<Vec<FfprobeStream>>,
    }

    let probe = Command::new("ffprobe")
        .args(["-v", "quiet", "-print_format", "json", "-show_streams"])
        .arg(&input_path)
        .output()
        .context("Failed to invoke ffprobe for demux")?;

    if !probe.status.success() {
        let _ = fs::remove_file(&input_path);
        let _ = fs::remove_dir(&temp_dir);
        return Err(anyhow!("ffprobe failed with status {}", probe.status));
    }

    let parsed: FfprobeOutput =
        serde_json::from_slice(&probe.stdout).context("Failed to parse ffprobe JSON")?;
    let mut streams: Vec<(u32, String)> = parsed
        .streams
        .unwrap_or_default()
        .into_iter()
        .filter_map(|stream| {
            let index = stream.index?;
            let codec_name = stream.codec_name?.to_ascii_lowercase();
            let codec_type = stream.codec_type.unwrap_or_default();
            if codec_type != "video" && codec_type != "audio" {
                return None;
            }
            if demux_stream_params(&codec_name).is_none() {
                return None;
            }
            Some((index, codec_name))
        })
        .collect();
    streams.sort_by_key(|(index, _)| *index);

    let mut outputs = Vec::new();
    let mut output_paths = Vec::new();
    for (index, codec_name) in streams {
        let Some((codec, format, bitstream_filter)) = demux_stream_params(&codec_name) else {
            continue;
        };
        let output_path = temp_dir.join(format!("stream-{}-{}.bin", index, codec));
        let mut command = Command::new("ffmpeg");
        command.arg("-y");
        command.arg("-i").arg(&input_path);
        command.arg("-map").arg(format!("0:{}", index));
        command.arg("-c").arg("copy");
        if let Some(filter) = bitstream_filter {
            command.arg("-bsf:v").arg(filter);
        }
        command.arg("-f").arg(format).arg(&output_path);

        let status = command
            .status()
            .context("Failed to invoke ffmpeg for demux")?;
        if !status.success() {
            let _ = fs::remove_file(&input_path);
            for path in output_paths {
                let _ = fs::remove_file(path);
            }
            let _ = fs::remove_dir(&temp_dir);
            return Err(anyhow!("ffmpeg demux failed with status {}", status));
        }

        let demuxed = fs::read(&output_path).context("Failed to read demuxed stream data")?;
        outputs.push(DemuxedStream {
            codec_name,
            data: demuxed,
        });
        output_paths.push(output_path);
    }

    let _ = fs::remove_file(&input_path);
    for path in output_paths {
        let _ = fs::remove_file(path);
    }
    let _ = fs::remove_dir(&temp_dir);

    Ok(outputs)
}

fn demux_stream_params(
    codec_name: &str,
) -> Option<(&'static str, &'static str, Option<&'static str>)> {
    match codec_name {
        "h264" => Some(("h264", "h264", Some("h264_mp4toannexb"))),
        "hevc" | "h265" => Some(("h265", "hevc", Some("hevc_mp4toannexb"))),
        "aac" => Some(("aac", "adts", None)),
        "opus" => Some(("opus", "opus", None)),
        "flac" => Some(("flac", "flac", None)),
        _ => None,
    }
}

pub struct AdtsParseInfo {
    pub frames: Vec<(usize, usize, i64)>,
    pub sample_rate: u32,
    pub sample_rate_index: u8,
    pub channel_config: Option<u16>,
    pub audio_object_type: u8,
}

pub fn parse_adts_frames(data: &[u8]) -> Option<AdtsParseInfo> {
    let sample_rates = [
        96000, 88200, 64000, 48000, 44100, 32000, 24000, 22050, 16000, 12000, 11025, 8000, 7350,
    ];
    let mut frames = Vec::new();
    let mut offset = 0usize;
    let mut pts_us = 0i64;
    let mut sample_rate = None;
    let mut sample_rate_index = None;
    let mut channel_config = None;
    let mut audio_object_type = None;
    while offset + 7 <= data.len() {
        if data[offset] != 0xFF || (data[offset + 1] & 0xF0) != 0xF0 {
            return None;
        }
        let protection_absent = data[offset + 1] & 0x01;
        let header_len = if protection_absent == 1 { 7 } else { 9 };
        let frame_length = (((data[offset + 3] & 0x03) as usize) << 11)
            | ((data[offset + 4] as usize) << 3)
            | ((data[offset + 5] & 0xE0) as usize >> 5);
        if frame_length < header_len || offset + frame_length > data.len() {
            return None;
        }
        let profile = (data[offset + 2] & 0xC0) >> 6;
        let audio_object = profile + 1;
        let sr_index = ((data[offset + 2] & 0x3C) >> 2) as usize;
        let sr = sample_rates.get(sr_index).copied()?;
        let channel_cfg =
            (((data[offset + 2] & 0x01) as u16) << 2) | (((data[offset + 3] & 0xC0) as u16) >> 6);
        sample_rate_index.get_or_insert(sr_index as u8);
        sample_rate.get_or_insert(sr);
        if sample_rate != Some(sr) {
            return None;
        }
        channel_config.get_or_insert(channel_cfg);
        if channel_config != Some(channel_cfg) {
            return None;
        }
        audio_object_type.get_or_insert(audio_object);
        if audio_object_type != Some(audio_object) {
            return None;
        }
        frames.push((offset, frame_length, pts_us));
        pts_us += (1_000_000i64 * 1024) / sr as i64;
        offset += frame_length;
    }
    if offset != data.len() || frames.is_empty() {
        None
    } else {
        Some(AdtsParseInfo {
            frames,
            sample_rate: sample_rate?,
            sample_rate_index: sample_rate_index?,
            channel_config,
            audio_object_type: audio_object_type?,
        })
    }
}

pub fn group_adts_frames(
    data: &[u8],
    frames: &[(usize, usize, i64)],
    max_chunk_size: u64,
    frame_duration_us: i64,
) -> Vec<ChunkWithMeta> {
    const MAX_AUDIO_CHUNK_DURATION_US: i64 = 1_000_000;
    let mut chunks = Vec::new();
    let mut current = Vec::new();
    let mut current_pts = None;
    for (start, length, pts) in frames {
        if !current.is_empty() {
            let mut should_flush = current.len() as u64 + *length as u64 > max_chunk_size;
            if let Some(start_pts) = current_pts {
                if frame_duration_us > 0 {
                    let end_pts = pts.saturating_add(frame_duration_us);
                    if end_pts.saturating_sub(start_pts) > MAX_AUDIO_CHUNK_DURATION_US {
                        should_flush = true;
                    }
                }
            }
            if should_flush {
                chunks.push(ChunkWithMeta {
                    data: std::mem::take(&mut current),
                    pts: current_pts,
                });
                current_pts = None;
            }
        }
        if current.is_empty() {
            current_pts = Some(*pts);
        }
        current.extend_from_slice(&data[*start..start + length]);
    }
    if !current.is_empty() {
        chunks.push(ChunkWithMeta {
            data: current,
            pts: current_pts,
        });
    }
    chunks
}

struct AudioFrameMeta {
    start: usize,
    len: usize,
    pts_us: i64,
    duration_us: i64,
}

fn group_frames_with_durations(
    data: &[u8],
    frames: &[AudioFrameMeta],
    max_chunk_size: u64,
) -> Vec<ChunkWithMeta> {
    const MAX_AUDIO_CHUNK_DURATION_US: i64 = 1_000_000;
    let mut chunks = Vec::new();
    let mut current = Vec::new();
    let mut current_pts: Option<i64> = None;
    let mut current_end: Option<i64> = None;

    for frame in frames {
        if !current.is_empty() {
            let mut should_flush = current.len() as u64 + frame.len as u64 > max_chunk_size;
            if let Some(start_pts) = current_pts {
                let frame_end = frame
                    .pts_us
                    .saturating_add(frame.duration_us.max(0));
                let next_end = current_end.map_or(frame_end, |end| end.max(frame_end));
                if next_end.saturating_sub(start_pts) > MAX_AUDIO_CHUNK_DURATION_US {
                    should_flush = true;
                }
            }
            if should_flush {
                chunks.push(ChunkWithMeta {
                    data: std::mem::take(&mut current),
                    pts: current_pts,
                });
                current_pts = None;
                current_end = None;
            }
        }

        if current.is_empty() {
            current_pts = Some(frame.pts_us);
            current_end = Some(frame.pts_us);
        }
        current.extend_from_slice(&data[frame.start..frame.start + frame.len]);
        let frame_end = frame.pts_us.saturating_add(frame.duration_us.max(0));
        current_end = Some(current_end.map_or(frame_end, |end| end.max(frame_end)));
    }

    if !current.is_empty() {
        chunks.push(ChunkWithMeta {
            data: current,
            pts: current_pts,
        });
    }
    chunks
}

struct OggPage {
    start: usize,
    len: usize,
    granule_pos: Option<u64>,
}

fn parse_ogg_pages(data: &[u8]) -> Option<Vec<OggPage>> {
    if data.len() < 27 || &data[..4] != b"OggS" {
        return None;
    }
    let mut pages = Vec::new();
    let mut offset = 0usize;
    while offset + 27 <= data.len() {
        if &data[offset..offset + 4] != b"OggS" {
            return None;
        }
        let seg_count = *data.get(offset + 26)? as usize;
        if offset + 27 + seg_count > data.len() {
            return None;
        }
        let mut body_len = 0usize;
        for i in 0..seg_count {
            body_len += data[offset + 27 + i] as usize;
        }
        let page_len = 27 + seg_count + body_len;
        if offset + page_len > data.len() {
            return None;
        }
        let granule_raw = u64::from_le_bytes(
            data[offset + 6..offset + 14].try_into().ok()?,
        );
        let granule_pos = if granule_raw == u64::MAX {
            None
        } else {
            Some(granule_raw)
        };
        pages.push(OggPage {
            start: offset,
            len: page_len,
            granule_pos,
        });
        offset += page_len;
    }
    if offset != data.len() {
        return None;
    }
    Some(pages)
}

fn parse_opus_head(data: &[u8]) -> Option<(u32, u16)> {
    let marker = b"OpusHead";
    let pos = data
        .windows(marker.len())
        .position(|window| window == marker)?;
    if pos + 19 > data.len() {
        return None;
    }
    let channels = data[pos + 9] as u16;
    let sample_rate = u32::from_le_bytes(
        data[pos + 12..pos + 16].try_into().ok()?,
    );
    Some((sample_rate, channels))
}

fn samples_to_us(samples: u64, sample_rate: u32) -> i64 {
    if sample_rate == 0 {
        return 0;
    }
    let micros = (samples as u128)
        .saturating_mul(1_000_000u128)
        / sample_rate as u128;
    micros.min(i64::MAX as u128) as i64
}

fn chunk_ogg_opus(
    data: &[u8],
    max_chunk_size: u64,
    container_type: Option<String>,
) -> Option<(Vec<ChunkWithMeta>, TrackPlaybackInfo)> {
    let pages = parse_ogg_pages(data)?;
    let (mut sample_rate, channels) = parse_opus_head(data).unwrap_or((48_000, 0));
    if sample_rate == 0 {
        sample_rate = 48_000;
    }
    let mut frames = Vec::with_capacity(pages.len());
    let mut prev_granule = None;
    let mut pts_samples = 0u64;
    for page in pages {
        let duration_samples = match (page.granule_pos, prev_granule) {
            (Some(current), Some(prev)) if current >= prev => current - prev,
            _ => 0,
        };
        if let Some(current) = page.granule_pos {
            prev_granule = Some(current);
        }
        let pts_us = samples_to_us(pts_samples, 48_000);
        let duration_us = samples_to_us(duration_samples, 48_000);
        frames.push(AudioFrameMeta {
            start: page.start,
            len: page.len,
            pts_us,
            duration_us,
        });
        pts_samples = pts_samples.saturating_add(duration_samples);
    }
    let chunks = group_frames_with_durations(data, &frames, max_chunk_size);
    Some((
        chunks,
        TrackPlaybackInfo {
            codec: "opus".to_string(),
            container_type,
            codec_extradata: None,
            width: None,
            height: None,
            sample_rate: Some(sample_rate),
            channels: if channels == 0 { None } else { Some(channels) },
            timebase_num: Some(1),
            timebase_den: Some(1_000_000),
        },
    ))
}

struct FlacStreamInfo {
    metadata_end: usize,
    sample_rate: u32,
    channels: Option<u16>,
}

fn parse_flac_streaminfo(data: &[u8]) -> Option<FlacStreamInfo> {
    if data.len() < 4 || &data[..4] != b"fLaC" {
        return None;
    }
    let mut offset = 4usize;
    let mut sample_rate = None;
    let mut channels = None;
    loop {
        if offset + 4 > data.len() {
            return None;
        }
        let header = data[offset];
        let is_last = (header & 0x80) != 0;
        let block_type = header & 0x7F;
        let length = ((data[offset + 1] as usize) << 16)
            | ((data[offset + 2] as usize) << 8)
            | data[offset + 3] as usize;
        let block_start = offset + 4;
        let block_end = block_start + length;
        if block_end > data.len() {
            return None;
        }
        if block_type == 0 && length >= 34 {
            let info = &data[block_start..block_end];
            let idx = 10;
            if idx + 8 <= info.len() {
                let raw = u64::from_be_bytes(info[idx..idx + 8].try_into().ok()?);
                let sr = ((raw >> 44) & 0xFFFFF) as u32;
                let ch = ((raw >> 41) & 0x7) as u16;
                sample_rate = Some(sr);
                channels = Some(ch + 1);
            }
        }
        offset = block_end;
        if is_last {
            break;
        }
    }
    Some(FlacStreamInfo {
        metadata_end: offset,
        sample_rate: sample_rate?,
        channels,
    })
}

struct FlacFrameHeader {
    block_size: u32,
    sample_rate: Option<u32>,
}

fn parse_flac_utf8_number_len(data: &[u8], offset: usize) -> Option<usize> {
    let first = *data.get(offset)?;
    if (first & 0x80) == 0 {
        return Some(1);
    }
    let leading = first.leading_ones() as usize;
    if leading < 2 || leading > 7 {
        return None;
    }
    if offset + leading > data.len() {
        return None;
    }
    for i in 1..leading {
        if (data[offset + i] & 0xC0) != 0x80 {
            return None;
        }
    }
    Some(leading)
}

fn flac_crc8(data: &[u8]) -> u8 {
    let mut crc = 0u8;
    for &byte in data {
        crc ^= byte;
        for _ in 0..8 {
            if (crc & 0x80) != 0 {
                crc = (crc << 1) ^ 0x07;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

fn flac_block_size_from_bits(bits: u8, data: &[u8], offset: &mut usize) -> Option<u32> {
    match bits {
        0b0000 => None,
        0b0001 => Some(192),
        0b0010 | 0b0011 | 0b0100 | 0b0101 => Some(144u32 << bits),
        0b0110 => {
            let value = *data.get(*offset)? as u32;
            *offset += 1;
            Some(value + 1)
        }
        0b0111 => {
            let hi = *data.get(*offset)? as u32;
            let lo = *data.get(*offset + 1)? as u32;
            *offset += 2;
            Some(((hi << 8) | lo) + 1)
        }
        0b1000 | 0b1001 | 0b1010 | 0b1011 | 0b1100 | 0b1101 | 0b1110 | 0b1111 => {
            Some(1u32 << bits)
        }
        _ => None,
    }
}

fn flac_sample_rate_from_bits(
    bits: u8,
    data: &[u8],
    offset: &mut usize,
    fallback: u32,
) -> Option<u32> {
    match bits {
        0b0000 => Some(fallback),
        0b0001 => Some(88_200),
        0b0010 => Some(176_400),
        0b0011 => Some(192_000),
        0b0100 => Some(8_000),
        0b0101 => Some(16_000),
        0b0110 => Some(22_050),
        0b0111 => Some(24_000),
        0b1000 => Some(32_000),
        0b1001 => Some(44_100),
        0b1010 => Some(48_000),
        0b1011 => Some(96_000),
        0b1100 => {
            let value = *data.get(*offset)? as u32;
            *offset += 1;
            Some(value * 1_000)
        }
        0b1101 => {
            let hi = *data.get(*offset)? as u32;
            let lo = *data.get(*offset + 1)? as u32;
            *offset += 2;
            Some((hi << 8) | lo)
        }
        0b1110 => {
            let hi = *data.get(*offset)? as u32;
            let lo = *data.get(*offset + 1)? as u32;
            *offset += 2;
            Some(((hi << 8) | lo) * 10)
        }
        _ => None,
    }
}

fn parse_flac_frame_header(
    data: &[u8],
    offset: usize,
    streaminfo_rate: u32,
) -> Option<FlacFrameHeader> {
    if offset + 4 > data.len() {
        return None;
    }
    if data[offset] != 0xFF || (data[offset + 1] & 0xFE) != 0xF8 {
        return None;
    }
    let block_bits = data[offset + 2] >> 4;
    let sample_bits = data[offset + 2] & 0x0F;
    if (data[offset + 3] & 0x01) != 0 {
        return None;
    }

    let mut cursor = offset + 4;
    let utf8_len = parse_flac_utf8_number_len(data, cursor)?;
    cursor += utf8_len;

    let block_size = flac_block_size_from_bits(block_bits, data, &mut cursor)?;
    let sample_rate =
        flac_sample_rate_from_bits(sample_bits, data, &mut cursor, streaminfo_rate);

    if cursor >= data.len() {
        return None;
    }
    let crc_expected = data[cursor];
    let crc_actual = flac_crc8(&data[offset..cursor]);
    if crc_expected != crc_actual {
        return None;
    }
    Some(FlacFrameHeader {
        block_size,
        sample_rate,
    })
}

fn chunk_flac_from_bytes(
    data: &[u8],
    max_chunk_size: u64,
    container_type: Option<String>,
) -> Option<(Vec<ChunkWithMeta>, TrackPlaybackInfo)> {
    let info = parse_flac_streaminfo(data)?;
    let mut frames = Vec::new();
    let mut cursor = info.metadata_end;
    let mut last_frame_start = None;
    let mut last_header: Option<FlacFrameHeader> = None;
    let mut pts_samples = 0u64;

    while cursor + 4 <= data.len() {
        let mut found = None;
        let mut search = cursor;
        while search + 4 <= data.len() {
            if let Some(header) = parse_flac_frame_header(data, search, info.sample_rate) {
                found = Some((search, header));
                break;
            }
            search += 1;
        }
        let Some((frame_start, header)) = found else { break };

        if let Some(prev_start) = last_frame_start {
            let frame_len = frame_start.saturating_sub(prev_start);
            let sample_rate = last_header
                .as_ref()
                .and_then(|h| h.sample_rate)
                .unwrap_or(info.sample_rate);
            let Some(last) = last_header.as_ref() else {
                break;
            };
            let duration_us = samples_to_us(last.block_size as u64, sample_rate);
            frames.push(AudioFrameMeta {
                start: prev_start,
                len: frame_len,
                pts_us: samples_to_us(pts_samples, sample_rate),
                duration_us,
            });
            pts_samples = pts_samples.saturating_add(last.block_size as u64);
        } else if info.metadata_end > 0 {
            frames.push(AudioFrameMeta {
                start: 0,
                len: info.metadata_end,
                pts_us: 0,
                duration_us: 0,
            });
        }

        last_frame_start = Some(frame_start);
        last_header = Some(header);
        cursor = frame_start.saturating_add(2);
    }

    if let Some(prev_start) = last_frame_start {
        let frame_len = data.len().saturating_sub(prev_start);
        let sample_rate = last_header
            .as_ref()
            .and_then(|h| h.sample_rate)
            .unwrap_or(info.sample_rate);
        let block_size = last_header.as_ref()?.block_size as u64;
        let duration_us = samples_to_us(block_size, sample_rate);
        frames.push(AudioFrameMeta {
            start: prev_start,
            len: frame_len,
            pts_us: samples_to_us(pts_samples, sample_rate),
            duration_us,
        });
    }

    if frames.is_empty() {
        return None;
    }

    let chunks = group_frames_with_durations(data, &frames, max_chunk_size);
    Some((
        chunks,
        TrackPlaybackInfo {
            codec: "flac".to_string(),
            container_type,
            codec_extradata: None,
            width: None,
            height: None,
            sample_rate: Some(info.sample_rate),
            channels: info.channels,
            timebase_num: Some(1),
            timebase_den: Some(1_000_000),
        },
    ))
}

pub struct AnnexbNal {
    pub start: usize,
    pub end: usize,
    pub is_idr: bool,
    pub pts: Option<i64>,
}

pub enum AnnexbCodec {
    H264,
    H265,
}

pub struct AnnexbParseInfo {
    pub nals: Vec<AnnexbNal>,
    pub codec: AnnexbCodec,
    pub codec_extradata: Option<Vec<u8>>,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub timebase_num: Option<u32>,
    pub timebase_den: Option<u32>,
}

pub fn parse_annexb_nals(data: &[u8]) -> Option<AnnexbParseInfo> {
    if looks_like_isobmff(data) {
        return None;
    }
    let mut starts = Vec::new();
    let mut i = 0usize;
    while i + 3 <= data.len() {
        if data[i] == 0 && data[i + 1] == 0 && data[i + 2] == 1 {
            starts.push((i, 3));
            i += 3;
            continue;
        }
        if i + 4 <= data.len()
            && data[i] == 0
            && data[i + 1] == 0
            && data[i + 2] == 0
            && data[i + 3] == 1
        {
            starts.push((i, 4));
            i += 4;
            continue;
        }
        i += 1;
    }
    if starts.len() < 2 {
        return None;
    }

    // Try to detect codec by looking at first few NALs
    let mut h264_score = 0;
    let mut h265_score = 0;
    for idx in 0..starts.len().min(10) {
        let (start, code_len) = starts[idx];
        if start + code_len >= data.len() {
            continue;
        }
        let first_byte = data[start + code_len];
        let h264_type = first_byte & 0x1F;
        let h265_type = (first_byte & 0x7E) >> 1;

        if matches!(h264_type, 7 | 8 | 5 | 1) {
            h264_score += 1;
        }
        if matches!(h265_type, 32 | 33 | 34 | 19 | 20 | 1) {
            h265_score += 1;
        }
    }

    let codec = if h265_score > h264_score {
        AnnexbCodec::H265
    } else {
        AnnexbCodec::H264
    };

    let mut nals = Vec::new();
    let mut sps = None;
    let mut pps = None;
    let mut vps = None; // For H.265
    let mut current_pts = 0i64;
    for idx in 0..starts.len() {
        let (start, code_len) = starts[idx];
        let end = if idx + 1 < starts.len() {
            starts[idx + 1].0
        } else {
            data.len()
        };
        if start + code_len >= end {
            continue;
        }

        let first_byte = data[start + code_len];
        let (is_idr, is_vcl, nal_type) = match codec {
            AnnexbCodec::H264 => {
                let nt = first_byte & 0x1F;
                (nt == 5, (1..=5).contains(&nt), nt)
            }
            AnnexbCodec::H265 => {
                let nt = (first_byte & 0x7E) >> 1;
                (nt == 19 || nt == 20, (0..=31).contains(&nt), nt)
            }
        };

        if is_vcl {
            let pts = current_pts;
            current_pts = current_pts.saturating_add(1);
            nals.push(AnnexbNal {
                start,
                end,
                is_idr,
                pts: Some(pts),
            });
        } else {
            nals.push(AnnexbNal {
                start,
                end,
                is_idr,
                pts: Some(current_pts),
            });
        }

        match codec {
            AnnexbCodec::H264 => {
                if nal_type == 7 && sps.is_none() {
                    sps = Some(data[start + code_len..end].to_vec());
                } else if nal_type == 8 && pps.is_none() {
                    pps = Some(data[start + code_len..end].to_vec());
                }
            }
            AnnexbCodec::H265 => {
                if nal_type == 32 && vps.is_none() {
                    vps = Some(data[start + code_len..end].to_vec());
                } else if nal_type == 33 && sps.is_none() {
                    sps = Some(data[start + code_len..end].to_vec());
                } else if nal_type == 34 && pps.is_none() {
                    pps = Some(data[start + code_len..end].to_vec());
                }
            }
        }
    }

    if nals.is_empty() {
        return None;
    }

    let (codec_extradata, width, height, timebase_num, timebase_den) = match codec {
        AnnexbCodec::H264 => match (sps.as_deref(), pps.as_deref()) {
            (Some(sps_bytes), Some(pps_bytes)) => {
                let extradata = build_annexb_extradata(&[sps_bytes, pps_bytes]);
                let (width, height) = parse_h264_sps_dimensions(sps_bytes).unwrap_or((0, 0));
                let timing = parse_h264_sps_timing(sps_bytes);
                let (timebase_num, timebase_den) = timing
                    .map(|(num, den)| (Some(num), Some(den)))
                    .unwrap_or((None, None));
                (
                    Some(extradata),
                    if width == 0 { None } else { Some(width) },
                    if height == 0 { None } else { Some(height) },
                    timebase_num,
                    timebase_den,
                )
            }
            _ => (None, None, None, None, None),
        },
        AnnexbCodec::H265 => {
            let mut units = Vec::new();
            if let Some(v) = vps.as_deref() {
                units.push(v);
            }
            if let Some(s) = sps.as_deref() {
                units.push(s);
            }
            if let Some(p) = pps.as_deref() {
                units.push(p);
            }
            let extradata = build_annexb_extradata(&units);
            (
                if extradata.is_empty() {
                    None
                } else {
                    Some(extradata)
                },
                None,
                None,
                None,
                None,
            )
        }
    };

    Some(AnnexbParseInfo {
        nals,
        codec,
        codec_extradata,
        width,
        height,
        timebase_num,
        timebase_den,
    })
}

pub fn looks_like_isobmff(data: &[u8]) -> bool {
    if data.len() < 12 {
        return false;
    }
    let box_type = &data[4..8];
    if !box_type.iter().all(|b| b.is_ascii_alphanumeric()) {
        return false;
    }
    if matches!(
        box_type,
        b"ftyp"
            | b"moov"
            | b"moof"
            | b"mdat"
            | b"free"
            | b"skip"
            | b"wide"
            | b"uuid"
            | b"jumb"
            | b"meta"
    ) {
        return true;
    }
    let scan_len = data.len().min(4096);
    let mut offset = 0usize;
    while offset + 8 <= scan_len {
        let size = u32::from_be_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]) as usize;
        let kind = &data[offset + 4..offset + 8];
        if matches!(
            kind,
            b"ftyp" | b"moov" | b"moof" | b"mdat" | b"jumb" | b"meta"
        ) {
            return true;
        }
        if size < 8 || size > scan_len - offset {
            break;
        }
        offset += size;
    }
    false
}

pub fn group_nals(data: &[u8], nals: &[AnnexbNal], max_chunk_size: u64) -> Vec<ChunkWithMeta> {
    let mut chunks = Vec::new();
    let mut current = Vec::new();
    let mut current_pts = None;
    for nal in nals {
        let nal_len = nal.end - nal.start;
        if nal.is_idr && !current.is_empty() {
            chunks.push(ChunkWithMeta {
                data: std::mem::take(&mut current),
                pts: current_pts.take(),
            });
        }
        if !current.is_empty() && current.len() as u64 + nal_len as u64 > max_chunk_size {
            chunks.push(ChunkWithMeta {
                data: std::mem::take(&mut current),
                pts: current_pts.take(),
            });
        }
        if current.is_empty() {
            current_pts = nal.pts;
        }
        current.extend_from_slice(&data[nal.start..nal.end]);
    }
    if !current.is_empty() {
        chunks.push(ChunkWithMeta {
            data: current,
            pts: current_pts,
        });
    }
    chunks
}

pub fn build_aac_extradata(
    audio_object_type: u8,
    sample_rate_index: u8,
    channel_config: Option<u16>,
) -> Vec<u8> {
    let channel_config = channel_config.unwrap_or(0) as u8;
    let packed = ((audio_object_type & 0x1F) as u16) << 11
        | ((sample_rate_index & 0x0F) as u16) << 7
        | ((channel_config & 0x0F) as u16) << 3;
    vec![(packed >> 8) as u8, packed as u8]
}

pub fn build_avcc_extradata(sps: &[u8], pps: &[u8]) -> Vec<u8> {
    let profile_idc = sps.get(1).copied().unwrap_or(0);
    let compatibility = sps.get(2).copied().unwrap_or(0);
    let level_idc = sps.get(3).copied().unwrap_or(0);
    let mut extradata = Vec::new();
    extradata.push(1); // configurationVersion
    extradata.push(profile_idc);
    extradata.push(compatibility);
    extradata.push(level_idc);
    extradata.push(0xFF); // lengthSizeMinusOne (4 bytes)
    extradata.push(0xE1); // numOfSequenceParameterSets = 1
    extradata.extend_from_slice(&(sps.len() as u16).to_be_bytes());
    extradata.extend_from_slice(sps);
    extradata.push(1); // numOfPictureParameterSets = 1
    extradata.extend_from_slice(&(pps.len() as u16).to_be_bytes());
    extradata.extend_from_slice(pps);
    extradata
}

pub fn build_annexb_extradata(units: &[&[u8]]) -> Vec<u8> {
    let mut extradata = Vec::new();
    for unit in units {
        if unit.is_empty() {
            continue;
        }
        extradata.extend_from_slice(&[0, 0, 0, 1]);
        extradata.extend_from_slice(unit);
    }
    extradata
}

pub fn parse_h264_sps_dimensions(sps: &[u8]) -> Option<(u32, u32)> {
    if sps.len() < 4 {
        return None;
    }
    let rbsp = remove_emulation_prevention_bytes(&sps[1..]);
    let mut reader = BitReader::new(&rbsp);
    let profile_idc = reader.read_bits(8)? as u8;
    reader.read_bits(8)?;
    reader.read_bits(8)?;
    reader.read_ue()?;
    let mut chroma_format_idc = 1u32;
    if matches!(
        profile_idc,
        100 | 110 | 122 | 244 | 44 | 83 | 86 | 118 | 128 | 138 | 139 | 134
    ) {
        chroma_format_idc = reader.read_ue()?;
        if chroma_format_idc == 3 {
            reader.read_bits(1)?;
        }
        reader.read_ue()?;
        reader.read_ue()?;
        reader.read_bits(1)?;
        let seq_scaling_matrix_present_flag = reader.read_bits(1)?;
        if seq_scaling_matrix_present_flag == 1 {
            let scaling_list_count = if chroma_format_idc == 3 { 12 } else { 8 };
            for i in 0..scaling_list_count {
                let scaling_list_present = reader.read_bits(1)?;
                if scaling_list_present == 1 {
                    skip_scaling_list(&mut reader, if i < 6 { 16 } else { 64 })?;
                }
            }
        }
    }
    reader.read_ue()?;
    let pic_order_cnt_type = reader.read_ue()?;
    if pic_order_cnt_type == 0 {
        reader.read_ue()?;
    } else if pic_order_cnt_type == 1 {
        reader.read_bits(1)?;
        reader.read_se()?;
        reader.read_se()?;
        let num_ref_frames_in_pic_order_cnt_cycle = reader.read_ue()?;
        for _ in 0..num_ref_frames_in_pic_order_cnt_cycle {
            reader.read_se()?;
        }
    }
    reader.read_ue()?;
    reader.read_bits(1)?;
    let pic_width_in_mbs_minus1 = reader.read_ue()?;
    let pic_height_in_map_units_minus1 = reader.read_ue()?;
    let frame_mbs_only_flag = reader.read_bits(1)?;
    if frame_mbs_only_flag == 0 {
        reader.read_bits(1)?;
    }
    reader.read_bits(1)?;
    let frame_cropping_flag = reader.read_bits(1)?;
    let mut frame_crop_left = 0u32;
    let mut frame_crop_right = 0u32;
    let mut frame_crop_top = 0u32;
    let mut frame_crop_bottom = 0u32;
    if frame_cropping_flag == 1 {
        frame_crop_left = reader.read_ue()?;
        frame_crop_right = reader.read_ue()?;
        frame_crop_top = reader.read_ue()?;
        frame_crop_bottom = reader.read_ue()?;
    }
    let width = (pic_width_in_mbs_minus1 + 1) * 16;
    let mut height = (pic_height_in_map_units_minus1 + 1) * 16;
    if frame_mbs_only_flag == 0 {
        height *= 2;
    }
    let crop_unit_x = match chroma_format_idc {
        0 | 3 => 1,
        _ => 2,
    };
    let crop_unit_y = match chroma_format_idc {
        0 | 3 => 2 - frame_mbs_only_flag,
        _ => 2 * (2 - frame_mbs_only_flag),
    };
    let width = width.saturating_sub((frame_crop_left + frame_crop_right) * crop_unit_x);
    let height = height.saturating_sub((frame_crop_top + frame_crop_bottom) * crop_unit_y);
    Some((width, height))
}

pub fn parse_h264_sps_timing(sps: &[u8]) -> Option<(u32, u32)> {
    if sps.len() < 4 {
        return None;
    }
    let rbsp = remove_emulation_prevention_bytes(&sps[1..]);
    let mut reader = BitReader::new(&rbsp);
    let profile_idc = reader.read_bits(8)? as u8;
    reader.read_bits(8)?;
    reader.read_bits(8)?;
    reader.read_ue()?;
    if matches!(
        profile_idc,
        100 | 110 | 122 | 244 | 44 | 83 | 86 | 118 | 128 | 138 | 139 | 134
    ) {
        let chroma_format_idc = reader.read_ue()?;
        if chroma_format_idc == 3 {
            reader.read_bits(1)?;
        }
        reader.read_ue()?;
        reader.read_ue()?;
        reader.read_bits(1)?;
        let seq_scaling_matrix_present_flag = reader.read_bits(1)?;
        if seq_scaling_matrix_present_flag == 1 {
            let scaling_list_count = if chroma_format_idc == 3 { 12 } else { 8 };
            for i in 0..scaling_list_count {
                let scaling_list_present = reader.read_bits(1)?;
                if scaling_list_present == 1 {
                    skip_scaling_list(&mut reader, if i < 6 { 16 } else { 64 })?;
                }
            }
        }
    }
    reader.read_ue()?;
    let pic_order_cnt_type = reader.read_ue()?;
    if pic_order_cnt_type == 0 {
        reader.read_ue()?;
    } else if pic_order_cnt_type == 1 {
        reader.read_bits(1)?;
        reader.read_se()?;
        reader.read_se()?;
        let num_ref_frames_in_pic_order_cnt_cycle = reader.read_ue()?;
        for _ in 0..num_ref_frames_in_pic_order_cnt_cycle {
            reader.read_se()?;
        }
    }
    reader.read_ue()?;
    reader.read_bits(1)?;
    reader.read_ue()?;
    reader.read_ue()?;
    let frame_mbs_only_flag = reader.read_bits(1)?;
    if frame_mbs_only_flag == 0 {
        reader.read_bits(1)?;
    }
    reader.read_bits(1)?;
    let frame_cropping_flag = reader.read_bits(1)?;
    if frame_cropping_flag == 1 {
        reader.read_ue()?;
        reader.read_ue()?;
        reader.read_ue()?;
        reader.read_ue()?;
    }
    let vui_parameters_present_flag = reader.read_bits(1)?;
    if vui_parameters_present_flag == 0 {
        return None;
    }
    let aspect_ratio_info_present_flag = reader.read_bits(1)?;
    if aspect_ratio_info_present_flag == 1 {
        let aspect_ratio_idc = reader.read_bits(8)?;
        if aspect_ratio_idc == 255 {
            reader.read_bits(16)?;
            reader.read_bits(16)?;
        }
    }
    let overscan_info_present_flag = reader.read_bits(1)?;
    if overscan_info_present_flag == 1 {
        reader.read_bits(1)?;
    }
    let video_signal_type_present_flag = reader.read_bits(1)?;
    if video_signal_type_present_flag == 1 {
        reader.read_bits(3)?;
        reader.read_bits(1)?;
        let colour_description_present_flag = reader.read_bits(1)?;
        if colour_description_present_flag == 1 {
            reader.read_bits(8)?;
            reader.read_bits(8)?;
            reader.read_bits(8)?;
        }
    }
    let chroma_loc_info_present_flag = reader.read_bits(1)?;
    if chroma_loc_info_present_flag == 1 {
        reader.read_ue()?;
        reader.read_ue()?;
    }
    let timing_info_present_flag = reader.read_bits(1)?;
    if timing_info_present_flag == 0 {
        return None;
    }
    let num_units_in_tick = reader.read_bits(32)?;
    let time_scale = reader.read_bits(32)?;
    let _fixed_frame_rate_flag = reader.read_bits(1)?;
    if num_units_in_tick == 0 || time_scale == 0 {
        return None;
    }
    let timebase_num = num_units_in_tick.saturating_mul(2);
    Some((timebase_num, time_scale))
}

pub fn remove_emulation_prevention_bytes(data: &[u8]) -> Vec<u8> {
    let mut cleaned = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        if i + 2 < data.len() && data[i] == 0 && data[i + 1] == 0 && data[i + 2] == 3 {
            cleaned.push(0);
            cleaned.push(0);
            i += 3;
            continue;
        }
        cleaned.push(data[i]);
        i += 1;
    }
    cleaned
}

pub struct BitReader<'a> {
    data: &'a [u8],
    bit_pos: usize,
}

impl<'a> BitReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, bit_pos: 0 }
    }

    pub fn read_bits(&mut self, count: usize) -> Option<u32> {
        let mut value = 0u32;
        for _ in 0..count {
            value <<= 1;
            value |= self.read_bit()? as u32;
        }
        Some(value)
    }

    pub fn read_bit(&mut self) -> Option<u8> {
        let byte_pos = self.bit_pos / 8;
        if byte_pos >= self.data.len() {
            return None;
        }
        let bit_offset = 7 - (self.bit_pos % 8);
        let bit = (self.data[byte_pos] >> bit_offset) & 1;
        self.bit_pos += 1;
        Some(bit)
    }

    pub fn read_ue(&mut self) -> Option<u32> {
        let mut zeros = 0usize;
        while self.read_bit()? == 0 {
            zeros += 1;
        }
        let mut value = 0u32;
        if zeros > 0 {
            value = self.read_bits(zeros)?;
        }
        Some((1u32 << zeros) - 1 + value)
    }

    pub fn read_se(&mut self) -> Option<i32> {
        let code_num = self.read_ue()? as i32;
        let sign = if code_num % 2 == 0 { -1 } else { 1 };
        Some(((code_num + 1) / 2) * sign)
    }
}

pub fn skip_scaling_list(reader: &mut BitReader<'_>, size: usize) -> Option<()> {
    let mut last_scale = 8i32;
    let mut next_scale = 8i32;
    for _ in 0..size {
        if next_scale != 0 {
            let delta_scale = reader.read_se()?;
            next_scale = (last_scale + delta_scale + 256) % 256;
        }
        last_scale = if next_scale == 0 {
            last_scale
        } else {
            next_scale
        };
    }
    Some(())
}

pub fn fallback_chunking(data: &[u8], max_chunk_size: u64) -> Vec<ChunkWithMeta> {
    let mut chunks = Vec::new();
    let mut offset = 0usize;
    let chunk_size = max_chunk_size as usize;
    while offset < data.len() {
        let end = (offset + chunk_size).min(data.len());
        chunks.push(ChunkWithMeta {
            data: data[offset..end].to_vec(),
            pts: None,
        });
        offset = end;
    }
    chunks
}

pub fn codec_to_ffmpeg_format(codec: &str) -> Option<&'static str> {
    match codec.to_lowercase().as_str() {
        "h264" => Some("h264"),
        "h265" | "hevc" => Some("hevc"),
        // Use the raw AAC demuxer name for ffmpeg input; some builds don't expose "adts".
        "aac" => Some("aac"),
        "opus" => Some("opus"),
        "flac" => Some("flac"),
        "raw" => Some("data"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_h265_detection() {
        let mut data = vec![0, 0, 0, 1, 0x40, 0x01]; // VPS (type 32)
        data.extend_from_slice(&[0; 10]);
        data.extend_from_slice(&[0, 0, 0, 1, 0x42, 0x01]); // SPS (type 33)
        data.extend_from_slice(&[0; 10]);
        data.extend_from_slice(&[0, 0, 0, 1, 0x26, 0x01]); // IDR_W_RADL (type 19)
        data.extend_from_slice(&[0; 10]);

        let info = parse_annexb_nals(&data).unwrap();
        assert!(matches!(info.codec, AnnexbCodec::H265));
        assert_eq!(info.nals.len(), 3);
        assert!(info.nals[2].is_idr);
    }
}
