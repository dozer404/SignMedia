use crate::models::{TrackChunkIndexEntry, TrackMetadata};

pub fn pts_to_seconds(pts: i64, timebase_num: u32, timebase_den: u32) -> Option<f64> {
    if timebase_num == 0 || timebase_den == 0 {
        return None;
    }
    Some(pts as f64 * timebase_num as f64 / timebase_den as f64)
}

pub fn seconds_to_pts_floor(time: f64, timebase_num: u32, timebase_den: u32) -> Option<i64> {
    if !time.is_finite() || time < 0.0 || timebase_num == 0 || timebase_den == 0 {
        return None;
    }
    let raw = time * timebase_den as f64 / timebase_num as f64;
    Some(raw.floor() as i64)
}

pub fn seconds_to_pts_ceil(time: f64, timebase_num: u32, timebase_den: u32) -> Option<i64> {
    if !time.is_finite() || time < 0.0 || timebase_num == 0 || timebase_den == 0 {
        return None;
    }
    let raw = time * timebase_den as f64 / timebase_num as f64;
    Some(raw.ceil() as i64)
}

pub fn time_range_to_chunk_range(
    track: &TrackMetadata,
    entries: &[TrackChunkIndexEntry],
    start_time: Option<f64>,
    end_time: Option<f64>,
) -> Option<(u64, u64)> {
    let (timebase_num, timebase_den) = (track.timebase_num?, track.timebase_den?);
    let mut pts_entries: Vec<(i64, u64)> = entries
        .iter()
        .filter_map(|entry| entry.pts.map(|pts| (pts, entry.chunk_index)))
        .collect();
    if pts_entries.is_empty() {
        return None;
    }
    pts_entries.sort_by_key(|(pts, _)| *pts);
    let first_pts = pts_entries.first()?.0;
    let last_pts = pts_entries.last()?.0;
    let start_pts = match start_time {
        Some(time) => seconds_to_pts_floor(time, timebase_num, timebase_den)?,
        None => first_pts,
    };
    let end_pts = match end_time {
        Some(time) => seconds_to_pts_ceil(time, timebase_num, timebase_den)?,
        None => last_pts.saturating_add(1),
    };
    let start_chunk = pts_entries
        .iter()
        .find(|(pts, _)| *pts >= start_pts)
        .map(|(_, chunk_index)| *chunk_index)?;
    let end_chunk = match pts_entries
        .iter()
        .find(|(pts, _)| *pts >= end_pts)
        .map(|(_, chunk_index)| *chunk_index)
    {
        Some(chunk) => chunk,
        None => pts_entries
            .last()
            .map(|(_, chunk_index)| chunk_index.saturating_add(1))?,
    };
    if start_chunk >= end_chunk {
        None
    } else {
        Some((start_chunk, end_chunk))
    }
}

pub fn chunk_range_to_time_range(
    track: &TrackMetadata,
    entries: &[TrackChunkIndexEntry],
    start_chunk: u64,
    end_chunk: u64,
) -> Option<(f64, f64)> {
    let (timebase_num, timebase_den) = (track.timebase_num?, track.timebase_den?);
    let mut filtered: Vec<&TrackChunkIndexEntry> = entries
        .iter()
        .filter(|entry| {
            entry.pts.is_some() && entry.chunk_index >= start_chunk && entry.chunk_index < end_chunk
        })
        .collect();
    if filtered.is_empty() {
        return None;
    }
    filtered.sort_by_key(|entry| entry.chunk_index);
    let start_pts = filtered.first()?.pts?;
    let end_pts = filtered.last()?.pts?.saturating_add(1);
    let start_time = pts_to_seconds(start_pts, timebase_num, timebase_den)?;
    let end_time = pts_to_seconds(end_pts, timebase_num, timebase_den)?;
    Some((start_time, end_time))
}
