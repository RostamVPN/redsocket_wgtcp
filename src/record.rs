// Copyright 2026 Internet Mastering & Company, Inc.
// SPDX-License-Identifier: Apache-2.0

//! WGTCP carrier record framing.

use std::collections::VecDeque;

/// `WG_TCP_RECORD_DATA` — the only record type the module emits or accepts.
pub const RECORD_DATA: u8 = 0;
/// `WG_TCP_FRAG_FLAG` — inner IPv4 fragment metadata follows the header.
pub const FRAG_FLAG: u8 = 0x1;

/// `WG_TCP_ENCAP_HDR_LEN`.
pub const ENCAP_HDR_LEN: usize = 8;
/// `WG_TCP_FRAG_HDR_LEN`.
pub const FRAG_HDR_LEN: usize = 4;

/// `MESSAGE_MINIMUM_LENGTH` = `message_data_len(0)` = `noise_encrypted_len(0)`
/// (16, the Poly1305 tag) + `sizeof(struct message_data)` (16).
pub const MESSAGE_MINIMUM_LENGTH: usize = 32;

/// `WG_MAX_PACKET_SIZE` = 65535 + `WG_TCP_ENCAP_HDR_LEN`.
pub const WG_MAX_PACKET_SIZE: usize = 65535 + ENCAP_HDR_LEN;

/// Mirror of the kernel's `wg_header_checksum()`.
fn header_checksum(total_len: u32, ty: u8, flags: u8) -> u16 {
    let mut ck: u16 = 0;
    ck ^= ((total_len >> 16) & 0xFFFF) as u16;
    ck ^= (total_len & 0xFFFF) as u16;
    ck ^= ((flags as u16) << 8) | (ty as u16);
    ck = ck.rotate_left(5);
    ck ^= 0xA5A5;
    ck
}

/// Serialize one WireGuard message into a carrier record.
pub fn encode(payload: &[u8], out: &mut Vec<u8>) -> Result<(), RecordError> {
    if payload.len() < MESSAGE_MINIMUM_LENGTH {
        return Err(RecordError::TooShort(payload.len()));
    }
    let total_len = ENCAP_HDR_LEN + payload.len();
    if total_len > WG_MAX_PACKET_SIZE {
        return Err(RecordError::TooLong(total_len));
    }

    let total = total_len as u32;
    let ck = header_checksum(total, RECORD_DATA, 0);

    out.reserve(total_len);
    out.extend_from_slice(&total.to_be_bytes());
    out.push(RECORD_DATA);
    out.push(0);
    out.extend_from_slice(&ck.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(())
}

/// A parsed header candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Header {
    total_len: usize,
    ty: u8,
    flags: u8,
}

impl Header {
    /// Header length including the optional fragment header.
    fn header_len(&self) -> usize {
        if self.flags & FRAG_FLAG != 0 {
            ENCAP_HDR_LEN + FRAG_HDR_LEN
        } else {
            ENCAP_HDR_LEN
        }
    }
}

/// Port of the kernel's `wg_check_potential_header_validity()`.
fn parse_header(buf: &[u8]) -> Option<Header> {
    if buf.len() < ENCAP_HDR_LEN {
        return None;
    }
    let total_len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let ty = buf[4];
    let flags = buf[5];
    let ck = u16::from_be_bytes([buf[6], buf[7]]);

    if header_checksum(total_len, ty, flags) != ck {
        return None;
    }
    if ty != RECORD_DATA {
        return None;
    }
    if flags & !FRAG_FLAG != 0 {
        return None;
    }

    let mut minimum = ENCAP_HDR_LEN + MESSAGE_MINIMUM_LENGTH;
    if flags & FRAG_FLAG != 0 {
        minimum += FRAG_HDR_LEN;
    }
    let total = total_len as usize;
    if total < minimum || total > WG_MAX_PACKET_SIZE {
        return None;
    }

    Some(Header {
        total_len: total,
        ty,
        flags,
    })
}

#[derive(Debug, thiserror::Error)]
pub enum RecordError {
    #[error("payload {0} shorter than WireGuard minimum message length")]
    TooShort(usize),
    #[error("record length {0} exceeds WG_MAX_PACKET_SIZE")]
    TooLong(usize),
}

/// Streaming record parser over a TCP byte stream.
pub struct RecordParser {
    buf: VecDeque<u8>,
    /// Contiguous scratch so we can hand out slices without copying twice.
    scratch: Vec<u8>,
    resyncs: u64,
}

impl Default for RecordParser {
    fn default() -> Self {
        Self::new()
    }
}

impl RecordParser {
    pub fn new() -> Self {
        Self {
            buf: VecDeque::new(),
            scratch: Vec::new(),
            resyncs: 0,
        }
    }

    /// Number of times the parser had to scan for a new header offset.
    pub fn resyncs(&self) -> u64 {
        self.resyncs
    }

    pub fn push(&mut self, data: &[u8]) {
        self.buf.extend(data.iter().copied());
    }

    /// Pull the next complete WireGuard message, if one is fully buffered.
    pub fn next_message(&mut self) -> Option<Vec<u8>> {
        loop {
            if self.buf.len() < ENCAP_HDR_LEN {
                return None;
            }

            self.materialize();

            match parse_header(&self.scratch) {
                Some(hdr) => {
                    if self.scratch.len() < hdr.total_len {
                        return None;
                    }
                    let start = hdr.header_len();
                    let payload = self.scratch[start..hdr.total_len].to_vec();
                    self.buf.drain(..hdr.total_len);
                    return Some(payload);
                }
                None => {
                    match self.find_resync_offset() {
                        Some(off) => {
                            self.resyncs += 1;
                            self.buf.drain(..off);
                            continue;
                        }
                        None => {
                            let keep = ENCAP_HDR_LEN - 1;
                            if self.buf.len() > keep {
                                self.resyncs += 1;
                                let drop = self.buf.len() - keep;
                                self.buf.drain(..drop);
                            }
                            return None;
                        }
                    }
                }
            }
        }
    }

    /// Copy the ring buffer into contiguous scratch for slice-based parsing.
    fn materialize(&mut self) {
        self.scratch.clear();
        self.scratch.reserve(self.buf.len());
        let (a, b) = self.buf.as_slices();
        self.scratch.extend_from_slice(a);
        self.scratch.extend_from_slice(b);
    }

    /// Scan for the next byte offset that starts a structurally valid header.
    fn find_resync_offset(&self) -> Option<usize> {
        let n = self.scratch.len();
        if n < ENCAP_HDR_LEN {
            return None;
        }
        (1..=(n - ENCAP_HDR_LEN)).find(|&off| parse_header(&self.scratch[off..]).is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Independent reimplementation of the C checksum, transcribed statement by
    /// statement from `wg_header_checksum()` using explicit wrapping ops rather
    /// than `rotate_left`, so a mistake in the shift/rotate reasoning in
    /// `header_checksum` would show up as a mismatch here.
    fn checksum_reference(total_len: u32, ty: u8, flags: u8) -> u16 {
        let mut ck: u32 = 0;
        ck ^= (total_len >> 16) & 0xFFFF;
        ck ^= total_len & 0xFFFF;
        ck ^= ((flags as u32) << 8) | (ty as u32);
        ck = ((ck << 5) | (ck >> (16 - 5))) & 0xFFFF;
        ck ^= 0xA5A5;
        ck as u16
    }

    /// Golden vectors produced by the WGTCP kernel module's own checksum routine.
    const KERNEL_VECTORS: &[(u32, u8, u8, u16)] = &[
        (40, 0, 0, 41125),
        (40, 0, 1, 32933),
        (41, 0, 0, 41093),
        (41, 0, 1, 32901),
        (64, 0, 0, 44453),
        (64, 0, 1, 36261),
        (100, 0, 0, 43301),
        (100, 0, 1, 35109),
        (148, 0, 0, 46885),
        (148, 0, 1, 38693),
        (255, 0, 0, 47685),
        (255, 0, 1, 39493),
        (256, 0, 0, 34213),
        (256, 0, 1, 42405),
        (1420, 0, 0, 5157),
        (1420, 0, 1, 13349),
        (1500, 0, 0, 7717),
        (1500, 0, 1, 15909),
        (4096, 0, 0, 42407),
        (4096, 0, 1, 34215),
        (32768, 0, 0, 42421),
        (32768, 0, 1, 34229),
        (65535, 0, 0, 23130),
        (65535, 0, 1, 31322),
        (65543, 0, 0, 42341),
        (65543, 0, 1, 34149),
        (12345, 0, 0, 41603),
        (12345, 0, 1, 33411),
        (999, 0, 0, 55621),
        (999, 0, 1, 63813),
    ];

    #[test]
    fn checksum_matches_kernel_golden_vectors() {
        for &(len, ty, flags, expected) in KERNEL_VECTORS {
            assert_eq!(
                header_checksum(len, ty, flags),
                expected,
                "kernel mismatch: len={len} type={ty} flags={flags}"
            );
        }
    }

    #[test]
    fn checksum_matches_reference() {
        for len in [40u32, 64, 148, 1420, 1500, 65535, 65543] {
            for flags in [0u8, FRAG_FLAG] {
                assert_eq!(
                    header_checksum(len, RECORD_DATA, flags),
                    checksum_reference(len, RECORD_DATA, flags),
                    "len={len} flags={flags}"
                );
            }
        }
    }

    /// The kernel deliberately avoids trivial checksums; confirm the 0xA5A5 fold is
    /// applied so an all-zero header cannot validate.
    #[test]
    fn all_zero_header_is_rejected() {
        assert!(parse_header(&[0u8; ENCAP_HDR_LEN]).is_none());
    }

    #[test]
    fn header_layout_is_exact() {
        let payload = vec![0xABu8; 64];
        let mut out = Vec::new();
        encode(&payload, &mut out).unwrap();

        assert_eq!(out.len(), ENCAP_HDR_LEN + 64);

        assert_eq!(&out[0..4], &(72u32).to_be_bytes());
        assert_eq!(out[4], RECORD_DATA);
        assert_eq!(out[5], 0);
        assert_eq!(
            &out[6..8],
            &header_checksum(72, RECORD_DATA, 0).to_be_bytes()
        );
        assert_eq!(&out[8..], &payload[..]);
    }

    #[test]
    fn round_trip_single_record() {
        let payload = vec![0x5Au8; 148];
        let mut wire = Vec::new();
        encode(&payload, &mut wire).unwrap();

        let mut p = RecordParser::new();
        p.push(&wire);
        assert_eq!(p.next_message().unwrap(), payload);
        assert!(p.next_message().is_none());
        assert_eq!(p.resyncs(), 0);
    }

    /// The whole point of the streaming parser: TCP may deliver a record one byte
    /// at a time and must not yield anything until it is complete.
    #[test]
    fn reassembles_byte_by_byte() {
        let payload = vec![0x11u8; 200];
        let mut wire = Vec::new();
        encode(&payload, &mut wire).unwrap();

        let mut p = RecordParser::new();
        for (i, b) in wire.iter().enumerate() {
            p.push(&[*b]);
            if i + 1 < wire.len() {
                assert!(p.next_message().is_none(), "yielded early at byte {i}");
            }
        }
        assert_eq!(p.next_message().unwrap(), payload);
    }

    #[test]
    fn parses_multiple_records_in_one_read() {
        let a = vec![0x01u8; 40];
        let b = vec![0x02u8; 1420];
        let mut wire = Vec::new();
        encode(&a, &mut wire).unwrap();
        encode(&b, &mut wire).unwrap();

        let mut p = RecordParser::new();
        p.push(&wire);
        assert_eq!(p.next_message().unwrap(), a);
        assert_eq!(p.next_message().unwrap(), b);
        assert!(p.next_message().is_none());
    }

    /// Fragment records carry 4 extra header bytes that must be skipped, not
    /// delivered as payload.
    #[test]
    fn strips_fragment_header() {
        let payload = vec![0x77u8; 100];
        let total = (ENCAP_HDR_LEN + FRAG_HDR_LEN + payload.len()) as u32;
        let ck = header_checksum(total, RECORD_DATA, FRAG_FLAG);

        let mut wire = Vec::new();
        wire.extend_from_slice(&total.to_be_bytes());
        wire.push(RECORD_DATA);
        wire.push(FRAG_FLAG);
        wire.extend_from_slice(&ck.to_be_bytes());
        wire.extend_from_slice(&0x1234u16.to_be_bytes());
        wire.extend_from_slice(&0x0020u16.to_be_bytes());
        wire.extend_from_slice(&payload);

        let mut p = RecordParser::new();
        p.push(&wire);
        assert_eq!(p.next_message().unwrap(), payload);
    }

    /// A record shorter than a minimum WireGuard message is a malformed header, not
    /// a short read; it must not be accepted.
    #[test]
    fn rejects_undersized_total_length() {
        let total = (ENCAP_HDR_LEN + 4) as u32;
        let ck = header_checksum(total, RECORD_DATA, 0);
        let mut wire = Vec::new();
        wire.extend_from_slice(&total.to_be_bytes());
        wire.push(RECORD_DATA);
        wire.push(0);
        wire.extend_from_slice(&ck.to_be_bytes());
        wire.extend_from_slice(&[0u8; 4]);

        assert!(parse_header(&wire).is_none());
    }

    #[test]
    fn rejects_unknown_flags_and_types() {
        let total = 100u32;

        let ck = header_checksum(total, RECORD_DATA, 0x80);
        let mut wire = Vec::new();
        wire.extend_from_slice(&total.to_be_bytes());
        wire.push(RECORD_DATA);
        wire.push(0x80);
        wire.extend_from_slice(&ck.to_be_bytes());
        assert!(parse_header(&wire).is_none());

        let ck = header_checksum(total, 9, 0);
        let mut wire = Vec::new();
        wire.extend_from_slice(&total.to_be_bytes());
        wire.push(9);
        wire.push(0);
        wire.extend_from_slice(&ck.to_be_bytes());
        assert!(parse_header(&wire).is_none());
    }

    #[test]
    fn resyncs_after_leading_garbage() {
        let payload = vec![0x42u8; 64];
        let mut wire = Vec::new();
        wire.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11]);
        encode(&payload, &mut wire).unwrap();

        let mut p = RecordParser::new();
        p.push(&wire);
        assert_eq!(p.next_message().unwrap(), payload);
        assert!(p.resyncs() > 0);
    }

    #[test]
    fn encode_rejects_out_of_range_payloads() {
        let mut out = Vec::new();
        assert!(matches!(
            encode(&[0u8; 8], &mut out),
            Err(RecordError::TooShort(8))
        ));
        assert!(matches!(
            encode(&vec![0u8; 65536], &mut out),
            Err(RecordError::TooLong(_))
        ));
    }
}
