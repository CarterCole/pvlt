//! The streaming blob writer and reader: they must agree with the whole-buffer code byte for byte, accept any
//! way of cutting the input, and refuse everything the whole-buffer reader refuses.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use pvlt_format::blob::{self, BlobReader, BlobWriter, CHUNK_MIN};
use pvlt_format::{Error, Suite};
use serde_json::Value;

const DEK: [u8; 32] = [0x11; 32];
const DOMAIN: [u8; 16] = [0x22; 16];
const OBJECT: [u8; 16] = [0x33; 16];
const SALT: [u8; 24] = [0x44; 24];

/// A small deterministic generator, so a failure is reproducible.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n)
            .map(|_| u8::try_from(self.next() & 0xff).unwrap())
            .collect()
    }
    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(n.max(1)).unwrap()).unwrap()
    }
}

/// Cuts `data` into pieces: one piece, one byte at a time, or random sizes.
fn cuts(data: &[u8], mode: usize, rng: &mut Rng) -> Vec<Vec<u8>> {
    match mode {
        0 => vec![data.to_vec()],
        1 => data.chunks(1).map(<[u8]>::to_vec).collect(),
        _ => {
            let mut out = Vec::new();
            let mut at = 0;
            while at < data.len() {
                let n = 1 + rng.below(3000);
                let end = (at + n).min(data.len());
                out.push(data[at..end].to_vec());
                at = end;
            }
            out
        }
    }
}

fn whole(suite: Suite, chunk: u32, data: &[u8]) -> Vec<u8> {
    blob::seal(&DEK, suite, &DOMAIN, &OBJECT, 3, chunk, &SALT, data).unwrap()
}

fn stream(suite: Suite, chunk: u32, data: &[u8], mode: usize, rng: &mut Rng) -> Vec<u8> {
    let (mut w, header) = BlobWriter::new(
        &DEK,
        suite,
        &DOMAIN,
        &OBJECT,
        3,
        chunk,
        &SALT,
        u64::try_from(data.len()).unwrap(),
    )
    .unwrap();
    let mut out = header;
    for piece in cuts(data, mode, rng) {
        out.extend_from_slice(&w.write(&piece).unwrap());
    }
    out.extend_from_slice(&w.finish().unwrap());
    out
}

fn read(object: &[u8], mode: usize, rng: &mut Rng) -> Result<Vec<u8>, Error> {
    let mut r = BlobReader::new(&DEK, object)?;
    let mut out = Vec::new();
    for piece in cuts(&object[104..], mode, rng) {
        out.extend_from_slice(&r.push(&piece)?);
    }
    out.extend_from_slice(&r.finish()?);
    Ok(out)
}

const LENGTHS: [usize; 16] = [
    0, 1, 7, 8, 9, 1015, 1016, 1017, 2039, 2040, 2041, 2500, 4096, 10_000, 65_535, 70_000,
];

#[test]
fn the_writer_makes_the_same_bytes_as_the_whole_buffer_sealer_however_the_data_is_cut() {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    for suite in [Suite::XChaCha20Poly1305, Suite::Aes256Gcm] {
        for chunk in [CHUNK_MIN, 4096, 65_536] {
            for len in LENGTHS {
                let data = rng.bytes(len);
                let want = whole(suite, chunk, &data);
                for mode in [0, 1, 2, 2, 2] {
                    if mode == 1 && len > 3000 {
                        continue;
                    }
                    assert_eq!(
                        stream(suite, chunk, &data, mode, &mut rng),
                        want,
                        "{suite:?} chunk {chunk} len {len} mode {mode}"
                    );
                }
            }
        }
    }
}

#[test]
fn the_reader_returns_the_data_however_the_object_is_cut() {
    let mut rng = Rng(0x0123_4567_89ab_cdef);
    for suite in [Suite::XChaCha20Poly1305, Suite::Aes256Gcm] {
        for chunk in [CHUNK_MIN, 4096] {
            for len in LENGTHS {
                let data = rng.bytes(len);
                let object = whole(suite, chunk, &data);
                for mode in [0, 1, 2, 2, 2] {
                    if mode == 1 && object.len() > 6000 {
                        continue;
                    }
                    assert_eq!(
                        read(&object, mode, &mut rng).unwrap(),
                        data,
                        "{suite:?} chunk {chunk} len {len} mode {mode}"
                    );
                }
            }
        }
    }
}

#[test]
fn the_reader_refuses_everything_the_whole_buffer_reader_refuses() {
    let mut rng = Rng(77);
    let data = rng.bytes(5000);
    let object = whole(Suite::Aes256Gcm, 1024, &data);
    let sealed = 1024 + 16;
    let chunks = (object.len() - 104).div_ceil(sealed);
    assert!(chunks >= 5);
    let bad = |o: &[u8]| read(o, 2, &mut Rng(5)).is_err();

    // A flipped bit anywhere: in the header (including the commitment) and in every chunk and tag.
    for at in (0..object.len())
        .step_by(37)
        .chain([103, 104, object.len() - 1])
    {
        let mut x = object.clone();
        x[at] ^= 1;
        assert!(bad(&x), "a flip at {at} was accepted");
    }
    // Truncation at every length from just the header to one byte short.
    for cut in
        (104..object.len())
            .step_by(53)
            .chain([object.len() - 1, 104 + sealed, 104 + 2 * sealed])
    {
        assert!(bad(&object[..cut]), "truncation to {cut} was accepted");
    }
    // The final chunk dropped on a boundary: what is left is a stream whose last chunk is not sealed as final.
    let boundary = 104 + (chunks - 1) * sealed;
    assert!(bad(&object[..boundary]));
    // Chunks reordered, repeated, and an extra one appended.
    let c = |i: usize| object[104 + i * sealed..104 + (i + 1) * sealed].to_vec();
    let mut swapped = object[..104].to_vec();
    swapped.extend(c(1));
    swapped.extend(c(0));
    for i in 2..chunks - 1 {
        swapped.extend(c(i));
    }
    swapped.extend_from_slice(&object[104 + (chunks - 1) * sealed..]);
    assert!(bad(&swapped));
    let mut extended = object.clone();
    extended.extend(c(0));
    assert!(bad(&extended));
    // The wrong key, and an empty object.
    assert!(BlobReader::new(&[0u8; 32], &object).is_err());
    assert!(BlobReader::new(&DEK, &object[..50]).is_err());
    assert!(read(&object[..104], 0, &mut Rng(1)).is_err());
}

#[test]
fn a_reader_that_stops_early_returns_nothing_it_should_not_be_trusted_with() {
    // `finish` is what makes a stream good: data returned before it is provisional, and truncation shows there.
    let mut rng = Rng(3);
    let data = rng.bytes(5000);
    let object = whole(Suite::XChaCha20Poly1305, 1024, &data);
    let mut r = BlobReader::new(&DEK, &object).unwrap();
    let early = r.push(&object[104..104 + 3 * (1024 + 16) + 5]).unwrap();
    assert!(
        !early.is_empty(),
        "verified chunks are released as they arrive"
    );
    assert!(early.len() <= data.len());
    assert_eq!(early.as_slice(), &data[..early.len()]);
    assert!(r.finish().is_err(), "but a truncated stream never finishes");
}

#[test]
fn the_writer_enforces_the_declared_length() {
    let (mut w, _) =
        BlobWriter::new(&DEK, Suite::Aes256Gcm, &DOMAIN, &OBJECT, 0, 1024, &SALT, 10).unwrap();
    assert!(w.write(&[0u8; 11]).is_err(), "more than declared");
    let (mut w, _) =
        BlobWriter::new(&DEK, Suite::Aes256Gcm, &DOMAIN, &OBJECT, 0, 1024, &SALT, 10).unwrap();
    w.write(&[0u8; 9]).unwrap();
    assert!(w.finish().is_err(), "less than declared");
    assert!(
        BlobWriter::new(&DEK, Suite::Aes256Gcm, &DOMAIN, &OBJECT, 0, 1000, &SALT, 1).is_err(),
        "a bad chunk size"
    );
    assert!(
        BlobWriter::new(
            &DEK,
            Suite::Aes256Gcm,
            &DOMAIN,
            &OBJECT,
            0,
            1024,
            &SALT,
            u64::MAX
        )
        .is_err()
    );
}

#[test]
fn the_known_answer_vectors_go_through_the_streams_too() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../spec/vectors/blob.json");
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let mut checked = 0;
    for v in doc["vectors"].as_array().unwrap() {
        let suite = match v["suite"].as_u64().unwrap() {
            1 => Suite::XChaCha20Poly1305,
            3 => Suite::Aes256Gcm,
            _ => continue, // 0x0002 needs the gcm-siv feature; the whole-buffer test covers it
        };
        let h = |k: &str| hex::decode(v[k].as_str().unwrap()).unwrap();
        let dek: [u8; 32] = h("dek").try_into().unwrap();
        let (domain, object, salt): ([u8; 16], [u8; 16], [u8; 24]) = (
            h("domain_id").try_into().unwrap(),
            h("object_id").try_into().unwrap(),
            h("salt").try_into().unwrap(),
        );
        let data = h("data");
        let chunk = u32::try_from(v["chunk_size"].as_u64().unwrap()).unwrap();
        let generation = u32::try_from(v["dek_generation"].as_u64().unwrap()).unwrap();
        let want = hex::decode(v["expected"]["object"].as_str().unwrap()).unwrap();

        let (mut w, header) = BlobWriter::new(
            &dek,
            suite,
            &domain,
            &object,
            generation,
            chunk,
            &salt,
            data.len() as u64,
        )
        .unwrap();
        let mut out = header;
        for b in data.chunks(7) {
            out.extend_from_slice(&w.write(b).unwrap());
        }
        out.extend_from_slice(&w.finish().unwrap());
        assert_eq!(out, want, "{}", v["name"]);

        let mut r = BlobReader::new(&dek, &want).unwrap();
        let mut got = Vec::new();
        for b in want[104..].chunks(13) {
            got.extend_from_slice(&r.push(b).unwrap());
        }
        got.extend_from_slice(&r.finish().unwrap());
        assert_eq!(got, data, "{}", v["name"]);
        checked += 1;
    }
    assert_eq!(checked, 8, "two suites, four vectors each");
}

#[test]
fn sealed_len_and_plausible_len_agree_with_what_is_actually_made() {
    let mut rng = Rng(11);
    let mut valid = std::collections::HashSet::new();
    for chunk in [1024u32, 4096] {
        for len in 0..12_000usize {
            let want = blob::sealed_len(len as u64, chunk).unwrap();
            if len % 97 == 0 || len < 20 {
                let data = rng.bytes(len);
                assert_eq!(
                    whole(Suite::Aes256Gcm, chunk, &data).len() as u64,
                    want,
                    "chunk {chunk} len {len}"
                );
            }
            assert!(blob::plausible_len(want, chunk), "chunk {chunk} len {len}");
            valid.insert((chunk, want));
        }
        // Every length that is not the sealed length of some data length is implausible.
        for l in 0..9_000u64 {
            assert_eq!(
                blob::plausible_len(l, chunk),
                valid.contains(&(chunk, l)),
                "chunk {chunk} length {l}"
            );
        }
    }
    assert!(blob::sealed_len(0, 1000).is_none());
    assert!(!blob::plausible_len(103, 1024));
    assert!(!blob::plausible_len(104, 1024));
}
