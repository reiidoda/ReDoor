use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use redoor_client::engine::{
    fuzz_classify_untrusted_blob, fuzz_validate_untrusted_inner_payload,
    FUZZ_CLASS_ACCEPTED_ENVELOPE, FUZZ_CLASS_ACCEPTED_HANDSHAKE, FUZZ_CLASS_DROPPED_ENVELOPE_PARSE,
    FUZZ_CLASS_DROPPED_ENVELOPE_VALIDATION,
};
use std::fs;
use std::path::{Path, PathBuf};

const MAX_MUTATED_INPUT_BYTES: usize = 300 * 1024;

fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fuzz")
        .join("corpus")
        .join("inbound_decode")
}

fn handshake_corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fuzz")
        .join("corpus")
        .join("handshake_nested_json")
}

fn collect_corpus_files() -> Vec<PathBuf> {
    let dir = corpus_dir();
    let mut files = Vec::new();
    if !dir.exists() {
        return files;
    }

    let entries = fs::read_dir(dir).expect("read corpus directory");
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() {
            files.push(path);
        }
    }
    files.sort();
    files
}

fn mutate_seed(seed: &[u8], rng: &mut StdRng) -> Vec<u8> {
    let mut out = if seed.is_empty() {
        vec![rng.gen()]
    } else {
        seed.to_vec()
    };

    match rng.gen_range(0..6) {
        0 => {
            let idx = rng.gen_range(0..out.len());
            out[idx] ^= 1u8 << rng.gen_range(0..8);
        }
        1 => {
            let idx = rng.gen_range(0..=out.len());
            out.insert(idx, rng.gen());
        }
        2 => {
            if out.len() > 1 {
                let idx = rng.gen_range(0..out.len());
                out.remove(idx);
            }
        }
        3 => {
            if !out.is_empty() {
                let start = rng.gen_range(0..out.len());
                let end = (start + rng.gen_range(1..=8)).min(out.len());
                let chunk = out[start..end].to_vec();
                out.extend_from_slice(&chunk);
            }
        }
        4 => {
            if out.len() > 4 {
                let new_len = rng.gen_range(1..out.len());
                out.truncate(new_len);
            }
        }
        _ => {
            if out.len() > 1 {
                let a = rng.gen_range(0..out.len());
                let b = rng.gen_range(0..out.len());
                out.swap(a, b);
            }
        }
    }

    if out.len() > MAX_MUTATED_INPUT_BYTES {
        out.truncate(MAX_MUTATED_INPUT_BYTES);
    }
    out
}

#[test]
fn parser_fuzz_corpus_pack_exists() {
    let files = collect_corpus_files();
    assert!(
        files.len() >= 4,
        "expected at least 4 inbound corpus seeds, found {}",
        files.len()
    );
}

#[test]
fn parser_regression_fixtures_classify_expected() {
    let mut seen = 0usize;
    for path in collect_corpus_files() {
        let name = path.file_name().unwrap().to_string_lossy();
        let data = fs::read(&path).expect("read corpus seed");
        let class = fuzz_classify_untrusted_blob(&data);

        match name.as_ref() {
            "unknown-envelope-field.json" => {
                assert_eq!(class, FUZZ_CLASS_DROPPED_ENVELOPE_PARSE);
                seen += 1;
            }
            "invalid-sender-format.json" => {
                assert_eq!(class, FUZZ_CLASS_DROPPED_ENVELOPE_VALIDATION);
                seen += 1;
            }
            "valid-envelope.json" => {
                assert_eq!(class, FUZZ_CLASS_ACCEPTED_ENVELOPE);
                seen += 1;
            }
            "malformed-nested-json.bin" => {
                assert_eq!(class, FUZZ_CLASS_DROPPED_ENVELOPE_PARSE);
                seen += 1;
            }
            _ => {}
        }
    }

    assert_eq!(seen, 4, "expected to assert all named regression fixtures");
}

#[test]
fn parser_mutation_smoke_no_panics() {
    let files = collect_corpus_files();
    assert!(!files.is_empty(), "corpus seeds are required");

    let seeds: Vec<Vec<u8>> = files
        .iter()
        .map(|path| fs::read(path).expect("read corpus seed bytes"))
        .collect();

    let mut rng = StdRng::seed_from_u64(0x5EED_F022);
    let iterations = std::env::var("REDOOR_PARSER_FUZZ_MUTATION_ITERS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(1500usize);

    for i in 0..iterations {
        let seed = &seeds[i % seeds.len()];
        let candidate = mutate_seed(seed, &mut rng);
        let sender = if i % 2 == 0 {
            "sender-1"
        } else {
            "bad sender with spaces"
        };

        let result = std::panic::catch_unwind(|| {
            let class = fuzz_classify_untrusted_blob(&candidate);
            assert!(
                class <= FUZZ_CLASS_ACCEPTED_HANDSHAKE,
                "classification out of range: {}",
                class
            );
            let _ = fuzz_validate_untrusted_inner_payload(sender, &candidate);
        });

        assert!(result.is_ok(), "mutation iteration {} panicked", i);
    }
}

#[test]
fn handshake_corpus_smoke_no_panics() {
    let dir = handshake_corpus_dir();
    let mut seen = 0usize;
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let data = fs::read(&path).expect("read handshake corpus seed");
            let result = std::panic::catch_unwind(|| {
                let class = fuzz_classify_untrusted_blob(&data);
                assert!(class <= FUZZ_CLASS_ACCEPTED_HANDSHAKE);
            });
            assert!(result.is_ok(), "handshake seed {:?} panicked", path);
            seen += 1;
        }
    }
    assert!(seen > 0, "expected at least one handshake corpus fixture");
}
