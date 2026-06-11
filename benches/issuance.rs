use std::io::Write;

use bitcoin_hashes::sha256;
use bls12_381::Scalar;
use ecash_ng_crypto::IssuanceRequest;
use ff::Field;
use rand::{thread_rng, Rng};

fn main() {
    divan::main();
}

#[divan::bench]
fn issuance_prepare(bencher: divan::Bencher) {
    bencher.bench(|| {
        IssuanceRequest::new(
            1000,
            sha256::Hash::hash(&[0; 32]),
            Scalar::random(&mut thread_rng()),
        )
        .prepare_issuance()
    });
}

#[divan::bench]
fn issuance_verify(bencher: divan::Bencher) {
    let request = IssuanceRequest::new(
        1000,
        sha256::Hash::hash(&[0; 32]),
        Scalar::random(&mut thread_rng()),
    )
    .prepare_issuance();

    bencher.bench(|| request.verify());
}

fn find_tag_single_bit(seed: [u8; 32]) -> [u8; 16] {
    loop {
        let tag = thread_rng().gen::<[u8; 16]>();

        if is_even(seed, tag) {
            return tag;
        }
    }
}

fn is_even(seed: [u8; 32], tag: [u8; 16]) -> bool {
    let mut engine = sha256::HashEngine::default();

    engine
        .write_all(&seed)
        .expect("Writing to hash engine can't fail");

    engine
        .write_all(&tag)
        .expect("Writing to hash engine can't fail");

    let hash = sha256::Hash::from_engine(engine);

    hash.as_byte_array()[0] & 0x01 == 0
}

#[divan::bench]
fn sha256_hash(bencher: divan::Bencher) {
    let seed = [0u8; 32];

    bencher.bench(|| find_tag_single_bit(seed));
}
