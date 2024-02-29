use bitcoin_hashes::sha256;
use bls12_381::Scalar;
use ecash_ng_crypto::IssuanceRequest;
use ff::Field;
use rand::thread_rng;

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

#[divan::bench]
fn bulletproofs_prove(bencher: divan::Bencher) {
    let blinding = Scalar::random(&mut thread_rng());

    bencher.bench(|| ecash_ng_crypto::rp::prove(1000, blinding));
}

#[divan::bench]
fn bulletproofs_verify(bencher: divan::Bencher) {
    let blinding = Scalar::random(&mut thread_rng());

    let proof = ecash_ng_crypto::rp::prove(1000, blinding);
    let commitment = ecash_ng_crypto::pedersen_commit(1000, blinding);

    bencher.bench(|| ecash_ng_crypto::rp::verify(commitment, &proof));
}
