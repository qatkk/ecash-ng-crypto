use bitcoin_hashes::sha256;
use bls12_381::{G1Projective, Scalar};
use ff::Field;
use group::Curve;
use rand::thread_rng;
use rayon::prelude::*;
use std::io::Write;

use crate::generators::{gv, hv, pedersen_g, pedersen_h};

// ============================================================================
// Bulletproofs Helper Functions
// ============================================================================

// ----------------------------------------------------------------------------
// 1. Vector Operations (Foundation)
// ----------------------------------------------------------------------------

/// Compute inner product: <a, b> = sum(aᵢ * bᵢ)
fn inner_product(a: &[Scalar], b: &[Scalar]) -> Scalar {
    assert_eq!(a.len(), b.len(), "Vectors must have same length");
    a.iter().zip(b.iter()).map(|(ai, bi)| ai * bi).sum()
}

/// Hadamard (element-wise) product: [a₀*b₀, a₁*b₁, ...]
fn hadamard_product(a: &[Scalar], b: &[Scalar]) -> Vec<Scalar> {
    assert_eq!(a.len(), b.len(), "Vectors must have same length");
    a.iter().zip(b.iter()).map(|(ai, bi)| ai * bi).collect()
}

/// Vector addition: [a₀+b₀, a₁+b₁, ...]
fn vector_add_bp(a: &[Scalar], b: &[Scalar]) -> Vec<Scalar> {
    assert_eq!(a.len(), b.len(), "Vectors must have same length");
    a.iter().zip(b.iter()).map(|(ai, bi)| ai + bi).collect()
}

/// Vector subtraction: [a₀-b₀, a₁-b₁, ...]
fn vector_sub_bp(a: &[Scalar], b: &[Scalar]) -> Vec<Scalar> {
    assert_eq!(a.len(), b.len(), "Vectors must have same length");
    a.iter().zip(b.iter()).map(|(ai, bi)| ai - bi).collect()
}

/// Scalar-vector multiplication: [s*v₀, s*v₁, ...]
fn scalar_vector_mul_bp(scalar: Scalar, vec: &[Scalar]) -> Vec<Scalar> {
    vec.iter().map(|v| scalar * v).collect()
}

/// Generate powers of x: [1, x, x², x³, ..., x^(n-1)]
fn powers_of_bp(x: Scalar, n: usize) -> [Scalar; 64] {
    assert_eq!(n, 64, "Only n=64 is supported");
    let mut powers = [Scalar::zero(); 64];
    let mut current = Scalar::one();
    for i in 0..64 {
        powers[i] = current;
        current *= x;
    }
    powers
}

// ----------------------------------------------------------------------------
// 2. Group Operations (Commitments)
// ----------------------------------------------------------------------------

/// Multi-exponentiation: sum(sᵢ * Pᵢ) - PARALLELIZED
/// This is a key operation for efficiency
fn vector_commit_bp(scalars: &[Scalar], points: &[G1Projective]) -> G1Projective {
    assert_eq!(scalars.len(), points.len(), "Vectors must have same length");
    scalars
        .par_iter()
        .zip(points.par_iter())
        .map(|(s, p)| s * p)
        .sum()
}

// ----------------------------------------------------------------------------
// 4. Fiat-Shamir (Challenge Generation)
// ----------------------------------------------------------------------------

/// Compute challenge y from commitments A and S
fn compute_challenge_y(a: &G1Projective, s: &G1Projective) -> Scalar {
    let mut engine = sha256::HashEngine::default();

    engine
        .write_all(b"FEDIMINT_BP_CHALLENGE_Y")
        .expect("Writing to hash engine can't fail");

    engine
        .write_all(&a.to_affine().to_compressed())
        .expect("Writing to hash engine can't fail");

    engine
        .write_all(&s.to_affine().to_compressed())
        .expect("Writing to hash engine can't fail");

    crate::hash::map_to_scalar(&sha256::Hash::from_engine(engine))
}

/// Compute challenge z from y
fn compute_challenge_z(y: Scalar) -> Scalar {
    let mut engine = sha256::HashEngine::default();

    engine
        .write_all(b"FEDIMINT_BP_CHALLENGE_Z")
        .expect("Writing to hash engine can't fail");

    engine
        .write_all(&y.to_bytes())
        .expect("Writing to hash engine can't fail");

    crate::hash::map_to_scalar(&sha256::Hash::from_engine(engine))
}

/// Compute challenge x from T1 and T2
fn compute_challenge_x(t1: &G1Projective, t2: &G1Projective, z: Scalar) -> Scalar {
    let mut engine = sha256::HashEngine::default();

    engine
        .write_all(b"FEDIMINT_BP_CHALLENGE_X")
        .expect("Writing to hash engine can't fail");

    engine
        .write_all(&z.to_bytes())
        .expect("Writing to hash engine can't fail");

    engine
        .write_all(&t1.to_affine().to_compressed())
        .expect("Writing to hash engine can't fail");

    engine
        .write_all(&t2.to_affine().to_compressed())
        .expect("Writing to hash engine can't fail");

    crate::hash::map_to_scalar(&sha256::Hash::from_engine(engine))
}

/// Compute challenge for inner product proof round
fn compute_challenge_ipp(l: &G1Projective, r: &G1Projective) -> Scalar {
    let mut engine = sha256::HashEngine::default();

    engine
        .write_all(b"FEDIMINT_BP_CHALLENGE_IPP")
        .expect("Writing to hash engine can't fail");

    engine
        .write_all(&l.to_affine().to_compressed())
        .expect("Writing to hash engine can't fail");

    engine
        .write_all(&r.to_affine().to_compressed())
        .expect("Writing to hash engine can't fail");

    crate::hash::map_to_scalar(&sha256::Hash::from_engine(engine))
}

// ----------------------------------------------------------------------------
// 5. Inner Product Argument
// ----------------------------------------------------------------------------

/// Inner product proof structure for n=64 (log2(64) = 6 rounds)
#[derive(Clone, Debug)]
struct InnerProductProof {
    l_vec: [G1Projective; 6], // Left commitments (6 rounds)
    r_vec: [G1Projective; 6], // Right commitments (6 rounds)
    a: Scalar,                // Final a value
    b: Scalar,                // Final b value
}

/// Prove knowledge of vectors a, b such that <a, b> = t
/// and P = <a, G> + <b, H>
fn prove_inner_product_bp(
    g_vec: &[G1Projective],
    h_vec: &[G1Projective],
    a: &[Scalar],
    b: &[Scalar],
) -> InnerProductProof {
    let mut n = a.len();
    assert_eq!(n, b.len());
    assert_eq!(n, g_vec.len());
    assert_eq!(n, h_vec.len());
    assert!(n.is_power_of_two(), "Length must be power of 2");

    let mut a = a.to_vec();
    let mut b = b.to_vec();
    let mut g = g_vec.to_vec();
    let mut h = h_vec.to_vec();

    let mut l_vec = Vec::with_capacity(6);
    let mut r_vec = Vec::with_capacity(6);

    // Recursive folding (6 rounds for n=64)
    while n > 1 {
        let n_half = n / 2;

        // Split vectors in half
        let (a_lo, a_hi) = a.split_at(n_half);
        let (b_lo, b_hi) = b.split_at(n_half);
        let (g_lo, g_hi) = g.split_at(n_half);
        let (h_lo, h_hi) = h.split_at(n_half);

        // Compute cross terms
        // L = <a_lo, G_hi> + <b_hi, H_lo>
        let l = vector_commit_bp(a_lo, g_hi) + vector_commit_bp(b_hi, h_lo);

        // R = <a_hi, G_lo> + <b_lo, H_hi>
        let r = vector_commit_bp(a_hi, g_lo) + vector_commit_bp(b_lo, h_hi);

        l_vec.push(l);
        r_vec.push(r);

        // Generate challenge
        let u = compute_challenge_ipp(&l, &r);
        let u_inv = u.invert().unwrap();

        // Fold scalars: a' = a_lo * u + a_hi * u^(-1)
        a = a_lo
            .iter()
            .zip(a_hi.iter())
            .map(|(lo, hi)| lo * u + hi * u_inv)
            .collect();

        // Fold scalars: b' = b_lo * u^(-1) + b_hi * u
        b = b_lo
            .iter()
            .zip(b_hi.iter())
            .map(|(lo, hi)| lo * u_inv + hi * u)
            .collect();

        // Fold generators: G' = G_lo * u^(-1) + G_hi * u - PARALLELIZED
        g = g_lo
            .par_iter()
            .zip(g_hi.par_iter())
            .map(|(lo, hi)| u_inv * lo + u * hi)
            .collect();

        // Fold generators: H' = H_lo * u + H_hi * u^(-1) - PARALLELIZED
        h = h_lo
            .par_iter()
            .zip(h_hi.par_iter())
            .map(|(lo, hi)| u * lo + u_inv * hi)
            .collect();

        n = n_half;
    }

    // Convert to fixed-size arrays (exactly 6 elements for n=64)
    assert_eq!(l_vec.len(), 6);
    assert_eq!(r_vec.len(), 6);

    InnerProductProof {
        l_vec: l_vec.try_into().unwrap(),
        r_vec: r_vec.try_into().unwrap(),
        a: a[0],
        b: b[0],
    }
}

/// Verify an inner product proof
fn verify_inner_product_bp(
    g_vec: &[G1Projective],
    h_vec: &[G1Projective],
    commitment: &G1Projective,
    proof: &InnerProductProof,
) -> bool {
    let n = g_vec.len();
    assert_eq!(n, h_vec.len());
    assert!(n.is_power_of_two(), "Length must be power of 2");

    // For n=64, we expect exactly 6 rounds
    assert_eq!(n, 64, "Only n=64 is supported with fixed arrays");

    // Recompute challenges
    let mut challenges = Vec::with_capacity(6);
    for (l, r) in proof.l_vec.iter().zip(proof.r_vec.iter()) {
        let u = compute_challenge_ipp(l, r);
        challenges.push(u);
    }

    // Fold the commitment P using L and R
    let mut p = *commitment;
    for (u, (l, r)) in challenges
        .iter()
        .zip(proof.l_vec.iter().zip(proof.r_vec.iter()))
    {
        let u_sq = u * u;
        let u_inv_sq = u_sq.invert().unwrap();
        p = u_sq * l + p + u_inv_sq * r;
    }

    // Fold generators (G and H fold differently!)
    let g_final = fold_generators_g_bp(g_vec, &challenges);
    let h_final = fold_generators_h_bp(h_vec, &challenges);

    // Final check: P' = a*G' + b*H'
    let expected = proof.a * g_final + proof.b * h_final;

    p == expected
}

/// Fold G generators: G' = G_lo * u^(-1) + G_hi * u - PARALLELIZED
fn fold_generators_g_bp(generators: &[G1Projective], challenges: &[Scalar]) -> G1Projective {
    let mut g = generators.to_vec();
    let mut n = g.len();

    for u in challenges {
        let n_half = n / 2;
        let u_inv = u.invert().unwrap();

        // G' = G_lo * u^(-1) + G_hi * u - PARALLEL
        g = (0..n_half)
            .into_par_iter()
            .map(|i| u_inv * g[i] + u * g[n_half + i])
            .collect();

        n = n_half;
    }

    assert_eq!(g.len(), 1);
    g[0]
}

/// Fold H generators: H' = H_lo * u + H_hi * u^(-1) - PARALLELIZED
fn fold_generators_h_bp(generators: &[G1Projective], challenges: &[Scalar]) -> G1Projective {
    let mut h = generators.to_vec();
    let mut n = h.len();

    for u in challenges {
        let n_half = n / 2;
        let u_inv = u.invert().unwrap();

        // H' = H_lo * u + H_hi * u^(-1) - PARALLEL
        h = (0..n_half)
            .into_par_iter()
            .map(|i| u * h[i] + u_inv * h[n_half + i])
            .collect();

        n = n_half;
    }

    assert_eq!(h.len(), 1);
    h[0]
}

// ----------------------------------------------------------------------------
// 6. Range Proof Protocol (Bulletproofs)
// ----------------------------------------------------------------------------

/// Decompose a value into its 64-bit representation (LSB first)
fn bit_decompose_bp(value: u64) -> [Scalar; 64] {
    std::array::from_fn(|i| {
        if (value >> i) & 1 == 1 {
            Scalar::one()
        } else {
            Scalar::zero()
        }
    })
}

/// Compute delta(y,z) = (z - z^2)*<1^n, y^n> - z^3*<1^n, 2^n> for n=64
fn compute_delta_bp(y: Scalar, z: Scalar) -> Scalar {
    let z_sq = z * z;
    let z_cubed = z_sq * z;

    let y_powers = powers_of_bp(y, 64);
    let two_powers: [Scalar; 64] = std::array::from_fn(|i| Scalar::from(1u64 << i));

    let sum_y: Scalar = y_powers.iter().sum();
    let sum_two: Scalar = two_powers.iter().sum();

    (z - z_sq) * sum_y - z_cubed * sum_two
}

/// Create weighted H generators: H_i' = y^(-i) * H_i  (inverse powers!)
fn create_weighted_h_bp(h_vec: &[G1Projective; 64], y_powers: &[Scalar; 64]) -> [G1Projective; 64] {
    // Parallelize: 64 scalar inversions + 64 scalar-point multiplications
    let weighted: Vec<_> = (0..64)
        .into_par_iter()
        .map(|i| y_powers[i].invert().unwrap() * h_vec[i])
        .collect();

    weighted.try_into().unwrap()
}

/// Compute polynomial t1 coefficient
fn compute_t1_bp(
    a_l: &[Scalar],
    a_r: &[Scalar],
    s_l: &[Scalar],
    s_r: &[Scalar],
    y_powers: &[Scalar],
    z: Scalar,
) -> Scalar {
    let n = a_l.len();
    let ones = vec![Scalar::one(); n];
    let two_powers: Vec<Scalar> = (0..n).map(|i| Scalar::from(1u64 << i)).collect();

    let z_sq = z * z;
    let z_ones = scalar_vector_mul_bp(z, &ones);

    let l0 = vector_sub_bp(a_l, &z_ones);
    let r0_temp = vector_add_bp(a_r, &z_ones);
    let y_sr = hadamard_product(y_powers, s_r);
    let y_r0 = hadamard_product(y_powers, &r0_temp);
    let z_sq_two = scalar_vector_mul_bp(z_sq, &two_powers);
    let r0 = vector_add_bp(&y_r0, &z_sq_two);

    inner_product(&l0, &y_sr) + inner_product(s_l, &r0)
}

/// Compute polynomial t2 coefficient
fn compute_t2_bp(s_l: &[Scalar], s_r: &[Scalar], y_powers: &[Scalar]) -> Scalar {
    let y_sr = hadamard_product(y_powers, s_r);
    inner_product(s_l, &y_sr)
}

/// Compute l and r vectors at challenge point x
fn compute_lr_vectors_bp(
    a_l: &[Scalar],
    a_r: &[Scalar],
    s_l: &[Scalar],
    s_r: &[Scalar],
    y_powers: &[Scalar],
    z: Scalar,
    x: Scalar,
) -> (Vec<Scalar>, Vec<Scalar>) {
    let n = a_l.len();
    let ones = vec![Scalar::one(); n];
    let two_powers: Vec<Scalar> = (0..n).map(|i| Scalar::from(1u64 << i)).collect();

    let z_sq = z * z;
    let z_ones = scalar_vector_mul_bp(z, &ones);

    // l = (aL - z*1^n) + sL*x
    let l0 = vector_sub_bp(a_l, &z_ones);
    let l = vector_add_bp(&l0, &scalar_vector_mul_bp(x, s_l));

    // r = y^n ∘ ((aR + z*1^n) + sR*x) + z^2*2^n
    let r0_temp = vector_add_bp(a_r, &z_ones);
    let r_temp = vector_add_bp(&r0_temp, &scalar_vector_mul_bp(x, s_r));
    let z_sq_two = scalar_vector_mul_bp(z_sq, &two_powers);
    let r = vector_add_bp(&hadamard_product(y_powers, &r_temp), &z_sq_two);

    (l, r)
}

/// Bulletproofs range proof structure
#[derive(Clone, Debug)]
pub struct BulletproofRangeProof {
    a: G1Projective,        // Commitment to aL, aR
    s: G1Projective,        // Commitment to sL, sR
    t1: G1Projective,       // Commitment to t1
    t2: G1Projective,       // Commitment to t2
    tau_x: Scalar,          // Blinding for t
    mu: Scalar,             // Blinding for vectors
    t_hat: Scalar,          // Inner product value <l, r>
    ipp: InnerProductProof, // Inner product proof
}

/// Prove that a committed value lies in [0, 2^64)
pub fn prove(value: u64, blinding: Scalar) -> BulletproofRangeProof {
    // 1. Bit decomposition and compute aR = aL - 1^n
    let a_l = bit_decompose_bp(value);
    let ones = [Scalar::one(); 64];
    let a_r = vector_sub_bp(&a_l, &ones);

    // 2. Generate random vectors sL, sR and blindings
    let s_l: [Scalar; 64] = std::array::from_fn(|_| Scalar::random(&mut thread_rng()));
    let s_r: [Scalar; 64] = std::array::from_fn(|_| Scalar::random(&mut thread_rng()));
    let alpha = Scalar::random(&mut thread_rng());
    let rho = Scalar::random(&mut thread_rng());

    // 3. Commit to aL, aR and sL, sR
    let a_commit =
        vector_commit_bp(&a_l, &gv()) + vector_commit_bp(&a_r, &hv()) + alpha * pedersen_h();
    let s_commit =
        vector_commit_bp(&s_l, &gv()) + vector_commit_bp(&s_r, &hv()) + rho * pedersen_h();

    // 4. Generate challenges
    let y = compute_challenge_y(&a_commit, &s_commit);
    let z = compute_challenge_z(y);
    let y_powers = powers_of_bp(y, 64);

    // 5. Compute polynomial coefficients t1, t2
    let t1 = compute_t1_bp(&a_l, &a_r, &s_l, &s_r, &y_powers, z);
    let t2 = compute_t2_bp(&s_l, &s_r, &y_powers);

    // 6. Commit to t1 and t2
    let tau1 = Scalar::random(&mut thread_rng());
    let tau2 = Scalar::random(&mut thread_rng());
    let t1_commit = t1 * pedersen_g() + tau1 * pedersen_h();
    let t2_commit = t2 * pedersen_g() + tau2 * pedersen_h();

    // 7. Generate challenge x
    let x = compute_challenge_x(&t1_commit, &t2_commit, z);

    // 8. Compute l and r at point x
    let (l, r) = compute_lr_vectors_bp(&a_l, &a_r, &s_l, &s_r, &y_powers, z, x);
    let t_hat = inner_product(&l, &r);

    // 9. Compute tau_x and mu
    let z_sq = z * z;
    let tau_x = tau1 * x + tau2 * x * x + z_sq * blinding;
    let mu = alpha + rho * x;

    // 10. Create weighted H generators and generate inner product proof
    let h_vec_weighted = create_weighted_h_bp(&hv(), &y_powers);
    let ipp = prove_inner_product_bp(&gv(), &h_vec_weighted, &l, &r);

    BulletproofRangeProof {
        a: a_commit,
        s: s_commit,
        t1: t1_commit,
        t2: t2_commit,
        tau_x,
        mu,
        t_hat,
        ipp,
    }
}

/// Verify a Bulletproofs range proof
pub fn verify(commitment: G1Projective, proof: &BulletproofRangeProof) -> bool {
    // 1. Regenerate challenges
    let y = compute_challenge_y(&proof.a, &proof.s);
    let z = compute_challenge_z(y);
    let x = compute_challenge_x(&proof.t1, &proof.t2, z);

    // 2. Compute delta and verify t_hat commitment
    let z_sq = z * z;
    let delta = compute_delta_bp(y, z);
    let lhs = proof.t_hat * pedersen_g() + proof.tau_x * pedersen_h();
    let rhs = z_sq * commitment + delta * pedersen_g() + x * proof.t1 + x * x * proof.t2;

    if lhs != rhs {
        eprintln!("t_hat commitment check failed");
        return false;
    }

    // 3. Create weighted H generators
    let y_powers = powers_of_bp(y, 64);
    let h_vec_weighted = create_weighted_h_bp(&hv(), &y_powers);

    // 4. Reconstruct commitment P for inner product
    // P = A + x*S - mu*h - <z*1^n, G> + <z*y^n*1^n + z^2*2^n, H'>
    let ones = [Scalar::one(); 64];
    let two_powers: [Scalar; 64] = std::array::from_fn(|i| Scalar::from(1u64 << i));
    let z_ones = scalar_vector_mul_bp(z, &ones);
    let z_y_ones = scalar_vector_mul_bp(z, &y_powers);
    let z_sq_two = scalar_vector_mul_bp(z_sq, &two_powers);
    let h_adjustment = vector_add_bp(&z_y_ones, &z_sq_two);

    // Parallelize the two independent MSMs
    let (msm_g, msm_h) = rayon::join(
        || vector_commit_bp(&z_ones, &gv()),
        || vector_commit_bp(&h_adjustment, &h_vec_weighted),
    );

    let p = proof.a + x * proof.s - msm_g + msm_h - proof.mu * pedersen_h();

    // 5. Verify inner product proof
    verify_inner_product_bp(&gv(), &h_vec_weighted, &p, &proof.ipp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inner_product() {
        let a = vec![Scalar::from(1u64), Scalar::from(2u64), Scalar::from(3u64)];
        let b = vec![Scalar::from(4u64), Scalar::from(5u64), Scalar::from(6u64)];

        let result = inner_product(&a, &b);
        // 1*4 + 2*5 + 3*6 = 4 + 10 + 18 = 32
        assert_eq!(result, Scalar::from(32u64));
    }

    #[test]
    fn test_hadamard_product() {
        let a = vec![Scalar::from(2u64), Scalar::from(3u64)];
        let b = vec![Scalar::from(5u64), Scalar::from(6u64)];

        let result = hadamard_product(&a, &b);
        assert_eq!(result[0], Scalar::from(10u64));
        assert_eq!(result[1], Scalar::from(18u64));
    }

    #[test]
    fn test_vector_add() {
        let a = vec![Scalar::from(1u64), Scalar::from(2u64)];
        let b = vec![Scalar::from(3u64), Scalar::from(4u64)];

        let result = vector_add_bp(&a, &b);
        assert_eq!(result[0], Scalar::from(4u64));
        assert_eq!(result[1], Scalar::from(6u64));
    }

    #[test]
    fn test_vector_sub() {
        let a = vec![Scalar::from(5u64), Scalar::from(7u64)];
        let b = vec![Scalar::from(2u64), Scalar::from(3u64)];

        let result = vector_sub_bp(&a, &b);
        assert_eq!(result[0], Scalar::from(3u64));
        assert_eq!(result[1], Scalar::from(4u64));
    }

    #[test]
    fn test_scalar_vector_mul() {
        let s = Scalar::from(3u64);
        let v = vec![Scalar::from(2u64), Scalar::from(4u64)];

        let result = scalar_vector_mul_bp(s, &v);
        assert_eq!(result[0], Scalar::from(6u64));
        assert_eq!(result[1], Scalar::from(12u64));
    }

    #[test]
    fn test_powers_of() {
        let x = Scalar::from(3u64);
        let powers = powers_of_bp(x, 64);

        assert_eq!(powers[0], Scalar::from(1u64)); // 3^0 = 1
        assert_eq!(powers[1], Scalar::from(3u64)); // 3^1 = 3
        assert_eq!(powers[2], Scalar::from(9u64)); // 3^2 = 9
        assert_eq!(powers[3], Scalar::from(27u64)); // 3^3 = 27
        assert_eq!(powers.len(), 64);
    }

    #[test]
    fn test_vector_commit() {
        let scalars = vec![Scalar::from(2u64), Scalar::from(3u64)];
        let g = pedersen_g();
        let h = pedersen_h();
        let points = vec![g, h];

        let result = vector_commit_bp(&scalars, &points);
        let expected = Scalar::from(2u64) * g + Scalar::from(3u64) * h;

        assert_eq!(result, expected);
    }

    #[test]
    fn test_gen_vectors() {
        assert_eq!(gv().len(), 64);
        assert_eq!(hv().len(), 64);

        // All generators should be different
        for i in 0..64 {
            for j in (i + 1)..64 {
                assert_ne!(gv()[i], gv()[j]);
                assert_ne!(hv()[i], hv()[j]);
                assert_ne!(gv()[i], hv()[j]);
            }
        }
    }

    #[test]
    fn test_challenge_y() {
        let a = Scalar::from(5u64) * pedersen_g();
        let s = Scalar::from(7u64) * pedersen_h();

        let y1 = compute_challenge_y(&a, &s);
        let y2 = compute_challenge_y(&a, &s);

        // Same inputs should give same output (deterministic)
        assert_eq!(y1, y2);

        // Different inputs should give different output
        let s_different = Scalar::from(8u64) * pedersen_h();
        let y3 = compute_challenge_y(&a, &s_different);
        assert_ne!(y1, y3);
    }

    #[test]
    fn test_challenge_z() {
        let y = Scalar::from(12345u64);

        let z1 = compute_challenge_z(y);
        let z2 = compute_challenge_z(y);

        // Deterministic
        assert_eq!(z1, z2);

        // Different input
        let y_different = Scalar::from(54321u64);
        let z3 = compute_challenge_z(y_different);
        assert_ne!(z1, z3);
    }

    #[test]
    fn test_challenge_x() {
        let t1 = Scalar::from(3u64) * pedersen_g();
        let t2 = Scalar::from(5u64) * pedersen_g();
        let z = Scalar::from(99u64);

        let x1 = compute_challenge_x(&t1, &t2, z);
        let x2 = compute_challenge_x(&t1, &t2, z);

        // Deterministic
        assert_eq!(x1, x2);

        // Different input
        let t2_different = Scalar::from(6u64) * pedersen_g();
        let x3 = compute_challenge_x(&t1, &t2_different, z);
        assert_ne!(x1, x3);
    }

    #[test]
    fn test_challenge_ipp() {
        let l = Scalar::from(11u64) * pedersen_g();
        let r = Scalar::from(13u64) * pedersen_g();

        let u1 = compute_challenge_ipp(&l, &r);
        let u2 = compute_challenge_ipp(&l, &r);

        // Deterministic
        assert_eq!(u1, u2);

        // Different input
        let r_different = Scalar::from(14u64) * pedersen_g();
        let u3 = compute_challenge_ipp(&l, &r_different);
        assert_ne!(u1, u3);
    }

    #[test]
    fn test_inner_product_proof_simple() {
        // Test with vectors of length 64 (6 rounds)
        // Simple vectors: a = [1..64], b = [1..64]
        let a: Vec<Scalar> = (1..=64).map(Scalar::from).collect();
        let b: Vec<Scalar> = (1..=64).map(Scalar::from).collect();

        // Compute commitment P = <a, G> + <b, H>
        let commitment = vector_commit_bp(&a, &gv()) + vector_commit_bp(&b, &hv());

        // Generate proof
        let proof = prove_inner_product_bp(&gv(), &hv(), &a, &b);

        // Verify proof
        assert!(verify_inner_product_bp(&gv(), &hv(), &commitment, &proof));

        // Check proof structure
        assert_eq!(proof.l_vec.len(), 6); // log2(64) = 6 rounds
        assert_eq!(proof.r_vec.len(), 6);
    }

    #[test]
    fn test_inner_product_proof_64() {
        // Test with vectors of length 64 (6 rounds) - actual Bulletproofs size
        // Random-ish vectors
        let a: Vec<Scalar> = (1..=64).map(Scalar::from).collect();
        let b: Vec<Scalar> = (65..=128).map(Scalar::from).collect();

        // Compute commitment P = <a, G> + <b, H>
        let commitment = vector_commit_bp(&a, &gv()) + vector_commit_bp(&b, &hv());

        // Generate proof
        let proof = prove_inner_product_bp(&gv(), &hv(), &a, &b);

        // Verify proof
        assert!(verify_inner_product_bp(&gv(), &hv(), &commitment, &proof));

        // Check proof structure
        assert_eq!(proof.l_vec.len(), 6); // log2(64) = 6 rounds
        assert_eq!(proof.r_vec.len(), 6);
    }

    #[test]
    fn test_inner_product_proof_invalid() {
        // Test that invalid proofs fail
        let a = vec![Scalar::from(1u64); 64];
        let b = vec![Scalar::from(2u64); 64];

        let commitment = vector_commit_bp(&a, &gv()) + vector_commit_bp(&b, &hv());
        let proof = prove_inner_product_bp(&gv(), &hv(), &a, &b);

        // Correct proof should verify
        assert!(verify_inner_product_bp(&gv(), &hv(), &commitment, &proof));

        // Wrong commitment should fail
        let wrong_commitment = commitment + pedersen_g();

        assert!(!verify_inner_product_bp(
            &gv(),
            &hv(),
            &wrong_commitment,
            &proof
        ));
    }

    #[test]
    fn test_fold_generators() {
        // Create 6 challenges for 64->32->16->8->4->2->1 folding
        let challenges = vec![
            Scalar::from(2u64),
            Scalar::from(3u64),
            Scalar::from(5u64),
            Scalar::from(7u64),
            Scalar::from(11u64),
            Scalar::from(13u64),
        ];

        let result_g = fold_generators_g_bp(&gv(), &challenges);
        let result_h = fold_generators_h_bp(&hv(), &challenges);

        // Should be single generators (can't test exact values, but shouldn't panic)
        let _ = (result_g, result_h);
    }

    #[test]
    fn test_inner_product_proof_size_2() {
        // Test with n=64 (standard size)
        let a = vec![Scalar::from(7u64); 64];
        let b = vec![Scalar::from(11u64); 64];

        let commitment = vector_commit_bp(&a, &gv()) + vector_commit_bp(&b, &hv());
        let proof = prove_inner_product_bp(&gv(), &hv(), &a, &b);

        assert!(verify_inner_product_bp(&gv(), &hv(), &commitment, &proof));
        assert_eq!(proof.l_vec.len(), 6); // log2(64) = 6 rounds
        assert_eq!(proof.r_vec.len(), 6);
    }

    #[test]
    fn test_inner_product_proof_zeros() {
        // Edge case: zero vectors
        let a = vec![Scalar::zero(); 64];
        let b = vec![Scalar::from(1u64); 64];

        let commitment = vector_commit_bp(&a, &gv()) + vector_commit_bp(&b, &hv());
        let proof = prove_inner_product_bp(&gv(), &hv(), &a, &b);

        assert!(verify_inner_product_bp(&gv(), &hv(), &commitment, &proof));
    }

    #[test]
    fn test_inner_product_proof_random() {
        use rand::thread_rng;

        // Random vectors (more realistic)
        let a: Vec<Scalar> = (0..64).map(|_| Scalar::random(&mut thread_rng())).collect();
        let b: Vec<Scalar> = (0..64).map(|_| Scalar::random(&mut thread_rng())).collect();

        let commitment = vector_commit_bp(&a, &gv()) + vector_commit_bp(&b, &hv());
        let proof = prove_inner_product_bp(&gv(), &hv(), &a, &b);

        assert!(verify_inner_product_bp(&gv(), &hv(), &commitment, &proof));
    }

    #[test]
    fn test_inner_product_proof_tampered_l() {
        // Modify L_vec, should fail
        let a = vec![Scalar::from(1u64); 64];
        let b = vec![Scalar::from(2u64); 64];

        let commitment = vector_commit_bp(&a, &gv()) + vector_commit_bp(&b, &hv());
        let mut proof = prove_inner_product_bp(&gv(), &hv(), &a, &b);

        // Tamper with L_vec
        proof.l_vec[0] += pedersen_g();

        assert!(!verify_inner_product_bp(&gv(), &hv(), &commitment, &proof));
    }

    #[test]
    fn test_inner_product_proof_tampered_r() {
        // Modify R_vec, should fail
        let a = vec![Scalar::from(3u64); 64];
        let b = vec![Scalar::from(5u64); 64];

        let commitment = vector_commit_bp(&a, &gv()) + vector_commit_bp(&b, &hv());
        let mut proof = prove_inner_product_bp(&gv(), &hv(), &a, &b);

        // Tamper with R_vec
        proof.r_vec[1] += pedersen_h();

        assert!(!verify_inner_product_bp(&gv(), &hv(), &commitment, &proof));
    }

    #[test]
    fn test_inner_product_proof_tampered_final_scalars() {
        // Modify a or b, should fail
        let a = vec![Scalar::from(2u64); 64];
        let b = vec![Scalar::from(3u64); 64];

        let commitment = vector_commit_bp(&a, &gv()) + vector_commit_bp(&b, &hv());
        let mut proof = prove_inner_product_bp(&gv(), &hv(), &a, &b);

        // Tamper with final scalar a
        proof.a += Scalar::one();

        assert!(!verify_inner_product_bp(&gv(), &hv(), &commitment, &proof));

        // Reset and tamper with final scalar b
        proof = prove_inner_product_bp(&gv(), &hv(), &a, &b);
        proof.b += Scalar::one();

        assert!(!verify_inner_product_bp(&gv(), &hv(), &commitment, &proof));
    }

    #[test]
    fn test_inner_product_challenge_consistency() {
        // Same L,R → same challenge
        let l = Scalar::from(42u64) * pedersen_g();
        let r = Scalar::from(99u64) * pedersen_h();

        let u1 = compute_challenge_ipp(&l, &r);
        let u2 = compute_challenge_ipp(&l, &r);
        let u3 = compute_challenge_ipp(&l, &r);

        // Should be deterministic
        assert_eq!(u1, u2);
        assert_eq!(u2, u3);

        // Different L should give different challenge
        let l_different = Scalar::from(43u64) * pedersen_g();
        let u4 = compute_challenge_ipp(&l_different, &r);
        assert_ne!(u1, u4);
    }

    // ----------------------------------------------------------------------------
    // Helper Function Tests
    // ----------------------------------------------------------------------------

    #[test]
    fn test_bit_decompose() {
        // Test zero
        let bits = bit_decompose_bp(0);
        assert_eq!(bits.len(), 64);
        assert!(bits.iter().all(|b| *b == Scalar::zero()));

        // Test one
        let bits = bit_decompose_bp(1);
        assert_eq!(bits[0], Scalar::one());
        assert!(bits[1..].iter().all(|b| *b == Scalar::zero()));

        // Test power of 2
        let bits = bit_decompose_bp(256); // 2^8
        assert_eq!(bits[8], Scalar::one());
        for i in 0..64 {
            if i != 8 {
                assert_eq!(bits[i], Scalar::zero());
            }
        }

        // Test max value
        let bits = bit_decompose_bp(u64::MAX);
        assert!(bits.iter().all(|b| *b == Scalar::one()));

        // Test arbitrary value
        let value = 0b10110101u64;
        let bits = bit_decompose_bp(value);
        assert_eq!(bits[0], Scalar::one()); // bit 0
        assert_eq!(bits[1], Scalar::zero()); // bit 1
        assert_eq!(bits[2], Scalar::one()); // bit 2
        assert_eq!(bits[3], Scalar::zero()); // bit 3
        assert_eq!(bits[4], Scalar::one()); // bit 4
        assert_eq!(bits[5], Scalar::one()); // bit 5
        assert_eq!(bits[6], Scalar::zero()); // bit 6
        assert_eq!(bits[7], Scalar::one()); // bit 7
    }

    #[test]
    fn test_compute_delta() {
        let y = Scalar::from(2u64);
        let z = Scalar::from(3u64);

        let delta = compute_delta_bp(y, z);

        // For n=64, compute expected manually
        let y_powers = powers_of_bp(y, 64);
        let two_powers: [Scalar; 64] = std::array::from_fn(|i| Scalar::from(1u64 << i));
        let sum_y: Scalar = y_powers.iter().sum();
        let sum_two: Scalar = two_powers.iter().sum();
        let z_sq = z * z;
        let z_cubed = z_sq * z;
        let expected = (z - z_sq) * sum_y - z_cubed * sum_two;

        assert_eq!(delta, expected);
    }

    #[test]
    fn test_create_weighted_h() {
        let y_powers = powers_of_bp(Scalar::from(3u64), 64);

        let h_weighted = create_weighted_h_bp(&hv(), &y_powers);

        assert_eq!(h_weighted.len(), 64);
        // Check that H'[i] = y^(-i) * H[i]
        for i in 0..64 {
            assert_eq!(h_weighted[i], y_powers[i].invert().unwrap() * hv()[i]);
        }
    }

    #[test]
    fn test_compute_t1_t2() {
        use rand::thread_rng;

        let a_l: Vec<Scalar> = (0..64).map(|_| Scalar::random(&mut thread_rng())).collect();
        let a_r: Vec<Scalar> = (0..64).map(|_| Scalar::random(&mut thread_rng())).collect();
        let s_l: Vec<Scalar> = (0..64).map(|_| Scalar::random(&mut thread_rng())).collect();
        let s_r: Vec<Scalar> = (0..64).map(|_| Scalar::random(&mut thread_rng())).collect();
        let y_powers = powers_of_bp(Scalar::from(2u64), 64);
        let z = Scalar::from(3u64);

        let t1 = compute_t1_bp(&a_l, &a_r, &s_l, &s_r, &y_powers, z);
        let t2 = compute_t2_bp(&s_l, &s_r, &y_powers);

        // t2 should be <sL, y^n ∘ sR>
        let y_sr = hadamard_product(&y_powers, &s_r);
        let expected_t2 = inner_product(&s_l, &y_sr);
        assert_eq!(t2, expected_t2);

        // Both should be non-zero for random inputs (with high probability)
        // Just check they compute without panicking
        let _ = (t1, t2);
    }

    #[test]
    fn test_compute_lr_vectors() {
        use rand::thread_rng;

        let a_l: Vec<Scalar> = (0..64).map(|_| Scalar::random(&mut thread_rng())).collect();
        let a_r: Vec<Scalar> = (0..64).map(|_| Scalar::random(&mut thread_rng())).collect();
        let s_l: Vec<Scalar> = (0..64).map(|_| Scalar::random(&mut thread_rng())).collect();
        let s_r: Vec<Scalar> = (0..64).map(|_| Scalar::random(&mut thread_rng())).collect();
        let y_powers = powers_of_bp(Scalar::from(2u64), 64);
        let z = Scalar::from(3u64);
        let x = Scalar::from(5u64);

        let (l, r) = compute_lr_vectors_bp(&a_l, &a_r, &s_l, &s_r, &y_powers, z, x);

        assert_eq!(l.len(), 64);
        assert_eq!(r.len(), 64);

        // l should be linear in x: l = l0 + x*sL
        // When x=0, should get l0 = aL - z*1^n
        let (l_at_zero, _) =
            compute_lr_vectors_bp(&a_l, &a_r, &s_l, &s_r, &y_powers, z, Scalar::zero());
        let ones = vec![Scalar::one(); 64];
        let z_ones = scalar_vector_mul_bp(z, &ones);
        let expected_l0 = vector_sub_bp(&a_l, &z_ones);
        assert_eq!(l_at_zero, expected_l0);
    }

    // ----------------------------------------------------------------------------
    // Range Proof Tests
    // ----------------------------------------------------------------------------

    #[test]
    fn test_commitment_reconstruction() {
        // Test that we can reconstruct P correctly
        use rand::thread_rng;

        // Simulate prover: create aL, aR, sL, sR
        let a_l = bit_decompose_bp(100u64);
        let ones = [Scalar::one(); 64];
        let a_r = vector_sub_bp(&a_l, &ones);
        let s_l: Vec<Scalar> = (0..64).map(|_| Scalar::random(&mut thread_rng())).collect();
        let s_r: Vec<Scalar> = (0..64).map(|_| Scalar::random(&mut thread_rng())).collect();
        let alpha = Scalar::random(&mut thread_rng());
        let rho = Scalar::random(&mut thread_rng());

        // Create A and S commitments
        let a_commit =
            vector_commit_bp(&a_l, &gv()) + vector_commit_bp(&a_r, &hv()) + alpha * pedersen_h();
        let s_commit =
            vector_commit_bp(&s_l, &gv()) + vector_commit_bp(&s_r, &hv()) + rho * pedersen_h();

        // Generate challenges
        let y = compute_challenge_y(&a_commit, &s_commit);
        let z = compute_challenge_z(y);
        let y_powers = powers_of_bp(y, 64);

        // Create dummy t1, t2 for x challenge
        let t1_commit = Scalar::random(&mut thread_rng()) * pedersen_g();
        let t2_commit = Scalar::random(&mut thread_rng()) * pedersen_g();
        let x = compute_challenge_x(&t1_commit, &t2_commit, z);

        // Compute l and r
        let (l, r) = compute_lr_vectors_bp(&a_l, &a_r, &s_l, &s_r, &y_powers, z, x);
        let mu = alpha + rho * x;

        // Prover's P with weighted H
        let h_vec_weighted = create_weighted_h_bp(&hv(), &y_powers);
        let p_prover = vector_commit_bp(&l, &gv()) + vector_commit_bp(&r, &h_vec_weighted);

        // Verifier's P reconstruction
        // P = A + x*S - mu*h - <z*1^n, G> + <z*y^n*1^n + z^2*2^n, H'>
        let z_sq = z * z;
        let two_powers: [Scalar; 64] = std::array::from_fn(|i| Scalar::from(1u64 << i));
        let z_ones = scalar_vector_mul_bp(z, &ones);
        let z_y_ones = scalar_vector_mul_bp(z, &y_powers); // z * y^n * 1^n
        let z_sq_two = scalar_vector_mul_bp(z_sq, &two_powers);
        let h_adjustment = vector_add_bp(&z_y_ones, &z_sq_two);

        let p_verifier = a_commit + x * s_commit - vector_commit_bp(&z_ones, &gv())
            + vector_commit_bp(&h_adjustment, &h_vec_weighted)
            - mu * pedersen_h();

        use group::Curve;
        println!("P prover:   {:?}", p_prover.to_affine().to_compressed());
        println!("P verifier: {:?}", p_verifier.to_affine().to_compressed());

        assert_eq!(p_prover, p_verifier, "P commitments should match!");
    }

    #[test]
    fn test_rp_max() {
        let blinding = Scalar::random(&mut thread_rng());
        let commitment = crate::pedersen_commit(u64::MAX, blinding);

        assert!(verify(commitment, &prove(u64::MAX, blinding)));
    }

    #[test]
    fn test_rp_powers_of_two() {
        for i in 0..8 {
            let blinding = Scalar::random(&mut thread_rng());
            let commitment = crate::pedersen_commit(1 << i, blinding);

            assert!(verify(commitment, &prove(1 << i, blinding)));
        }
    }

    #[test]
    fn test_rp_range() {
        for value in 0..10 {
            let blinding = Scalar::random(&mut thread_rng());
            let commitment = crate::pedersen_commit(value, blinding);

            assert!(verify(commitment, &prove(value, blinding)));
        }
    }

    #[test]
    fn test_rp_wrong_commitment() {
        let blinding = Scalar::random(&mut thread_rng());

        let wrong_commitment = crate::pedersen_commit(54321u64, blinding);

        assert!(!verify(wrong_commitment, &prove(12345u64, blinding)));
    }

    #[test]
    fn test_rp_tampered_proof() {
        let blinding = Scalar::random(&mut thread_rng());
        let commitment = crate::pedersen_commit(999, blinding);

        // Tamper with A
        let mut proof = prove(999, blinding);

        proof.a += pedersen_g();

        assert!(!verify(commitment, &proof));

        // Tamper with t_hat
        let mut proof = prove(999, blinding);

        proof.t_hat += Scalar::one();

        assert!(!verify(commitment, &proof));

        // Tamper with tau_x
        let mut proof = prove(999, blinding);

        proof.tau_x += Scalar::one();

        assert!(!verify(commitment, &proof));
    }
}
