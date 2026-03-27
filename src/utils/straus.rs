//! Straus' multi-scalar multiplication for small numbers of points.
//!
//! Computes `s_1*P_1 + s_2*P_2 + ... + s_n*P_n` by scanning all scalars
//! bit-by-bit (or window-by-window) in lockstep, using a precomputed table
//! of all combinations of point multiples to perform a single lookup per step.
//!
//! The precomputed table has `(2^w)^n` entries, so this is only practical for
//! small `n` (roughly n <= 5 with w=1). For larger sets, Pippenger / bucket
//! MSM methods are preferable.
//!
//! Reference: Handbook of Elliptic and Hyperelliptic Curve Cryptography,
//! [Algorithm 9.23](https://hyperelliptic.org/HEHCC/chapters/chap09.pdf).

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{AdditiveGroup, BigInteger, PrimeField, Zero};
use ark_std::{iter, vec::Vec};

/// Builds the precomputation table for `n` points with window size `w`.
///
/// For each point `P_i`, stores multiples `k*P_i` for `k` in `1..2^w`,
/// then forms all cross-products with the previously accumulated rows.
/// The resulting table has `(2^w)^n` entries (including the identity at index 0),
/// stored in affine coordinates for cheaper mixed additions in the main loop.
fn table<C: AffineRepr>(points: &[C], w: usize) -> Vec<C> {
    let c = 2usize.pow(w as u32);
    let total = c.pow(points.len() as u32);
    let mut table = Vec::with_capacity(total);
    table.push(C::Group::zero());
    for p in points {
        let prev_len = table.len();
        // k=1: P_i + table[j] for j in 0..prev_len
        for j in 0..prev_len {
            table.push(table[j] + p);
        }
        // k=2..c-1: reuse previous row, since k*P_i + table[j] = P_i + (k-1)*P_i + table[j]
        for k in 2..c {
            for j in 0..prev_len {
                table.push(table[(k - 1) * prev_len + j] + p);
            }
        }
    }
    C::Group::normalize_batch(&table)
}

/// Extracts a `w`-bit digit from position `bit_pos` (LSB-indexed) of the BigInt.
fn extract_digit<B: BigInteger>(repr: &B, bit_pos: usize, w: usize, mask: u32) -> u32 {
    let limbs = repr.as_ref();
    let limb_idx = bit_pos / 64;
    let bit_idx = bit_pos % 64;
    let mut digit = (limbs[limb_idx] >> bit_idx) as u32;
    if bit_idx + w > 64 && limb_idx + 1 < limbs.len() {
        digit |= (limbs[limb_idx + 1] << (64 - bit_idx)) as u32;
    }
    digit & mask
}

/// Converts per-window scalar digits into table lookup indices.
///
/// For each window position (MSB to LSB), combines per-scalar digits into a
/// single table index using mixed-radix encoding: `d_0 + d_1*(2^w) + d_2*(2^w)^2 + ...`.
fn indices<F: PrimeField>(scalars: &[F], w: usize) -> Vec<usize> {
    let repr_bit_len = F::BigInt::NUM_LIMBS * 64;
    let num_digits = repr_bit_len.div_ceil(w);
    let mask = (1u32 << w) - 1;

    let reprs: Vec<_> = scalars.iter().map(|s| s.into_bigint()).collect();

    let powers_of_c: Vec<u32> = iter::successors(Some(1u32), |prev| Some(prev << w))
        .take(scalars.len())
        .collect();

    (0..num_digits)
        .map(|i| {
            let bit_pos = (num_digits - 1 - i) * w;
            reprs
                .iter()
                .zip(powers_of_c.iter())
                .map(|(r, &pc)| extract_digit(r, bit_pos, w, mask) * pc)
                .sum::<u32>() as usize
        })
        .collect()
}

/// Straus multi-scalar multiplication with configurable window size `w`.
///
/// Larger `w` reduces the number of doubling rounds (from `b` to `b/w` for
/// `b`-bit scalars) at the cost of an exponentially larger table: `(2^w)^n`
/// entries. In practice, `w=2` is optimal for n <= 3 and `w=1` for n >= 4.
pub fn short_msm<C: AffineRepr>(points: &[C], scalars: &[C::ScalarField], w: usize) -> C::Group {
    let table = table(points, w);
    let indices = indices(scalars, w);
    let mut acc = C::Group::zero();
    for idx in indices.into_iter().skip_while(|&idx| idx == 0) {
        for _ in 0..w {
            acc.double_in_place();
        }
        acc += table[idx]
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::{UniformRand, test_rng};

    type TestAffine = crate::AffinePoint<crate::suites::testing::TestSuite>;
    type TestScalar = crate::ScalarField<crate::suites::testing::TestSuite>;

    #[test]
    fn straus_works() {
        let rng = &mut test_rng();

        for n in 2..=4 {
            let scalars = (0..n).map(|_| TestScalar::rand(rng)).collect::<Vec<_>>();
            let points = (0..n).map(|_| TestAffine::rand(rng)).collect::<Vec<_>>();

            let res: <TestAffine as AffineRepr>::Group =
                points.iter().zip(scalars.iter()).map(|(&p, s)| p * s).sum();

            for w in 1..=3 {
                let res_w = short_msm(&points, &scalars, w);
                assert_eq!(res_w, res, "mismatch for n={n}, w={w}");
            }
        }
    }
}
