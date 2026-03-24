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
use ark_ff::{AdditiveGroup, BigInteger, BitIteratorBE, PrimeField, Zero};
use ark_std::{iter, vec, vec::Vec};

/// Builds the precomputation table for `n` points with window size `w`.
///
/// For each point `P_i`, stores multiples `k*P_i` for `k` in `1..2^w`,
/// then forms all cross-products with the previously accumulated rows.
/// The resulting table has `(2^w)^n` entries (including the identity at index 0),
/// stored in affine coordinates for cheaper mixed additions in the main loop.
fn table<C: AffineRepr>(points: &[C], w: u32) -> Vec<C> {
    let c = 2usize.pow(w);
    let mut table = vec![C::Group::zero()];
    for p in points {
        // P, 2P, ..., (c-1)P, where c = 2^w
        let multiples_of_p: Vec<C::Group> =
            iter::successors(Some(p.into_group()), move |prev| Some(*p + *prev))
                .take(c - 1)
                .collect();
        let new_rows: Vec<C::Group> = multiples_of_p
            .iter()
            .flat_map(|&kp| table.iter().map(move |&prev_row| prev_row + kp))
            .collect();
        table.extend(new_rows)
    }
    C::Group::normalize_batch(&table)
}

/// Converts a window of `w` bits (LSB-first) into an unsigned digit in `0..2^w`.
fn bits_to_digit<I: Iterator<Item = bool>>(bits: I, powers_of_2: &[u32]) -> u32 {
    bits.zip(powers_of_2.iter())
        .filter_map(|(bit, power)| bit.then_some(power))
        .sum::<u32>()
}

/// Combines per-scalar digits into a single table index using mixed-radix encoding.
///
/// Each scalar contributes a digit in `0..2^w`; the combined index is
/// `d_0 + d_1*(2^w) + d_2*(2^w)^2 + ...`, matching the table layout.
fn digits_to_index<I: Iterator<Item = u32>>(digits: I, powers_of_c: &[u32]) -> usize {
    digits
        .zip(powers_of_c.iter())
        .map(|(digit, power)| digit * power)
        .sum::<u32>() as usize
}

/// Pads the big-endian bit decomposition of `scalar` with leading zeros
/// so that the total length is a multiple of the window size `w`.
fn to_msbf_bits_padded<F: PrimeField>(scalar: F, w: usize) -> Vec<bool> {
    let repr_bit_len = F::BigInt::NUM_LIMBS * 64;
    let extra_bits = repr_bit_len % w;
    let padding_len = if extra_bits == 0 { 0 } else { w - extra_bits };
    iter::repeat(false)
        .take(padding_len)
        .chain(BitIteratorBE::new(scalar.into_bigint()))
        .collect()
}

/// Decomposes each scalar into a sequence of base-`2^w` digits (MSB-first).
fn to_base_c_digits<F: PrimeField>(scalars: &[F], w: usize) -> Vec<Vec<u32>> {
    let powers_of_2 = iter::successors(Some(1u32), move |prev| Some(prev << 1))
        .take(w)
        .collect::<Vec<_>>();

    scalars
        .iter()
        .map(|&s| {
            to_msbf_bits_padded(s, w)
                .chunks(w)
                .map(|w_bit_chunk| bits_to_digit(w_bit_chunk.iter().rev().cloned(), &powers_of_2))
                .collect()
        })
        .collect()
}

/// Converts per-window scalar digits into table lookup indices.
///
/// Returns one index per window position, scanning from MSB to LSB.
fn indices<F: PrimeField>(scalars: &[F], w: usize) -> Vec<usize> {
    let scalars_base_c = to_base_c_digits(scalars, w);
    let powers_of_c = iter::successors(Some(1u32), move |prev| Some(prev << w))
        .take(scalars.len())
        .collect::<Vec<_>>();
    (0..scalars_base_c[0].len())
        .map(|i| {
            let slice = scalars_base_c.iter().map(|s| s[i]);
            digits_to_index(slice, &powers_of_c)
        })
        .collect()
}

/// Straus multi-scalar multiplication with window size 1.
pub fn short_msm<C: AffineRepr>(points: &[C], scalars: &[C::ScalarField]) -> C::Group {
    short_msm_windowed(points, scalars, 1)
}

/// Straus multi-scalar multiplication with configurable window size `w`.
///
/// Larger `w` reduces the number of doubling rounds (from `b` to `b/w` for
/// `b`-bit scalars) at the cost of an exponentially larger table: `(2^w)^n`
/// entries. In practice, `w=2` is optimal for n <= 3 and `w=1` for n >= 4.
pub fn short_msm_windowed<C: AffineRepr>(
    points: &[C],
    scalars: &[C::ScalarField],
    w: usize,
) -> C::Group {
    let table = table(points, w as u32);
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
    use ark_std::{test_rng, UniformRand};

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
                let res_w = short_msm_windowed(&points, &scalars, w);
                assert_eq!(res_w, res, "mismatch for n={n}, w={w}");
            }
        }
    }
}
