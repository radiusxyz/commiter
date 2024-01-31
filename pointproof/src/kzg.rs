use ark_ec::ProjectiveCurve;
use ark_ec::{msm::VariableBaseMSM, PairingEngine};
use ark_ff::PrimeField;
use ark_poly::UVPolynomial;
use ark_poly_commit::kzg10::{Powers, Proof, Randomness, UniversalParams, VerifierKey, KZG10};
use ark_poly_commit::PCUniversalParams;
use ark_std::borrow::Cow;
use ark_std::{end_timer, start_timer};
#[cfg(feature = "parallel")]
use rayon::iter::IntoParallelRefIterator;
#[cfg(feature = "parallel")]
use rayon::iter::ParallelIterator;
use std::ops::Div;

/// ORIGINAL - trim()
/// Specializes the public parameters for a given maximum degree `d` for polynomials
/// `d` should be less that `pp.max_degree()`.
pub fn trim<E>(pp: &UniversalParams<E>, mut supported_degree: usize) -> (Powers<E>, VerifierKey<E>)
where
    E: PairingEngine,
{
    if supported_degree == 1 {
        supported_degree += 1;
    }

    // Is `supported_degree` always bigger than the Vector length?
    let powers_of_g = pp.powers_of_g[..=supported_degree].to_vec();

    // Is `supported_degree` always bigger than the BTreeMap length?
    let powers_of_gamma_g = (0..=supported_degree)
        .map(|i| pp.powers_of_gamma_g[&i])
        .collect();

    let powers = Powers {
        powers_of_g: ark_std::borrow::Cow::Owned(powers_of_g),
        powers_of_gamma_g: ark_std::borrow::Cow::Owned(powers_of_gamma_g),
    };
    let vk = VerifierKey {
        g: pp.powers_of_g[0],
        gamma_g: pp.powers_of_gamma_g[&0],
        h: pp.h,
        beta_h: pp.beta_h,
        prepared_h: pp.prepared_h.clone(),
        prepared_beta_h: pp.prepared_beta_h.clone(),
    };
    (powers, vk)
}

/// REVISED - trim()
/// Remove redundant allocations incurred by `to_owned` of `Cow::Owned` and pass
/// borrowed value. Better performance with the lifetime parameter. It is up to a user
/// to guarantee in runtime that the lifetime of `UniversalParams<E>` is covariant with
/// that of `Powers<E>`.
pub fn trim_revised<E>(
    pp: &UniversalParams<E>,
    mut supported_degree: usize,
) -> (Powers<E>, VerifierKey<E>)
where
    E: PairingEngine,
{
    // Needs explanation.
    if supported_degree == 1 {
        supported_degree += 1;
    }
    // Check length. All assertions must be turned into Result<T, E> for the production.
    assert!(supported_degree <= pp.max_degree());

    let powers_of_gamma_g = pp
        .powers_of_gamma_g
        .values()
        .take(supported_degree)
        .copied()
        .collect::<Vec<_>>();

    let powers = Powers {
        powers_of_g: Cow::Borrowed(&pp.powers_of_g[..=supported_degree]),
        powers_of_gamma_g: Cow::Owned(powers_of_gamma_g),
    };

    let vk = VerifierKey {
        g: pp.powers_of_g[0],
        gamma_g: pp.powers_of_gamma_g[&0],
        h: pp.h,
        beta_h: pp.beta_h,
        prepared_h: pp.prepared_h.to_owned(),
        prepared_beta_h: pp.prepared_beta_h.to_owned(),
    };

    (powers, vk)
}

pub(crate) fn check_degree_is_too_large(degree: usize, num_powers: usize) -> bool {
    let num_coefficients = degree + 1;
    num_coefficients <= num_powers
}

fn open_with_witness_polynomial<E, P>(
    powers: &Powers<E>,
    point: P::Point,
    randomness: &Randomness<E::Fr, P>,
    witness_polynomial: &P,
    hiding_witness_polynomial: Option<&P>,
) -> Proof<E>
where
    E: PairingEngine,
    P: UVPolynomial<E::Fr, Point = E::Fr>,
    for<'a, 'b> &'a P: Div<&'b P, Output = P>,
{
    assert!(
        check_degree_is_too_large(witness_polynomial.degree(), powers.size()),
        "degree is too large"
    );
    let (num_leading_zeros, witness_coeffs) =
        skip_leading_zeros_and_convert_to_bigints(witness_polynomial);

    let witness_comm_time = start_timer!(|| "Computing commitment to witness polynomial");
    let mut w = VariableBaseMSM::multi_scalar_mul(
        &powers.powers_of_g[num_leading_zeros..],
        &witness_coeffs,
    );
    end_timer!(witness_comm_time);

    let random_v = if let Some(hiding_witness_polynomial) = hiding_witness_polynomial {
        let blinding_p = &randomness.blinding_polynomial;
        let blinding_eval_time = start_timer!(|| "Evaluating random polynomial");
        let blinding_evaluation = blinding_p.evaluate(&point);
        end_timer!(blinding_eval_time);

        let random_witness_coeffs = convert_to_bigints(&hiding_witness_polynomial.coeffs());
        let witness_comm_time =
            start_timer!(|| "Computing commitment to random witness polynomial");
        w += &VariableBaseMSM::multi_scalar_mul(&powers.powers_of_gamma_g, &random_witness_coeffs);
        end_timer!(witness_comm_time);
        Some(blinding_evaluation)
    } else {
        None
    };

    Proof {
        w: w.into_affine(),
        random_v,
    }
}

/// On input a polynomial `p` and a point `point`, outputs a proof for the same.
pub fn open<E, P>(
    powers: &Powers<E>,
    p: &P,
    point: P::Point,
    rand: &Randomness<E::Fr, P>,
) -> Proof<E>
where
    E: PairingEngine,
    P: UVPolynomial<E::Fr, Point = E::Fr>,
    for<'a, 'b> &'a P: Div<&'b P, Output = P>,
{
    // Assertion will be removed in the production and `Result<T, E>` will be returned.
    assert!(
        check_degree_is_too_large(p.degree(), powers.size()),
        "degree is too large"
    );

    let open_time = start_timer!(|| format!("Opening polynomial of degree {}", p.degree()));

    let witness_time = start_timer!(|| "Computing witness polynomials");
    let (witness_poly, hiding_witness_poly) =
        KZG10::<E, P>::compute_witness_polynomial(p, point, rand).unwrap();
    end_timer!(witness_time);

    let proof = open_with_witness_polynomial(
        powers,
        point,
        rand,
        &witness_poly,
        hiding_witness_poly.as_ref(),
    );

    end_timer!(open_time);
    proof
}

/// ORIGINAL - skip_leading_zeros_and_convert_to_bigints
fn skip_leading_zeros_and_convert_to_bigints<F: PrimeField, P: UVPolynomial<F>>(
    p: &P,
) -> (usize, Vec<F::BigInt>) {
    let mut num_leading_zeros = 0;
    while num_leading_zeros < p.coeffs().len() && p.coeffs()[num_leading_zeros].is_zero() {
        num_leading_zeros += 1;
    }
    let coeffs = convert_to_bigints(&p.coeffs()[num_leading_zeros..]);
    (num_leading_zeros, coeffs)
}

/// REVISED - skip_leading_zeros_and_convert_to_bigints
fn skip_leading_zeros_and_convert_to_bigints_revised<F: PrimeField, P: UVPolynomial<F>>(
    p: &P,
) -> (usize, Vec<F::BigInt>) {
    // Less verbose for the same performance.
    let num_leading_zeros = p.coeffs().iter().filter(|coeff| coeff.is_zero()).count();
    let coeffs = convert_to_bigints(&p.coeffs()[num_leading_zeros..]);
    (num_leading_zeros, coeffs)
}

fn convert_to_bigints<F: PrimeField>(p: &[F]) -> Vec<F::BigInt> {
    let to_bigint_time = start_timer!(|| "Converting polynomial coeffs to bigints");
    let coeffs = ark_std::cfg_iter!(p)
        .map(|s| s.into_repr())
        .collect::<Vec<_>>();
    end_timer!(to_bigint_time);
    coeffs
}
