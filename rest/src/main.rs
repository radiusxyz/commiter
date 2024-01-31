#[macro_use]
extern crate rocket;
use ark_bn254::Bn254;
use ark_ec::PairingEngine;
use ark_std::UniformRand;
use ark_std::{rand::Rng, test_rng};
use pointproof::*;

/// ORIGINAL
#[get("/commitment")]
fn commitment() -> &'static str {
    let mut rng = test_rng();
    let srs = StructuredReferenceString::<Bn254, 128>::new_srs_for_testing(&mut rng);
    let prover_param: ProverParam<Bn254, 128> = (&srs).into();

    let mut chars = "messagesmessagesmessagesmessagesmessagesmessagesmessagesmessagesmessagesmessagesmessagesmessagesmessagesmessagesmessagesmessages".chars();

    let message: Vec<<Bn254 as PairingEngine>::Fr> = (0..128)
        .map(|_| <Bn254 as PairingEngine>::Fr::from(chars.next().unwrap() as u32))
        .collect();
    let commitment: Commitment<ark_ec::bn::Bn<ark_bn254::Parameters>, 128> =
        Commitment::<Bn254, 128>::commit(&prover_param, &message);
    let s = commitment.to_string().as_str().to_owned();
    Box::leak(s.into_boxed_str()) // Memory leak occurs unless converted back to box using `Box::from_raw`.
}

/// REVISED
#[get("/commitment-revised")]
fn commitment_revised() -> String {
    let mut rng = test_rng();
    let srs = StructuredReferenceString::<Bn254, 128>::new_srs_for_testing(&mut rng);
    let prover_param: ProverParam<Bn254, 128> = (&srs).into();

    let chars = "messagesmessagesmessagesmessagesmessagesmessagesmessagesmessagesmessagesmessagesmessagesmessagesmessagesmessagesmessagesmessages".chars();

    // Faster because there's no null-check for `chars_next()` iterator.
    // If the input must be truncated in the case of `chars` being greater than the const N: 128,
    // there must be another function which returns `Result`.
    let message: Vec<<Bn254 as PairingEngine>::Fr> = chars
        .into_iter()
        .map(|i| <Bn254 as PairingEngine>::Fr::from(i as u32))
        .collect();

    let commitment = Commitment::<Bn254, 128>::commit(&prover_param, &message);

    commitment.to_string()
}

#[get("/test")]
fn test() -> &'static str {
    "Hello, test!"
}

#[launch]
fn rocket() -> _ {
    rocket::build().mount("/", routes![commitment, commitment_revised, test])
}
