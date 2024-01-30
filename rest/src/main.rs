#[macro_use] extern crate rocket;
use pointproof::*;
use ark_std::{rand::Rng, test_rng};
use ark_bn254::Bn254;
use ark_ec::PairingEngine;
use ark_std::UniformRand;

#[get("/commitment")]
fn commitment() -> &'static str {
    let mut rng = test_rng();
    let srs = StructuredReferenceString::<Bn254, 128>::new_srs_for_testing(&mut rng);
    let prover_param: ProverParam<Bn254, 128> = (&srs).into();

    let mut chars = "messagesmessagesmessagesmessagesmessagesmessagesmessagesmessagesmessagesmessagesmessagesmessagesmessagesmessagesmessagesmessages".chars();

    let message: Vec<<Bn254 as PairingEngine>::Fr> = (0..128)
    .map(|_| <Bn254 as PairingEngine>::Fr::from(chars.next().unwrap() as u32))
    .collect();
    let commitment: Commitment<ark_ec::bn::Bn<ark_bn254::Parameters>, 128> = Commitment::<Bn254, 128>::commit(&prover_param, &message);
    let s = commitment.to_string().as_str().to_owned();
    Box::leak(s.into_boxed_str())
}

#[get("/test")]
fn test() -> &'static str {
    "Hello, test!"
}

#[launch]
fn rocket() -> _ {
    rocket::build()
        .mount("/", routes![commitment, test])
}