#[macro_use] extern crate rocket;
use pointproof;

#[get("/commitment")]
fn commitment() -> &'static str {
    "Hello, world!"
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