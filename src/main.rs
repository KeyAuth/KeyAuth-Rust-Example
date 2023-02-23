fn main() {
    let mut auth = keyauth::v1_2::KeyauthApi::new(
        "demo",
        "demo",
        "demo",
        "1.0",
        "https://keyauth.cc/api/1.2/",
    );

    // None or Some(apphash)
    // we call unwrap() because if the response success = false, it returns an error with the error message
    auth.init(None).unwrap();

    // None will auto generate hwid, if you want to use your own hwid system then use Some(hwid)
    //auth.register("some_username".to_string(), "some_password_from_user".to_string(), "7F64WM-TP3I4H-6NY0QI-164KGY-WP5CHF-EBFG30".to_string(), None).unwrap();
    // again None will autogenerate hwid
    auth.login("some_username".to_string(), "some_password_from_user".to_string(), None).unwrap();

    // for more functions see the docs https://docs.rs/keyauth/latest/keyauth/
}
