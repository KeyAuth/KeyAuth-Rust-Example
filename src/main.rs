fn main() {
    let mut keyauthapp = keyauth::v1_2::KeyauthApi::new(
        "library-development",
        "EdmsTKiuld",
        "9f752b6a414455175efd942abfd2183667413d57b1d59d6742d8437c71802b49",
        "1.0",
        "https://keyauth.cc/api/1.2/",
    );

    // None or Some(apphash)
    // we call unwrap() because if the response success = false, it returns an error with the error message
    keyauthapp.init(None).unwrap();

    // None will auto generate hwid, if you want to use your own hwid system then use Some(hwid)
    //auth.register("some_username".to_string(), "some_password_from_user".to_string(), "7F64WM-TP3I4H-6NY0QI-164KGY-WP5CHF-EBFG30".to_string(), None).unwrap();
    // again None will autogenerate hwid
    keyauthapp.login("some_username".to_string(), "some_password_from_user".to_string(), None).unwrap();

    // for more functions see the docs https://docs.rs/keyauth/latest/keyauth/
}
