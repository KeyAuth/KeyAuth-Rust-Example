fn get_hwid() -> String {
    let output = std::process::Command::new("wmic")
        .args(&["csproduct", "get", "uuid"])
        .output()
        .ok();

    if let Some(output) = output {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let lines: Vec<&str> = stdout.lines().collect();
        if lines.len() >= 2 {
            let hwid = lines[1].trim().to_string();
            if !hwid.is_empty() && hwid != "UUID" {
                return hwid;
            }
        }
    }
    "default-hwid".to_string()
}

fn main() {
    let mut keyauthapp = keyauth::v1_2::KeyauthApi::new(
        "example",
        "JjPMBVlIOd",
        "db40d586f4b189e04e5c18c3c94b7e72221be3f6551995adc05236948d1762bc",
        "1.0",
        "https://keyauth.cc/api/1.2/",
    );

    // None or Some(apphash)
    // we call unwrap() because if the response success = false, it returns an error with the error message
    keyauthapp.init(None).unwrap();

    let hwid = get_hwid();

    // None will auto generate hwid, if you want to use your own hwid system then use Some(hwid)
    //auth.register("some_username".to_string(), "some_password_from_user".to_string(), "7F64WM-TP3I4H-6NY0QI-164KGY-WP5CHF-EBFG30".to_string(), Some(hwid.clone())).unwrap();
    // again None will autogenerate hwid
    keyauthapp.login("some_username".to_string(), "some_password_from_user".to_string(), Some(hwid)).unwrap();

    // for more functions see the docs https://docs.rs/keyauth/latest/keyauth/
}
