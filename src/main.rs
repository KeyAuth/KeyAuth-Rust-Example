mod keyauth;

fn main() {
    let keyauthapp = keyauth::KeyauthApi::new(
        "Application name".into(),
        "Owner ID".into(),
        "Secret".into(),
    );
    match keyauthapp.init() {
        Ok(_) => println!("Initialized"),
        Err(msg) => {
            println!("{}", msg);
            return;
        }
    };

    match keyauthapp.login("000CC0-003F6C-00F95F-00429B-00AC0A-00BBF9".into(), None) {
        Ok(_) => println!("Logged in"),
        Err(msg) => {
            println!("{}", msg);
            return;
        }
    };
}
