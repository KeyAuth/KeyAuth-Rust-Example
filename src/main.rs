// Import the keyauth module from the other file
mod keyauth;

fn main() {
    // This is the example for using keyauth.com in your rust application.
    let mut keyauthapp = keyauth::KeyauthApi::new(
        "App name", // This should be your application name, you can find this in your dashboard
        "Owner ID", // This is your ownerid, you can find this in your user settings (where you change your password)
        obfstr::obfstr!("Application secret"), // This is your app secret
        "Version",
    );
    let key = "A random key".to_string();
    let key2 = "A different random key".to_string();
    let key3 = "Yet another random key".to_string();

    let varid = "A testing variable ID".to_string();
    let fileid = "A testing file ID (with a text file uploaded)".to_string();
    let webid = "A webhook ID".to_string();
    let params = "Anything you want".to_string();

    let username = "Any_username".to_string();
    let password = "Any_password".to_string();

    // You always need to call init first, otherwise the authentication will fail!
    match keyauthapp.init() {
        Ok(_) => println!("Initialized"),
        Err(msg) => {
            println!("Error: {}", msg);
            return;
        }
    };

    match keyauthapp.register(username.clone(), password.clone(), key, None) {
        Ok(_) => println!("Registered"),
        Err(msg) => {
            println!("Error: {}", msg);
            return;
        }
    }

    match keyauthapp.login(username.clone(), password, None) {
        Ok(_) => println!("Logged in"),
        Err(msg) => {
            println!("Error: {}", msg);
            return;
        }
    }

    match keyauthapp.license(key2, None) {
        Ok(_) => println!("License works"),
        Err(msg) => {
            println!("Error: {}", msg);
            return;
        }
    }

    match keyauthapp.upgrade(username, key3) {
        Ok(_) => println!("Upgrade works"),
        Err(msg) => {
            println!("Error: {}", msg);
            return;
        }
    }

    match keyauthapp.var(varid) {
        Ok(var) => println!("VarID works: {}", var),
        Err(msg) => {
            println!("Error: {}", msg);
            return;
        }
    }

    match keyauthapp.file(fileid) {
        Ok(contents) => println!("FileID works: {}", String::from_utf8_lossy(&contents)),
        Err(msg) => {
            println!("Error: {}", msg);
            return;
        }
    }

    match keyauthapp.webhook(webid, params) {
        Ok(contents) => println!("Web works: {}", contents),
        Err(msg) => {
            println!("Error: {}", msg);
            return;
        }
    }

    keyauthapp.log("Log message works as well!".to_string());
    println!("Log seems to work as well!");

    println!("Done!");
}
