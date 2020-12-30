// Import the keyauth module from the other file
mod keyauth;

// This is not required, but it makes it so that the secret isn't visible if you run strings on the executable
use obfstr;

fn main() {
    // This is the example for using keyauth.com in your rust application.
    let mut keyauthapp = keyauth::KeyauthApi::new(
        "Application name".to_string(), // This should be your application name, you can find this in your dashboard
        "Owner ID".to_string(), // This is your ownerid, you can find this in your user settings (where you change your password)
        obfstr::obfstr!("Application secret").to_string(), // This is your app secret
        // The obfstr is a good idea to have (it wont hurt) but it might not be enough! If someone has this it's trivial to bypass the authentication!
    );
    let key: String = "Key".to_string();

    // You always need to call init first, otherwise the authentication will fail!
    match keyauthapp.init() {
        Ok(_) => println!("Initialized"),
        Err(msg) => {
            println!("Error: {}", msg);
            return;
        }
    };

    // Then you call login, here is where you ask for the key from the user.
    // You should save the key somewhere otherwise the user will have to enter it every single time.
    // The implementation of this is left up to the user.
    let key_info = match keyauthapp.login(key, None) {
        Ok(key_info) => key_info,
        Err(msg) => {
            println!("Error: {}", msg);
            return;
        }
    };
    // The `key_info` variable contains the expiry and level of the key the user entered. 
    println!("{:?}", key_info);

    // This logs a message, should be self-explanitory
    match keyauthapp.log("This will get logged!".into()) {
        Ok(_) => println!("Logged message!"),
        Err(why) => {
            println!("Error: {}", why);
            return;
        }
    };
}
