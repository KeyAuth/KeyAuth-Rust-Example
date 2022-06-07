mod keyauth;
use simple_user_input::get_input;
use std::process;

fn main() {
    let mut keyauthapp = keyauth::KeyauthApi::new(
        "",   // Application name
        "", // Application OwnerID
        obfstr::obfstr!(""), // Application Secret
        "", // Application Version
    );

    match keyauthapp.init() {
        Ok(_) => println!("Initialized"),
        Err(msg) => {
            println!("\n\n Error: {}", msg);
            return;
        }
    };

    keyauthapp.check();
    keyauthapp.checkBlack();
    println!(
        "
-
 Application Data:
 Number of users: {}
 Number of online users: {}
 Number of keys: {}
 Application Version: {}
 Customer panel link: {}

 Session Validated? {}
 BlackListed? {}
",
        keyauthapp.numKeys.to_string(),
        keyauthapp.numOnlineUsers.to_string(),
        keyauthapp.numUsers.to_string(),
        keyauthapp.appVersion.to_string(),
        keyauthapp.customerPanelLink.to_string(),
        keyauthapp.message.to_string(),
        keyauthapp.blackListed.to_string()
    );

    let input: String = get_input(
        "
 1 Login
 2 Register
 3 Upgrade 
 4 License
    
 Your Choice: ",
    );

    if input == "1" {
        let UserName: String = get_input(" Username: ");
        let PassWord: String = get_input(" Password: ");

        match keyauthapp.login(UserName, PassWord, None) {
            Ok(_) => {}
            Err(msg) => {
                println!("Status: {}", msg);
                process::exit(0);
            }
        }
    } else if input == "2" {
        let UserName: String = get_input(" Username: ");
        let PassWord: String = get_input(" Password: ");
        let License: String = get_input(" License: ");

        match keyauthapp.register(UserName, PassWord, License, None) {
            Ok(_) => {}
            Err(msg) => {
                println!("Status: {}", msg);
                process::exit(0);
            }
        }
    } else if input == "3" {
        let UserName: String = get_input(" Username: ");
        let License: String = get_input(" License: ");

        match keyauthapp.upgrade(UserName, License) {
            Ok(_) => {}
            Err(msg) => {
                println!("Status: {}", msg);
                process::exit(0);
            }
        }
    } else if input == "4" {
        let License: String = get_input(" License: ");

        match keyauthapp.license(License, None) {
            Ok(_) => {}
            Err(msg) => {
                println!("Status: {}", msg);
                process::exit(0);
            }
        }
    } else {
        println!(" Wrong Choice!");
        process::exit(0);
    }

    keyauthapp.check();
    keyauthapp.checkBlack();
    println!(
        "
-Logged in!

 Username: {}
 IP address: {}
 Hardware-Id: {}
 Created at: {}
 Last Login: {}
 Subscription: {}

 Session Validated? {}
 BlackListed? {}

",
        keyauthapp.username.to_string(),
        keyauthapp.ip.to_string(),
        keyauthapp.hwid.to_string(),
        keyauthapp.createDate.to_string(),
        keyauthapp.LastLogin.to_string(),
        keyauthapp.subscription.to_string(),
        keyauthapp.message.to_string(),
        keyauthapp.blackListed.to_string()
    );

    println!(" Closing in 10 seconds...");
}

mod simple_user_input {
    use std::io;
    pub fn get_input(prompt: &str) -> String {
        println!("{}", prompt);
        let mut input = String::new();
        match io::stdin().read_line(&mut input) {
            Ok(_goes_into_input_above) => {}
            Err(_no_updates_is_fine) => {}
        }
        input.trim().to_string()
    }
}

/*
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
*/
