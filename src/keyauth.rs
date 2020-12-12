use base16::encode_lower;
use crypto::{digest::Digest, sha2::Sha256};
use hex::decode;
use reqwest::blocking::Client;
use uuid::Uuid;
use machine_uuid;

use aes::Aes256;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};

const BASE_URL: &str = "https://keyauth.com/api/";

type Aes256Cbc = Cbc<Aes256, Pkcs7>;
pub struct KeyauthApi {
    name: String,
    owner_id: String,
    secret: String,
}

impl KeyauthApi {
    pub fn new(name: String, owner_id: String, secret: String) -> Self {
        Self {
            name: name,
            owner_id: owner_id,
            secret: secret,
        }
    }

    pub fn init(&self) -> Result<(), String> {
        let session_iv = Uuid::new_v4().to_simple().to_string()[..8].to_string();
        let mut hasher = Sha256::new();
        hasher.input(session_iv.as_bytes());
        let init_iv: String = hasher.result_str();
        let data = format!(
            "type={}&name={}&ownerid={}&init_iv={}",
            encode_lower(b"init"),
            encode_lower(self.name.as_bytes()),
            encode_lower(self.owner_id.as_bytes()),
            &init_iv
        );

        let req = Self::make_req(data);

        let response = Encryption::decrypt(req.text().unwrap(), &self.secret, &init_iv);

        if response == "KeyAuth_Disabled".to_string() {
            Err("The program key you tried to use doesn't exist".to_string())
        } else if response == "KeyAuth_Initialized".to_string() {
            Ok(())
        } else {
            Err("The program key you tried to use doesn't exist".to_string())
        }
    }

    pub fn login(&self, key: String, hwid: Option<String>) -> Result<(), String> {
        let hwid = match hwid {
            Some(hwid) => hwid,
            None => Self::get_hwid(),
        };
        let session_iv = Uuid::new_v4().to_simple().to_string()[..8].to_string();
        let mut hasher = Sha256::new();
        hasher.input(session_iv.as_bytes());
        let init_iv: String = hasher.result_str();

        let data = format!(
            "type={}&key={}&hwid={}&name={}&ownerid={}&init_iv={}",
            encode_lower(b"login"),
            Encryption::encrypt(key, &self.secret, &init_iv),
            Encryption::encrypt(hwid, &self.secret, &init_iv),
            encode_lower(self.name.as_bytes()),
            encode_lower(self.owner_id.as_bytes()),
            &init_iv
        );

        let req = Self::make_req(data);

        let response = Encryption::decrypt(req.text().unwrap(), &self.secret, &init_iv);
        if response == "KeyAuth_Valid".to_string() {
            Ok(())
        } else if response == "KeyAuth_Invalid".to_string() {
            Err("Key not found".to_string())
        } else if response == "KeyAuth_InvalidHWID".to_string() {
            Err("This computer doesn't match the computer the key is locked to. If you reset your computer, contact the application owner".to_string())
        } else if response == "KeyAuth_Expired".to_string() {
            Err("This key is expired".to_string())
        } else {
            Err("Application Failed To Connect. Try again or contact application owner".to_string())
        }
    }

    fn make_req(data: String) -> reqwest::blocking::Response {
        let client = Client::new();
        client
            .post(BASE_URL)
            .body(data)
            .header("User-Agent", "KeyAuth")
            .header("content-type", "application/x-www-form-urlencoded")
            .send()
            .unwrap()
    }

    fn get_hwid() -> String {
        if cfg!(windows) {
            machine_uuid::get()
        } else {
            "None".into()
        }
    }
}

struct Encryption;
impl Encryption {
    fn encrypt_string(plain_text: &[u8], key: &[u8], iv: &[u8]) -> String {
        let mut buffer = [0u8; 128];
        let pos = plain_text.len();
        buffer[..pos].copy_from_slice(plain_text);
        let cipher = Aes256Cbc::new_var(&key, &iv).unwrap();
        let ciphertext = cipher.encrypt(&mut buffer, pos).unwrap();
        encode_lower(ciphertext)
    }

    fn decrypt_string(cipher_text: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
        let cipher_text = decode(cipher_text).unwrap();
        let cipher = Aes256Cbc::new_var(&key, &iv).unwrap();
        let mut buf = cipher_text;
        cipher.decrypt_vec(&mut buf).unwrap()
    }

    fn encrypt(message: String, enc_key: &String, iv: &String) -> String {
        let mut hasher = Sha256::new();
        hasher.input(enc_key.as_bytes());
        let _key: String = hasher.result_str()[..32].to_owned();

        let mut hasher = Sha256::new();
        hasher.input(iv.as_bytes());
        let _iv: String = hasher.result_str()[..16].to_owned();
        Encryption::encrypt_string(message.as_bytes(), _key.as_bytes(), _iv.as_bytes())
    }

    fn decrypt(message: String, enc_key: &String, iv: &String) -> String {
        let mut hasher = Sha256::new();
        hasher.input(enc_key.as_bytes());
        let _key: String = hasher.result_str()[..32].to_owned();

        let mut hasher = Sha256::new();
        hasher.input(iv.as_bytes());
        let _iv: String = hasher.result_str()[..16].to_owned();
        String::from_utf8(Encryption::decrypt_string(
            message.as_bytes(),
            _key.as_bytes(),
            _iv.as_bytes(),
        ))
        .unwrap()
    }
}
