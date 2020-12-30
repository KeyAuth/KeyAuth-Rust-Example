use base16::encode_lower;
use crypto::{digest::Digest, sha2::Sha256};
use hex::decode;
use machine_uuid;
use reqwest::blocking::Client;
use serde::Deserialize;
use serde_json;
use uuid::Uuid;

use aes::Aes256;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};

const BASE_URL: &str = "https://keyauth.com/api/v2/";

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

pub struct KeyauthApi {
    name: String,
    owner_id: String,
    secret: String,
    key: Option<String>,
    init_iv: String,
}

#[derive(Deserialize, Debug)]
pub struct Key {
    key: String,
    expiry: String,
    level: u32,
}

impl KeyauthApi {
    pub fn new(name: String, owner_id: String, secret: String) -> Self {
        Self {
            name: name,
            owner_id: owner_id,
            secret: secret,
            key: None,
            init_iv: String::new(),
        }
    }

    pub fn init(&mut self) -> Result<(), String> {
        let session_iv = Uuid::new_v4().to_simple().to_string()[..8].to_string();
        let mut hasher = Sha256::new();
        hasher.input(session_iv.as_bytes());
        let init_iv: String = hasher.result_str();
        self.init_iv = init_iv;
        let data = format!(
            "type={}&name={}&ownerid={}&init_iv={}",
            encode_lower(b"init"),
            encode_lower(self.name.as_bytes()),
            encode_lower(self.owner_id.as_bytes()),
            &self.init_iv
        );
        

        let req = Self::make_req(data);

        let response = Encryption::decrypt(req.text().unwrap(), &self.secret, &self.init_iv);

        let json_rep: serde_json::Value = serde_json::from_str(&response).unwrap();
        if json_rep["success"].as_bool().unwrap() {
            Ok(())
        } else {
            Err(json_rep["message"].as_str().unwrap().to_string())
        }
    }

    pub fn login(&mut self, key: String, hwid: Option<String>) -> Result<Key, String> {
        let hwid = match hwid {
            Some(hwid) => hwid,
            None => Self::get_hwid(),
        };
        if self.init_iv == String::new() {
            return Err("NotInitalized".to_string());
        }

        let data = format!(
            "type={}&key={}&hwid={}&name={}&ownerid={}&init_iv={}",
            encode_lower(b"login"),
            Encryption::encrypt(&key, &self.secret, &self.init_iv),
            Encryption::encrypt(&hwid, &self.secret, &self.init_iv),
            encode_lower(self.name.as_bytes()),
            encode_lower(self.owner_id.as_bytes()),
            &self.init_iv
        );

        let req = Self::make_req(data);

        let response = Encryption::decrypt(req.text().unwrap(), &self.secret, &self.init_iv);
        let json_rep: serde_json::Value = serde_json::from_str(&response).unwrap();
        if json_rep["success"].as_bool().unwrap() {
            self.key = Some(key);
            Ok(serde_json::from_value(json_rep["info"].clone()).unwrap())
        } else {
            Err(json_rep["message"].as_str().unwrap().to_string())
        }
    }

    pub fn log(&self, msg: String) -> Result<(), String> {
        if msg.len() > 128 {
            return Err("MaxLogSize128".to_string());
        }
        match self.key {
            Some(_) => {}
            None => return Err("NotLoggedIn".to_string()),
        };
        let key = self.key.clone().unwrap();
        let data = format!(
            "type={}&key={}&message={}&name={}&ownerid={}&init_iv={}",
            encode_lower(b"log"),
            Encryption::encrypt(&key, &self.secret, &self.init_iv),
            Encryption::encrypt(&msg, &self.secret, &self.init_iv),
            encode_lower(self.name.as_bytes()),
            encode_lower(self.owner_id.as_bytes()),
            &self.init_iv,
        );
        let resp = Self::make_req(data);
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(resp.status().as_str().to_string())
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
            "None".to_string()
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

    fn encrypt(message: &String, enc_key: &String, iv: &String) -> String {
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
