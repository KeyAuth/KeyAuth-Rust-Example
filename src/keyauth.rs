use std::collections::HashMap;

use base16::{decode, encode_lower};
use crypto::{digest::Digest, sha2::Sha256};
use reqwest::blocking::Client;
use uuid::Uuid;

use aes::Aes256;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};

const BASE_URL: &str = "https://keyauth.com/api/1.0/";

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

pub struct KeyauthApi {
    name: String,
    owner_id: String,
    secret: String,
    version: String,
    enckey: String,
    session_id: String,
}

impl KeyauthApi {
    pub fn new(name: &str, owner_id: &str, secret: &str, version: &str) -> Self {
        Self {
            name: name.to_string(),
            owner_id: owner_id.to_string(),
            secret: secret.to_string(),
            version: version.to_string(),
            enckey: String::new(),
            session_id: String::new(),
        }
    }

    pub fn init(&mut self) -> Result<(), String> {
        let init_iv = Self::gen_init_iv();
        self.enckey = Self::gen_init_iv();

        let mut data = HashMap::new();
        data.insert("type", encode_lower(b"init"));
        data.insert(
            "ver",
            Encryption::encrypt(&self.version, &self.secret, &init_iv),
        );
        data.insert(
            "enckey",
            Encryption::encrypt(&self.enckey, &self.secret, &init_iv),
        );
        data.insert("name", encode_lower(self.name.as_bytes()));
        data.insert("ownerid", encode_lower(self.owner_id.as_bytes()));
        data.insert("init_iv", init_iv.to_string());

        let req = Self::make_req(data);
        let response = req.text().unwrap();

        if response == "KeyAuth_Invalid" {
            return Err("The application doesn't exist".to_string());
        }

        let response = Encryption::decrypt(response, &self.secret, &init_iv);

        let json_rep: serde_json::Value = serde_json::from_str(&response).unwrap();

        if json_rep["success"].as_bool().unwrap() {
            self.session_id = json_rep["sessionid"].as_str().unwrap().to_string();
            Ok(())
        } else {
            if json_rep["message"].as_str().unwrap() == "invalidver" {
                let download_url = json_rep["download"].as_str().unwrap();
                if !download_url.is_empty() {
                    webbrowser::open(download_url).unwrap();
                }
            }
            Err(json_rep["message"].as_str().unwrap().to_string())
        }
    }

    pub fn register(
        &mut self,
        username: String,
        password: String,
        license: String,
        hwid: Option<String>,
    ) -> Result<(), String> {
        let init_iv = Self::gen_init_iv();

        let hwid = match hwid {
            Some(hwid) => hwid,
            None => Self::get_hwid(),
        };

        let mut data = HashMap::new();
        data.insert("type", encode_lower(b"register"));
        data.insert(
            "username",
            Encryption::encrypt(&username, &self.enckey, &init_iv),
        );
        data.insert(
            "pass",
            Encryption::encrypt(&password, &self.enckey, &init_iv),
        );
        data.insert("key", Encryption::encrypt(&license, &self.enckey, &init_iv));
        data.insert("hwid", Encryption::encrypt(&hwid, &self.enckey, &init_iv));
        data.insert("sessionid", encode_lower(self.session_id.as_bytes()));
        data.insert("name", encode_lower(self.name.as_bytes()));
        data.insert("ownerid", encode_lower(self.owner_id.as_bytes()));
        data.insert("init_iv", init_iv.to_string());

        let req = Self::make_req(data);
        let response = req.text().unwrap();

        let response = Encryption::decrypt(response, &self.enckey, &init_iv);

        let json_rep: serde_json::Value = serde_json::from_str(&response).unwrap();

        if json_rep["success"].as_bool().unwrap() {
            Ok(())
        } else {
            Err(json_rep["message"].as_str().unwrap().to_string())
        }
    }

    pub fn upgrade(&mut self, username: String, license: String) -> Result<(), String> {
        let init_iv = Self::gen_init_iv();

        let mut data = HashMap::new();
        data.insert("type", encode_lower(b"upgrade"));
        data.insert(
            "username",
            Encryption::encrypt(&username, &self.enckey, &init_iv),
        );
        data.insert("key", Encryption::encrypt(&license, &self.enckey, &init_iv));
        data.insert("sessionid", encode_lower(self.session_id.as_bytes()));
        data.insert("name", encode_lower(self.name.as_bytes()));
        data.insert("ownerid", encode_lower(self.owner_id.as_bytes()));
        data.insert("init_iv", init_iv.to_string());

        let req = Self::make_req(data);
        let response = req.text().unwrap();

        let response = Encryption::decrypt(response, &self.enckey, &init_iv);

        let json_rep: serde_json::Value = serde_json::from_str(&response).unwrap();

        if json_rep["success"].as_bool().unwrap() {
            Ok(())
        } else {
            Err(json_rep["message"].as_str().unwrap().to_string())
        }
    }

    pub fn login(
        &mut self,
        username: String,
        password: String,
        hwid: Option<String>,
    ) -> Result<(), String> {
        let init_iv = Self::gen_init_iv();

        let hwid = match hwid {
            Some(hwid) => hwid,
            None => Self::get_hwid(),
        };

        let mut data = HashMap::new();
        data.insert("type", encode_lower(b"login"));
        data.insert(
            "username",
            Encryption::encrypt(&username, &self.enckey, &init_iv),
        );
        data.insert(
            "pass",
            Encryption::encrypt(&password, &self.enckey, &init_iv),
        );
        data.insert("hwid", Encryption::encrypt(&hwid, &self.enckey, &init_iv));
        data.insert("sessionid", encode_lower(self.session_id.as_bytes()));
        data.insert("name", encode_lower(self.name.as_bytes()));
        data.insert("ownerid", encode_lower(self.owner_id.as_bytes()));
        data.insert("init_iv", init_iv.to_string());

        let req = Self::make_req(data);
        let response = req.text().unwrap();

        let response = Encryption::decrypt(response, &self.enckey, &init_iv);

        let json_rep: serde_json::Value = serde_json::from_str(&response).unwrap();

        if json_rep["success"].as_bool().unwrap() {
            Ok(())
        } else {
            Err(json_rep["message"].as_str().unwrap().to_string())
        }
    }

    pub fn license(
        &mut self,
        license: String,
        hwid: Option<String>,
    ) -> Result<serde_json::Value, String> {
        let init_iv = Self::gen_init_iv();

        let hwid = match hwid {
            Some(hwid) => hwid,
            None => Self::get_hwid(),
        };

        let mut data = HashMap::new();
        data.insert("type", encode_lower(b"license"));
        data.insert("key", Encryption::encrypt(&license, &self.enckey, &init_iv));
        data.insert("hwid", Encryption::encrypt(&hwid, &self.enckey, &init_iv));
        data.insert("sessionid", encode_lower(self.session_id.as_bytes()));
        data.insert("name", encode_lower(self.name.as_bytes()));
        data.insert("ownerid", encode_lower(self.owner_id.as_bytes()));
        data.insert("init_iv", init_iv.to_string());

        let req = Self::make_req(data);
        let response = req.text().unwrap();

        let response = Encryption::decrypt(response, &self.enckey, &init_iv);

        let json_rep: serde_json::Value = serde_json::from_str(&response).unwrap();

        if json_rep["success"].as_bool().unwrap() {
            Ok(json_rep["info"].clone())
        } else {
            Err(json_rep["message"].as_str().unwrap().to_string())
        }
    }

    pub fn var(&mut self, varid: String) -> Result<String, String> {
        let init_iv = Self::gen_init_iv();

        let mut data = HashMap::new();
        data.insert("type", encode_lower(b"var"));
        data.insert("varid", Encryption::encrypt(&varid, &self.enckey, &init_iv));
        data.insert("sessionid", encode_lower(self.session_id.as_bytes()));
        data.insert("name", encode_lower(self.name.as_bytes()));
        data.insert("ownerid", encode_lower(self.owner_id.as_bytes()));
        data.insert("init_iv", init_iv.to_string());

        let req = Self::make_req(data);
        let response = req.text().unwrap();

        let response = Encryption::decrypt(response, &self.enckey, &init_iv);

        let json_rep: serde_json::Value = serde_json::from_str(&response).unwrap();

        if json_rep["success"].as_bool().unwrap() {
            Ok(json_rep["message"].as_str().unwrap().to_string())
        } else {
            Err(json_rep["message"].as_str().unwrap().to_string())
        }
    }

    pub fn file(&mut self, fileid: String) -> Result<Vec<u8>, String> {
        let init_iv = Self::gen_init_iv();

        let mut data = HashMap::new();
        data.insert("type", encode_lower(b"file"));
        data.insert(
            "fileid",
            Encryption::encrypt(&fileid, &self.enckey, &init_iv),
        );
        data.insert("sessionid", encode_lower(self.session_id.as_bytes()));
        data.insert("name", encode_lower(self.name.as_bytes()));
        data.insert("ownerid", encode_lower(self.owner_id.as_bytes()));
        data.insert("init_iv", init_iv.to_string());

        let req = Self::make_req(data);
        let response = req.text().unwrap();

        let response = Encryption::decrypt(response, &self.enckey, &init_iv);

        let json_rep: serde_json::Value = serde_json::from_str(&response).unwrap();

        if json_rep["success"].as_bool().unwrap() {
            Ok(decode(json_rep["contents"].as_str().unwrap()).unwrap())
        } else {
            Err(json_rep["message"].as_str().unwrap().to_string())
        }
    }

    pub fn webhook(&mut self, webid: String, params: String) -> Result<String, String> {
        let init_iv = Self::gen_init_iv();

        let mut data = HashMap::new();
        data.insert("type", encode_lower(b"webhook"));
        data.insert("webid", Encryption::encrypt(&webid, &self.enckey, &init_iv));
        data.insert(
            "params",
            Encryption::encrypt(&params, &self.enckey, &init_iv),
        );
        data.insert("sessionid", encode_lower(self.session_id.as_bytes()));
        data.insert("name", encode_lower(self.name.as_bytes()));
        data.insert("ownerid", encode_lower(self.owner_id.as_bytes()));
        data.insert("init_iv", init_iv.to_string());

        let req = Self::make_req(data);
        let response = req.text().unwrap();

        let response = Encryption::decrypt(response, &self.enckey, &init_iv);

        let json_rep: serde_json::Value = serde_json::from_str(&response).unwrap();

        if json_rep["success"].as_bool().unwrap() {
            Ok(json_rep["message"].as_str().unwrap().to_string())
        } else {
            Err(json_rep["message"].as_str().unwrap().to_string())
        }
    }

    pub fn log(&mut self, message: String) {
        let init_iv = Self::gen_init_iv();

        let mut data = HashMap::new();
        data.insert("type", encode_lower(b"log"));
        data.insert(
            "pcuser",
            Encryption::encrypt(&std::env::var("username").unwrap(), &self.enckey, &init_iv),
        );
        data.insert(
            "message",
            Encryption::encrypt(&message, &self.enckey, &init_iv),
        );
        data.insert("sessionid", encode_lower(self.session_id.as_bytes()));
        data.insert("name", encode_lower(self.name.as_bytes()));
        data.insert("ownerid", encode_lower(self.owner_id.as_bytes()));
        data.insert("init_iv", init_iv);

        Self::make_req(data);
    }

    fn make_req(data: HashMap<&str, String>) -> reqwest::blocking::Response {
        let client = Client::new();
        let mut data_str = String::new();
        for d in data {
            data_str.push_str(&format!("{}={}&", d.0, d.1))
        }
        data_str = data_str.strip_suffix('&').unwrap().to_string();
        println!("data_str: {}", data_str);
        client
            .post(BASE_URL)
            .body(data_str)
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

    fn gen_init_iv() -> String {
        let session_iv = Uuid::new_v4().to_simple().to_string()[..8].to_string();
        let mut hasher = Sha256::new();
        hasher.input(session_iv.as_bytes());
        hasher.result_str()
    }
}

struct Encryption;
impl Encryption {
    fn encrypt_string(plain_text: &[u8], key: &[u8], iv: &[u8]) -> String {
        let mut buffer = [0u8; 128];
        let pos = plain_text.len();
        buffer[..pos].copy_from_slice(plain_text);
        let cipher = Aes256Cbc::new_from_slices(&key, &iv).unwrap();
        let ciphertext = cipher.encrypt(&mut buffer, pos).unwrap();
        encode_lower(ciphertext)
    }

    fn decrypt_string(cipher_text: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
        let cipher_text = decode(cipher_text).unwrap();
        let cipher = Aes256Cbc::new_from_slices(&key, &iv).unwrap();
        cipher.decrypt_vec(&cipher_text).unwrap()
    }

    fn encrypt(message: &str, enc_key: &str, iv: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.input(enc_key.as_bytes());
        let key: String = hasher.result_str()[..32].to_owned();

        let mut hasher = Sha256::new();
        hasher.input(iv.as_bytes());
        let iv: String = hasher.result_str()[..16].to_owned();
        Encryption::encrypt_string(message.as_bytes(), key.as_bytes(), iv.as_bytes())
    }

    fn decrypt(message: String, enc_key: &str, iv: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.input(enc_key.as_bytes());
        let key: String = hasher.result_str()[..32].to_owned();

        let mut hasher = Sha256::new();
        hasher.input(iv.as_bytes());
        let iv: String = hasher.result_str()[..16].to_owned();
        String::from_utf8(Encryption::decrypt_string(
            message.as_bytes(),
            key.as_bytes(),
            iv.as_bytes(),
        ))
        .unwrap()
    }
}
