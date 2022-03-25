use std::env;
use std::fs;
use std::io;
use std::io::{stdout, Write};
use std::path;
use std::process::exit;
use std::result;
use walkdir::WalkDir;

fn dencrypt_file(path: &str, key: &str) -> result::Result<(), io::Error> {
    assert!(key != "");
    println!("Working on file: \"{}\"", path);
    let buffer = path::PathBuf::from(path);
    print!("Reading file ... ");
    let pure_data = fs::read(&buffer).expect("Failed to read file");
    println!("[Done]");
    println!("Total size (bytes): {}", pure_data.len());
    let endencrypt_data: Vec<u8> = pure_data
        .iter()
        .enumerate()
        .map(|(i, val)| {
            print!("\rProcessing (bytes): {}", i + 1);
            return val ^ key.chars().nth(i % key.len()).unwrap() as u8;
        })
        .collect();
    println!();
    println!("Process finished !");
    print!("Writting file ... ");
    let ret = fs::write(buffer, endencrypt_data);
    println!("[Done]");
    println!("Command complete successfully !");
    ret
}

#[derive(Debug)]
struct DencryptData {
    path: String,
    is_recursive: bool,
    key: String,
}

impl DencryptData {
    fn new(path: String, is_recursive: bool, key: String) -> Self {
        Self {
            path,
            is_recursive,
            key,
        }
    }

    fn std_ok(&self) -> bool {
        self.path != String::from("") && self.key != String::from("")
    }

    fn handle_args_error(&self) {
        if self.path == "".to_string() {
            exit(1);
        }
        if self.key == "".to_string() {
            exit(1);
        }
    }

    fn check_rec(&self) {
        if !self.is_recursive {
            return;
        }
        for entry in WalkDir::new("foo").into_iter().filter_map(|e| e.ok()) {
            let _ = dencrypt_file(
                entry.path().display().to_string().as_str(),
                hash_key(self, 3).as_str(),
            );
        }
    }
}

fn analys_args(args: Vec<String>) -> DencryptData {
    let mut path = String::from("");
    let mut is_recursive = false;
    let mut key = String::from("");
    for i in 1..args.len() {
        let arg = args.get(i).unwrap().as_str();
        if &arg[..6] == "--key=" {
            key = String::from(&arg[6..]);
        } else if &arg[..7] == "--path=" {
            path = String::from(&arg[7..]);
        } else if arg == "rec" {
            is_recursive = true;
        } else {
            println!("Warning: unknow option \"{} \"", arg);
        }
    }

    DencryptData::new(path, is_recursive, key)
}

fn hash_key(dencrypt_data: &DencryptData, time: u8) -> String {
    let mut ret = format!("{:x}", md5::compute(dencrypt_data.key.as_str()));
    for _ in 1..time {
        ret = format!("{:x}", md5::compute(dencrypt_data.key.as_str()));
    }
    ret
}

fn main() {
    let _ = stdout().flush().unwrap();
    let args: Vec<String> = env::args().collect();
    let dencrypt_data = analys_args(args);
    println!("{:?}", dencrypt_data);
    dencrypt_data.handle_args_error();

    if dencrypt_data.std_ok() && !dencrypt_data.is_recursive {
        let _ = dencrypt_file(
            dencrypt_data.path.as_str(),
            hash_key(&dencrypt_data, 3).as_str(),
        );
    }

    dencrypt_data.check_rec();
}
