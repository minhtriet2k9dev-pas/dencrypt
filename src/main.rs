use std::env;
use std::fs;
use std::io;
use std::io::{stdout, Write};
use std::path;
use std::process::exit;
use std::result;
use std::thread;
use walkdir::WalkDir;

fn dencrypt_file(path: &str, key: &str) -> result::Result<(), io::Error> {
    assert!(key != "");
    let buffer = path::PathBuf::from(path);
    println!("Reading file \"{}\" ... ", path);
    let pure_data = fs::read(&buffer).expect(format!("Failed to read file \"{}\"", path).as_str());
    println!(
        "[File: \"{}\"]: Total size (bytes): {}",
        path,
        pure_data.len()
    );
    println!("[File: \"{}\"]: Executing process ... ", path);
    let endencrypt_data: Vec<u8> = pure_data
        .iter()
        .enumerate()
        .map(move |(i, val)| {
            return val ^ key.chars().nth(i % key.len()).unwrap() as u8;
        })
        .collect();
    println!("[File: \"{}\"]: Process finished !", path);
    println!("Writting file \"{}\" ... ", path);
    let ret = fs::write(buffer, endencrypt_data);
    println!("[File: \"{}\"]: Command complete successfully !", path);
    ret
}

#[derive(Debug, Clone)]
struct DencryptData {
    path: String,
    is_recursive: bool,
    key: String,
    is_multi_threads: bool,
}

impl DencryptData {
    fn new(path: String, is_recursive: bool, key: String, is_multi_threads: bool) -> Self {
        Self {
            path,
            is_recursive,
            key,
            is_multi_threads,
        }
    }

    fn std_ok(&self) -> bool {
        self.path != String::from("") && self.key != String::from("")
    }

    fn handle_args_error(&self) {
        if self.path == "".to_string() {
            println!("Missing specific path");
            println!("Add option \"--pathh=<path>\"");
            exit(1);
        }
        if self.key == "".to_string() {
            println!("Missing specific key");
            println!("Add option \"--key=<key>\"");
            exit(1);
        }
        let md = fs::metadata(self.path.as_str()).unwrap();
        if md.is_dir() && !self.is_recursive {
            println!("The given path is a directory, add option \"--rec\"");
            exit(1);
        } else if md.is_file() && self.is_recursive {
            println!("The given path is a file, remove option \"--rec\"");
            exit(1);
        }

        if self.is_multi_threads {
            println!("Multi threads mode enable");
        }
        if self.is_recursive {
            println!("Target directory: \"{}\"", self.path);
        }
    }

    fn check_rec(&self) {
        if !self.is_recursive {
            return;
        }

        let mut threads = Vec::new();
        for entry in WalkDir::new(self.path.as_str())
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.path().display().to_string() == self.path {
                continue;
            }
            if !self.is_multi_threads {
                let _ = dencrypt_file(
                    entry.path().display().to_string().as_str(),
                    hash_key(self, 3).as_str(),
                );
            } else {
                let data = self.clone();
                let md = fs::metadata(entry.path().display().to_string().as_str()).unwrap();
                if md.is_file() {
                    let tmp_entry = entry.clone();
                    let thread = thread::spawn(move || {
                        let _ = dencrypt_file(
                            tmp_entry.path().display().to_string().as_str(),
                            hash_key(&data, 3).as_str(),
                        );
                    });
                    threads.push(thread);
                } else {
                    DencryptData::new(
                        entry.path().display().to_string(),
                        self.is_recursive,
                        self.key.clone(),
                        self.is_multi_threads,
                    )
                    .check_rec()
                }
            }
        }
        if self.is_multi_threads {
            for thread in threads {
                thread.join().unwrap();
            }
        }
    }
}

fn analys_args(args: Vec<String>) -> DencryptData {
    let mut path = String::from("");
    let mut is_recursive = false;
    let mut key = String::from("");
    let mut is_multi_threads = false;

    for i in 1..args.len() {
        let arg = args.get(i).unwrap().as_str();
        if arg.len() >= 6 {
            if &arg[..6] == "--key=" {
                key = String::from(&arg[6..]);
            } else if arg.len() >= 7 {
                if &arg[..7] == "--path=" {
                    path = String::from(&arg[7..]);
                } else if arg == "--multi-threads" {
                    is_multi_threads = true;
                }
            }
        } else if arg == "--rec" {
            is_recursive = true;
        } else {
            println!("Warning: unknow option \"{} \"", arg);
        }
    }

    DencryptData::new(path, is_recursive, key, is_multi_threads)
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
    let dencrypt_data: DencryptData = analys_args(args);
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
