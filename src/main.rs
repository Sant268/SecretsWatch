use git2::{ObjectType, OdbObject, Repository};
use once_cell::sync::Lazy;
use regex::bytes::RegexSet;
use std::ffi::OsString;
use clap::{arg, command, value_parser, ArgAction, Command, Error, ErrorKind};
use clap::builder::ValueParser;
use regex::Regex;

const INFO: &str = "\x1b[34m[INFO]\x1b[0m";
const CRITICAL: &str = "\x1b[31m[CRITICAL]\x1b[0m";
fn main() {
    include_str!("../Cargo.toml");
    let matches = command!()
        .arg(
            arg!(-m --mode <MODE>)
                .help("What type of repository to scan")
                .required(true)
                .value_parser(["local","remote"])
        )
        .arg(
            arg!(-r --repo <REPO>)
                .help("Set the Github URL/Directory for the repository to scan")
                .required(false)
                .value_parser(ValueParser::os_string())
                .default_value(".")
        )
        .get_matches();
    let mode = matches.get_one::<String>("mode").unwrap();
    let mut repo: Repository;
    if mode == "local" {
        let mut repo_root= matches.value_of_os("repo").unwrap();
        repo = Repository::open(repo_root).expect("Couldn't open repository");
    }
    else {
        let url = matches.value_of_os("repo").expect("No remote url");
        println!("{}",url.to_str().unwrap());
        let re =  Regex::new(r"https?://(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)").unwrap();
        //https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)
        let urlmod :&str = url.to_str().unwrap();
        if re.is_match(urlmod) {
            repo = match Repository::clone(urlmod, "./temp/") {
                Ok(repo) => repo,
                Err(e) => panic!("failed to clone: {}", e),
            };
        }
        else {
            Error::raw(ErrorKind::InvalidValue, "Invalid GitHub URL\n").exit();
        }
    }
    println!(
        "{} PATH DETECTED: {} REPO STATE={:?}",
        INFO,
        repo.path().display(),
        repo.state()
    );
}