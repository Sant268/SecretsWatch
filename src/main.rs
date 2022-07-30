use git2::{ObjectType, OdbObject, Repository};
use once_cell::sync::Lazy;
use regex::bytes::RegexSet;
use std::ffi::OsString;
use clap::{arg, command, value_parser, ArgAction, Command, Error, ErrorKind};
use clap::builder::ValueParser;
use regex::Regex;
use chrono::{Utc};
const INFO: &str = "\x1b[34m[INFO]\x1b[0m";
const CRITICAL: &str = "\x1b[31m[CRITICAL]\x1b[0m";
fn main() {
    include_str!("../Cargo.toml"); //force rust to detect changes in toml
    let argmatches = command!()
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
    let mode = argmatches.get_one::<String>("mode").unwrap();
    let repo: Repository;
    if mode == "local" {
        let mut repo_root= argmatches.value_of_os("repo").unwrap();
        repo = Repository::open(repo_root).expect("Couldn't open repository");
    }
    else {
        let url = argmatches.value_of_os("repo").expect("No remote url");
        println!("{}",url.to_str().unwrap());
        let re =  Regex::new(r"https?://(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)").unwrap();
        //https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)
        let urlmod :&str = url.to_str().unwrap();
        if re.is_match(urlmod) {
            let path :&str = &("./temp/".to_owned()+&Utc::now().timestamp_millis().to_string());
            repo = match Repository::clone(urlmod, path) {
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
    let odb = repo.odb().unwrap();
    odb.foreach(|&oid| {
        let obj = odb.read(oid).unwrap();
        scan_object(&obj);
        true
    }).unwrap();
}
fn scan_object(obj: &OdbObject)  {
    if obj.kind() != ObjectType::Blob {
        return;
    }
    if let Some(secrets_found) = find_secrets(obj.data()) {
        for bad in secrets_found {
            println!(
                "{} :: {} CONTAINS A SECRET OF TYPE :: `{}`",
                CRITICAL,
                obj.id(),
                bad
            );
        }
    }
}
fn find_secrets(blob: &[u8]) -> Option<Vec<&'static str>> {
    const RULES: &[(&str, &str)] = &[
        ("Slack Token", "(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})"),
        ("RSA private key", "-----BEGIN RSA PRIVATE KEY-----"),
        ("SSH (OPENSSH) private key", "-----BEGIN OPENSSH PRIVATE KEY-----"),
        ("SSH (DSA) private key", "-----BEGIN DSA PRIVATE KEY-----"),
        ("SSH (EC) private key", "-----BEGIN EC PRIVATE KEY-----"),
        ("PGP private key block", "-----BEGIN PGP PRIVATE KEY BLOCK-----"),
        ("Facebook Oauth", "[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].{0,30}['\"\\s][0-9a-f]{32}['\"\\s]"),
        ("Twitter Oauth", "[t|T][w|W][i|I][t|T][t|T][e|E][r|R].{0,30}['\"\\s][0-9a-zA-Z]{35,44}['\"\\s]"),
        ("GitHub", "[g|G][i|I][t|T][h|H][u|U][b|B].{0,30}['\"\\s][0-9a-zA-Z]{35,40}['\"\\s]"),
        ("Google Oauth", "(\"client_secret\":\"[a-zA-Z0-9-_]{24}\")"),
        ("AWS Access Key ID", "AKIA[0-9A-Z]{16}"),
        ("AWS Secret Key", "[0-9a-zA-Z/+]{40}"),
        ("GCP OAuth 2.0", "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"),
        ("GCP API Key", "[A-Za-z0-9_]{21}--[A-Za-z0-9_]{8}"),
        ("Heroku OAuth", "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"),
        ("Slack Webhooks", "T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}"),
        ("Heroku API Key", "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"),
        ("Generic Secret", "[s|S][e|E][c|C][r|R][e|E][t|T].{0,30}['\"\\s][0-9a-zA-Z]{32,45}['\"\\s]"),
        ("Generic API Key", "[a|A][p|P][i|I][_]?[k|K][e|E][y|Y].{0,30}['\"\\s][0-9a-zA-Z]{32,45}['\"\\s]"),
        ("Slack Webhook", "https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}"),
        ("Google (GCP) Service-account", "\"type\": \"service_account\""),
        ("Twilio API Key", "SK[a-z0-9]{32}"),
        ("Password in URL", "[a-zA-Z]{3,10}://[^/\\s:@]{3,20}:[^/\\s:@]{3,20}@.{1,100}[\"'\\s]"),
    ];
    static REGEX_SET: Lazy<RegexSet> = Lazy::new(|| {
        RegexSet::new(RULES.iter().map(|&(_, regex)| regex)).expect("All regexes should be valid")
    });

    let matches = REGEX_SET.matches(blob);
    if !matches.matched_any() {
        return None;
    }
    Some(matches.iter().map(|i| RULES[i].0).collect())
}