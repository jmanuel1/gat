use clap::{App, Arg, SubCommand};
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use ini::Ini;
use sha1;
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, HashSet};
use std::convert::{TryFrom, TryInto};
use std::fmt::Write;
use std::fs;
use std::io;
use std::io::{Read, Write as IOWrite};
use std::path::Path;
use std::str;

pub fn main() {
    let matches = App::new("My Test Program")
        .about("The stupid content tracker")
        .subcommand(SubCommand::with_name("add"))
        .subcommand(
            SubCommand::with_name("cat-file")
                .about("Provide content of repository objects")
                .arg(
                    Arg::with_name("type")
                        .value_name("type")
                        .required(true)
                        .help("Specify the type")
                        .index(1)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("object")
                        .value_name("object")
                        .required(true)
                        .help("The object to display")
                        .index(2)
                        .takes_value(true),
                ),
        )
        .subcommand(SubCommand::with_name("checkout"))
        .subcommand(SubCommand::with_name("commit"))
        .subcommand(
            SubCommand::with_name("hash-object")
                .about("Compute object ID and optionally creates a blob from a file")
                .arg(
                    Arg::with_name("type")
                        .short("t")
                        .takes_value(true)
                        .value_name("type")
                        .help("Specify the type"),
                )
                .arg(
                    Arg::with_name("write")
                        .short("w")
                        .takes_value(false)
                        .help("Actually write the object into the database"),
                )
                .arg(
                    Arg::with_name("path")
                        .value_name("path")
                        .required(true)
                        .help("Read object from <file>")
                        .takes_value(false),
                ),
        )
        .subcommand(
            SubCommand::with_name("init")
                .about("Initialize a new, empty repository")
                .arg(
                    Arg::with_name("path")
                        .value_name("directory")
                        .required(false)
                        .help("Where to create the repository.")
                        .index(1),
                ),
        )
        .subcommand(
            SubCommand::with_name("log")
                .about("Display history of a given commit.")
                .arg(
                    Arg::with_name("commit")
                        .value_name("commit")
                        .required(false)
                        .default_value("HEAD")
                        .help("Commit to start at."),
                ),
        )
        .subcommand(SubCommand::with_name("ls-tree"))
        .subcommand(SubCommand::with_name("merge"))
        .subcommand(SubCommand::with_name("rebase"))
        .subcommand(SubCommand::with_name("rev-parse"))
        .subcommand(SubCommand::with_name("rm"))
        .subcommand(SubCommand::with_name("show-ref"))
        .subcommand(SubCommand::with_name("tag"))
        .get_matches();

    if let Some(matches) = matches.subcommand_matches("init") {
        let directory = matches.value_of("path").unwrap_or(".");
        if let Err(err) = repo_create(&String::from(directory)) {
            println!("{}", err);
        }
    } else if let Some(matches) = matches.subcommand_matches("cat-file") {
        let object_type = matches.value_of("type").unwrap();
        if !["blob", "commit", "tag", "tree"].contains(&object_type) {
            panic!("Invalid type {}", object_type);
        }
        if let Err(err) = cmd_cat_file(matches.value_of("object").unwrap(), object_type) {
            println!("{}", err);
        }
    } else if let Some(matches) = matches.subcommand_matches("hash-object") {
        let write = matches.is_present("write");
        let path = matches.value_of("path").unwrap();
        let object_type = matches.value_of("type").unwrap_or("blob");
        if !["blob", "commit", "tag", "tree"].contains(&object_type) {
            panic!("Invalid type {}", object_type);
        }
        if let Err(err) = cmd_hash_object(write, path, object_type) {
            println!("{}", err);
        }
    } else if let Some(matches) = matches.subcommand_matches("log") {
        let commit = matches.value_of("commit").unwrap();
        if let Err(err) = cmd_log(commit) {
            println!("{}", err);
        }
    } else {
        todo!();
    }
}

struct GitRepository {
    worktree: String,
    gitdir: String,
    conf: Option<Ini>,
}

impl GitRepository {
    fn new(
        path: &str,
        force: bool, /* default is False in WYAG */
    ) -> Result<GitRepository, String> {
        let gitdir = Path::new(&path).join(".git");
        if !(force || gitdir.is_dir()) {
            return Err("Not a Git repository ".to_owned() + &path);
        }
        let gitdir = match gitdir.to_str() {
            None => panic!("path to git dir is not valid UTF-8"),
            Some(s) => s,
        };
        let cf = repo_file(
            &GitRepository {
                worktree: String::from(path),
                gitdir: gitdir.to_string(),
                conf: None,
            },
            &String::from("config"),
            false,
        );
        let mut conf = None;
        if let Ok(cf) = cf {
            if Path::new(&cf).exists() {
                conf = Some(Ini::load_from_file(cf).unwrap());
            }
        } else if !force {
            return Err("Configuration file missing".to_string());
        }
        if !force {
            let vers = conf
                .as_ref()
                .unwrap()
                .get_from(Some("core"), "repositoryformatversion")
                .unwrap()
                .parse::<i32>()
                .unwrap();
            if vers != 0 {
                return Err(format!("Unsupported repositoryformatversion {}", vers));
            }
        }
        return Ok(GitRepository {
            worktree: String::from(path),
            gitdir: gitdir.to_string(),
            conf: Some(conf.unwrap_or(Ini::new())),
        });
    }
}

fn repo_path(repo: &GitRepository, path: &str) -> String {
    return Path::new(&repo.gitdir)
        .join(path)
        .to_str()
        .unwrap()
        .to_string();
}

fn repo_file(
    repo: &GitRepository,
    path: &str,
    mkdir: bool, /* false by default in WYAG */
) -> Result<String, String> {
    return match Path::new(&path).parent() {
        None => Ok(repo_path(repo, path)),
        Some(dir) => {
            repo_dir(repo, &dir.to_str().unwrap().to_string(), mkdir)?;
            Ok(repo_path(repo, path))
        }
    };
}

fn repo_dir(repo: &GitRepository, path: &str, mkdir: bool) -> Result<String, String> {
    let full_path = repo_path(repo, path);
    let path = Path::new(&full_path);

    if path.exists() {
        if path.is_dir() {
            return Ok(path.to_str().unwrap().to_string());
        } else {
            return Err("Not a directory ".to_owned() + path.to_str().unwrap());
        }
    }

    if mkdir {
        match fs::create_dir_all(path) {
            Ok(_) => (),
            Err(err) => return Err(err.to_string()),
        };
        return Ok(path.to_str().unwrap().to_string());
    } else {
        let mut err = String::from(path.to_str().unwrap_or("Directory"));
        err.push_str(" does not exist");
        return Err(err);
    }
}

fn repo_create(path: &str) -> Result<GitRepository, String> {
    let repo = GitRepository::new(path, true)?;

    let worktree = Path::new(&repo.worktree);
    if worktree.exists() {
        if !worktree.is_dir() {
            return Err(format!("{} is not a directory!", path));
        }
        for _ in worktree.read_dir().expect("read_dir call failed") {
            return Err(format!("{} is not empty!", path));
        }
    } else {
        if let Err(err) = fs::create_dir_all(worktree) {
            return Err(err.to_string());
        }
    }

    repo_dir(&repo, &String::from("branches"), true)?;
    repo_dir(&repo, &String::from("objects"), true)?;
    repo_dir(&repo, &String::from("refs/tags"), true)?;
    repo_dir(&repo, &String::from("refs/heads"), true)?;

    if let Err(err) = fs::write(
        repo_file(&repo, &String::from("description"), false)?,
        "Unnamed repository; edit this file 'description' to name the repository.\n",
    ) {
        return Err(err.to_string());
    }

    if let Err(err) = fs::write(
        repo_file(&repo, &String::from("HEAD"), false)?,
        "ref: refs/heads/master\n",
    ) {
        return Err(err.to_string());
    }

    repo_default_config().write_to_file(repo_file(&repo, &String::from("config"), false)?);

    return Ok(repo);
}

fn repo_default_config() -> Ini {
    let mut ret = Ini::new();

    ret.set_to(
        Some(String::from("core")),
        String::from("repositoryformatversion"),
        String::from("0"),
    );
    ret.set_to(
        Some(String::from("core")),
        String::from("filemode"),
        String::from("false"),
    );
    ret.set_to(
        Some(String::from("core")),
        String::from("bare"),
        String::from("false"),
    );

    return ret;
}

fn repo_find(
    path: String,   /* "." by default in WYAG */
    required: bool, /* True by default in WYAG */
) -> Result<Option<GitRepository>, String> {
    let path = match fs::canonicalize(Path::new(&path)) {
        Ok(path) => path,
        Err(err) => return Err(err.to_string()),
    };

    if path.join(".git").is_dir() {
        return Ok(Some(GitRepository::new(path.to_str().unwrap(), false)?));
    }

    match path.parent() {
        None => {
            if required {
                return Err(String::from("No git directory."));
            } else {
                return Ok(None);
            }
        }
        Some(parent) => repo_find(String::from(parent.to_str().unwrap()), required),
    }
}

/* ---- */

enum GitObjectType {
    Commit,
    Tree,
    Tag,
    Blob,
}

struct GitObject<'a> {
    repo: Option<&'a GitRepository>,
    object_type: GitObjectType,
    blobdata: Vec<u8>,
    kvlm: BTreeMap<Vec<u8>, DctValue>,
}

impl<'b> GitObject<'b> {
    fn new<'a: 'b>(
        repo: Option<&'a GitRepository>,
        data: Option<Vec<u8>>,
        object_type: GitObjectType,
    ) -> Self {
        let mut object = Self {
            repo: repo,
            object_type: object_type,
            blobdata: vec![],
            kvlm: BTreeMap::new(),
        };
        match data {
            None => (),
            Some(data) => object.deserialize(data),
        };
        return object;
    }

    fn serialize(&self) -> Vec<u8> {
        return match self.object_type {
            GitObjectType::Blob => self.blobdata.clone(),
            GitObjectType::Commit => kvlm_serialize(&self.kvlm),
            _ => todo!(),
        };
    }

    fn deserialize<'a: 'b>(&mut self, data: Vec<u8>) {
        match self.object_type {
            GitObjectType::Blob => self.blobdata = data,
            GitObjectType::Commit => {
                self.kvlm = kvlm_parse(&data, None, None);
            }
            _ => todo!(),
        };
    }

    fn fmt(&self) -> &[u8] {
        return match self.object_type {
            GitObjectType::Commit => b"commit",
            GitObjectType::Tree => b"tree",
            GitObjectType::Tag => b"tag",
            GitObjectType::Blob => b"blob",
        };
    }
}

fn object_read<'a: 'b, 'b>(repo: &'a GitRepository, sha: &str) -> Result<GitObject<'b>, String> {
    let sha_path = Path::new("objects").join(&sha[0..2]).join(&sha[2..]);
    let path = repo_file(repo, sha_path.to_str().unwrap(), false)?;
    let path = Path::new(&path);
    let mut f = fs::File::open(&path).unwrap();
    let mut decoder = ZlibDecoder::new(&mut f);
    let mut raw = Vec::new();
    if let Err(err) = decoder.read_to_end(&mut raw) {
        return Err(err.to_string());
    }

    let x = raw.iter().position(|&char| char == b' ').unwrap();
    let fmt = &raw[0..x];
    let y = raw[x..].iter().position(|&char| char == b'\0').unwrap() + x;
    // x + 1 to skip the space
    let size = usize::from_str_radix(str::from_utf8(&raw[x + 1..y]).unwrap(), 10).unwrap();
    if size != raw.len() - y - 1 {
        return Err(format!("Malformed object {}: bad length", sha));
    }

    let fmt = str::from_utf8(fmt).unwrap();

    let c = if fmt == "commit" {
        GitObjectType::Commit
    } else if fmt == "tree" {
        GitObjectType::Tree
    } else if fmt == "tag" {
        GitObjectType::Tag
    } else if fmt == "blob" {
        GitObjectType::Blob
    } else {
        let mut err = String::new();
        write!(&mut err, "Unknown type {} for object {}", fmt, sha);
        return Err(err);
    };

    return Ok(GitObject::new(Some(repo), Some(raw[y + 1..].to_owned()), c));
}

fn object_find(
    _repo: &GitRepository,
    name: &str,
    _fmt: Option<&[u8]>, /* None by default in WYAG */
    _follow: bool,       /* True by default in WYAG */
) -> String {
    return String::from(name);
}

fn object_write(
    obj: &GitObject,
    actually_write: bool, /* True by default in WYAG */
) -> String {
    let data = obj.serialize();
    let mut result = Vec::new();
    result.extend(obj.fmt());
    result.extend(b" ");
    result.extend(data.len().to_string().bytes());
    result.extend(b"\0");
    result.extend(data);
    let mut m = sha1::Sha1::new();
    m.update(&result);
    let sha = m.digest().to_string();
    if actually_write {
        let path = Path::new("objects").join(&sha[0..2]).join(&sha[2..]);
        let path = repo_file(&obj.repo.unwrap(), path.to_str().unwrap(), actually_write).unwrap();
        let mut f = fs::File::create(path).unwrap();
        let mut encoder = ZlibEncoder::new(f, Compression::default());
        encoder.write(&result);
    }
    return sha;
}

fn cmd_cat_file(object: &str, object_type: &str) -> Result<(), String> {
    let repo = repo_find(String::from("."), true)?.unwrap();
    return cat_file(
        &repo,
        object,
        Some(&object_type.bytes().collect::<Vec<u8>>()),
    );
}

fn cat_file(repo: &GitRepository, obj: &str, fmt: Option<&[u8]>) -> Result<(), String> {
    let obj = object_read(repo, &object_find(repo, obj, fmt, true))?;
    io::stdout().write(&obj.serialize());
    return Ok(());
}

fn cmd_hash_object(write: bool, path: &str, object_type: &str) -> Result<(), String> {
    let repo = if write {
        Some(GitRepository::new(".", false)?)
    } else {
        None
    };
    let path = Path::new(path);
    let mut fd = fs::File::open(&path).unwrap();
    let sha = object_hash(&mut fd, &object_type.bytes().collect::<Vec<u8>>(), &repo)?;
    println!("{}", sha);

    return Ok(());
}

fn object_hash(
    fd: &mut fs::File,
    fmt: &[u8],
    repo: &Option<GitRepository>,
) -> Result<String, String> {
    let mut data = Vec::new();
    fd.read_to_end(&mut data);

    let object_type = match fmt {
        b"commit" => GitObjectType::Commit,
        b"tree" => GitObjectType::Tree,
        b"tag" => GitObjectType::Tag,
        b"blob" => GitObjectType::Blob,
        _ => {
            let mut err = String::new();
            write!(&mut err, "Unknown type {:?}!", fmt);
            return Err(err);
        }
    };

    let obj = GitObject::new(repo.as_ref(), Some(data), object_type);

    return Ok(object_write(&obj, repo.is_some()));
}

#[derive(Clone)]
enum DctValue {
    List(Vec<Vec<u8>>),
    Single(Vec<u8>),
}

fn kvlm_parse(
    raw: &[u8],
    start: Option<usize>,
    dct: Option<BTreeMap<Vec<u8>, DctValue>>,
) -> BTreeMap<Vec<u8>, DctValue> {
    let start = start.unwrap_or(0);
    let mut dct = dct.unwrap_or(BTreeMap::new());

    let spc = find(b' ', &raw, start);
    let nl = find(b'\n', &raw, start);

    if spc < 0 || nl < spc {
        assert!(nl == start.try_into().unwrap());
        let dctvalue = DctValue::Single(raw[start + 1..].to_vec());
        dct.insert(vec![], dctvalue);
        return dct;
    }

    let key = &raw[start..spc.try_into().unwrap()];

    let mut end = start;
    loop {
        end = find(b'\n', &raw, end + 1).try_into().unwrap();
        if end + 1 >= raw.len() || raw[end + 1] != b' ' {
            break;
        }
    }

    let value = replace(
        &raw[<usize as TryFrom<isize>>::try_from(spc).unwrap() + 1..end],
        b"\n ",
        b" ",
    );

    match dct.entry(key.to_owned()) {
        Entry::Occupied(mut d) => match d.get() {
            DctValue::List(list) => {
                let mut list = list.to_owned();
                list.append(&mut vec![value]);
                d.insert(DctValue::List(list));
            }
            DctValue::Single(v) => {
                d.insert(DctValue::List(vec![v.to_owned(), value]));
            }
        },
        Entry::Vacant(entry) => {
            entry.insert(DctValue::Single(value));
        }
    };

    if end + 1 >= raw.len() {
        return dct;
    }

    return kvlm_parse(raw, Some(end + 1), Some(dct));
}

fn kvlm_serialize(kvlm: &BTreeMap<Vec<u8>, DctValue>) -> Vec<u8> {
    let mut ret = Vec::new();

    for k in kvlm.keys() {
        if k == b"" {
            continue;
        }
        let val = kvlm.get(k).unwrap();
        let val = match val {
            DctValue::List(l) => l.to_owned(),
            DctValue::Single(s) => vec![s.to_owned()],
        };
        for v in val {
            ret.append(&mut k.to_owned());
            ret.append(&mut vec![b' ']);
            ret.append(&mut replace(&v, b"\n", b"\n "));
            ret.append(&mut vec![b'\n']);
        }
    }

    ret.append(&mut vec![b'\n']);
    match kvlm.get(&vec![]).unwrap() {
        DctValue::Single(message) => ret.append(&mut message.clone()),
        _ => unreachable!(),
    };

    return ret;
}

fn find(needle: u8, haystack: &[u8], start: usize) -> isize {
    return haystack[start..]
        .iter()
        .position(|c| c == &needle)
        .map(|i| <isize as TryFrom<usize>>::try_from(i + start).unwrap())
        .unwrap_or(-1);
}

// https://stackoverflow.com/a/55974786/3455228
fn replace<T>(source: &[T], from: &[T], to: &[T]) -> Vec<T>
where
    T: Clone + PartialEq,
{
    let mut result = source.to_vec();
    let from_len = from.len();
    let to_len = to.len();

    let mut i = 0;
    while i + from_len <= result.len() {
        if result[i..].starts_with(from) {
            result.splice(i..i + from_len, to.iter().cloned());
            i += to_len;
        } else {
            i += 1;
        }
    }

    result
}

fn cmd_log(commit: &str) -> Result<(), String> {
    let repo = repo_find(String::from("."), true)?.unwrap();
    println!("digraph wyaglog{{");
    log_graphviz(
        &repo,
        &object_find(&repo, commit, None, true),
        &mut HashSet::new(),
    )?;
    println!("}}");
    return Ok(());
}

fn log_graphviz(repo: &GitRepository, sha: &str, seen: &mut HashSet<String>) -> Result<(), String> {
    if seen.contains(sha) {
        return Ok(());
    }
    seen.insert(sha.to_owned());
    let commit = object_read(repo, sha)?;
    assert_eq!(commit.fmt(), b"commit");
    if !commit.kvlm.contains_key(b"parent" as &[u8]) {
        return Ok(());
    }

    let parents = match commit.kvlm.get(b"parent" as &[u8]).unwrap() {
        DctValue::List(l) => l.to_owned(),
        DctValue::Single(s) => vec![s.to_owned()],
    };

    for p in parents {
        let p = String::from_utf8(p).unwrap();
        println!("c_{} -> c_{}", sha, p);
        log_graphviz(repo, &p, seen)?;
    }

    return Ok(());
}
