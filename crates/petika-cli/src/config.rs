use crate::Result;
use std::{
    collections::BTreeMap,
    io::Read,
    path::{Path, PathBuf},
};

#[derive(Default)]
pub struct Config {
    pub store: Option<PathBuf>,
    pub session_file: Option<PathBuf>,
    pub identity_file: Option<PathBuf>,
    pub server: Option<String>,
}
fn home() -> Option<PathBuf> {
    std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
}
fn expand(value: &str, base: &Path) -> Result<PathBuf> {
    if let Some(suffix) = value.strip_prefix("~/") {
        return Ok(home()
            .ok_or("cannot expand ~/ without a home directory")?
            .join(suffix));
    }
    let path = PathBuf::from(value);
    Ok(if path.is_absolute() {
        path
    } else {
        base.join(path)
    })
}
impl Config {
    pub fn load(explicit: Option<&Path>, disabled: bool) -> Result<Self> {
        if disabled {
            return Ok(Self::default());
        }
        let path = match explicit {
            Some(p) => p.to_path_buf(),
            None => match home() {
                Some(h) => h.join(".petikarc"),
                None => return Ok(Self::default()),
            },
        };
        let file = match std::fs::File::open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && explicit.is_none() => {
                return Ok(Self::default());
            }
            Err(e) => {
                return Err(
                    format!("cannot read CLI configuration {}: {e}", path.display()).into(),
                );
            }
        };
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err("CLI configuration must be a regular file".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o022 != 0 {
                return Err(
                    "CLI configuration must not be group/world writable; use chmod 600".into(),
                );
            }
        }
        let mut text = String::new();
        file.take(65537).read_to_string(&mut text)?;
        if text.len() > 65536 {
            return Err("CLI configuration is too large".into());
        }
        Self::parse(&text, path.parent().unwrap_or(Path::new(".")))
    }
    fn parse(text: &str, base: &Path) -> Result<Self> {
        let mut fields = BTreeMap::new();
        for (index, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let invalid = || {
                format!(
                    "invalid CLI configuration at line {}; use documented key = value settings only",
                    index + 1
                )
            };
            let (key, value) = line.split_once('=').ok_or_else(invalid)?;
            let key = key.trim();
            let value = value.trim();
            if !["store", "session_file", "identity_file", "server"].contains(&key)
                || value.is_empty()
                || fields.contains_key(key)
            {
                return Err(invalid().into());
            }
            let value = if value.starts_with('"') {
                serde_json::from_str::<String>(value).map_err(|_| invalid())?
            } else {
                value.to_string()
            };
            if value.is_empty() || value.chars().any(char::is_control) {
                return Err(invalid().into());
            }
            fields.insert(key, value);
        }
        let path = |key| fields.get(key).map(|v| expand(v, base)).transpose();
        Ok(Self {
            store: path("store")?,
            session_file: path("session_file")?,
            identity_file: path("identity_file")?,
            server: fields.remove("server"),
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn data_only_defaults_and_strict_errors() {
        let config=Config::parse("# defaults\nstore = vault.petika\nsession_file = \"account session.json\"\nserver = https://example.test\n",Path::new("/tmp/config")).unwrap();
        assert_eq!(config.store.unwrap(), Path::new("/tmp/config/vault.petika"));
        assert_eq!(
            config.session_file.unwrap(),
            Path::new("/tmp/config/account session.json")
        );
        assert_eq!(config.server.as_deref(), Some("https://example.test"));
        for text in [
            "password = hidden-secret",
            "store=a\nstore=b",
            "unknown=x",
            "store=",
            "store=\"unterminated",
        ] {
            let error = Config::parse(text, Path::new("."))
                .err()
                .unwrap()
                .to_string();
            assert!(!error.contains("hidden-secret"));
        }
        let config = Config::parse("store = $(touch sentinel)", Path::new("/tmp")).unwrap();
        assert_eq!(config.store.unwrap(), Path::new("/tmp/$(touch sentinel)"));
    }
}
