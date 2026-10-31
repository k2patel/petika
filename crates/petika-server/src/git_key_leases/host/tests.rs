use super::*;
use std::{
    sync::{Arc, Mutex},
    thread,
};
fn public_key() -> String {
    let mut wire = Vec::new();
    wire.extend_from_slice(&11u32.to_be_bytes());
    wire.extend_from_slice(b"ssh-ed25519");
    wire.extend_from_slice(&32u32.to_be_bytes());
    wire.extend_from_slice(&[7; 32]);
    format!("ssh-ed25519 {}", STANDARD.encode(wire))
}
fn fake(
    provider: Provider,
    mode: &str,
) -> (
    ConfiguredHosts,
    Repository,
    Arc<Mutex<Vec<String>>>,
    thread::JoinHandle<()>,
) {
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let origin = format!("http://{}/", server.server_addr().to_ip().unwrap());
    let repository = Repository {
        provider,
        management_origin: origin,
        repository: "synthetic/vault".into(),
    };
    let requests = Arc::new(Mutex::new(Vec::new()));
    let logs = Arc::clone(&requests);
    let mode = mode.to_owned();
    let handle = thread::spawn(move || {
        let mut present = !mode.starts_with("registration");
        let mut title = "test-owned".to_owned();
        let mut public = public_key();
        let mut read_only = true;
        while let Ok(Some(mut request)) = server.recv_timeout(Duration::from_secs(1)) {
            let method = request.method().as_str().to_owned();
            let path = request.url().to_owned();
            assert!(
                request
                    .headers()
                    .iter()
                    .any(|h| h.field.equiv("Authorization")
                        && h.value.as_str() == "Bearer synthetic-local-only")
            );
            logs.lock().unwrap().push(format!("{method} {path}"));
            let (status, body) = if mode == "redirect" {
                (302, "[]".into())
            } else if mode == "denied" {
                (403, "{}".into())
            } else if method == "POST" {
                let mut bytes = Vec::new();
                request
                    .as_reader()
                    .take(16385)
                    .read_to_end(&mut bytes)
                    .unwrap();
                let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                title = payload["title"].as_str().unwrap().into();
                public = payload["key"].as_str().unwrap().into();
                read_only = payload["read_only"].as_bool().unwrap();
                present = true;
                if mode == "registration-lost" {
                    (503, "{}".into())
                } else {
                    (201,serde_json::json!({"id":17,"title":title,"key":public,"read_only":read_only}).to_string())
                }
            } else if method == "DELETE" {
                present = false;
                (204, String::new())
            } else if path
                .split_once('?')
                .is_some_and(|(_, q)| q.split('&').any(|p| p == "page=1"))
                && present
            {
                if mode == "malformed" {
                    (200, "not json".into())
                } else {
                    (
                        200,
                        serde_json::json!([{ "id":17,"title":title,"key":public,"read_only":read_only }])
                            .to_string(),
                    )
                }
            } else {
                (200, "[]".into())
            };
            let mut response = tiny_http::Response::from_string(body).with_status_code(status);
            if status == 302 {
                response = response.with_header(
                    tiny_http::Header::from_bytes("Location", "http://127.0.0.1:1/leak").unwrap(),
                );
            }
            request.respond(response).unwrap();
        }
    });
    let config = Configuration {
        version: 1,
        hosts: vec![Host {
            repository: repository.clone(),
            api_prefix: if repository.provider == Provider::Gitea {
                "/api/v1".into()
            } else {
                String::new()
            },
            token: Zeroizing::new("synthetic-local-only".into()),
            auth_scheme: Scheme::Bearer,
            owner_user_id: Some("b".repeat(64)),
            allow_write: false,
            max_lease_seconds: 3600,
        }],
    };
    (
        ConfiguredHosts::new(config, false),
        repository,
        requests,
        handle,
    )
}
#[test]
fn github_and_gitea_paginate_and_delete_scoped_keys() {
    for provider in [Provider::Github, Provider::Gitea] {
        let (mut adapter, repo, requests, handle) = fake(provider, "normal");
        let keys = adapter.inventory(&repo).unwrap();
        assert!(keys.complete);
        assert_eq!(keys.keys.len(), 1);
        assert_eq!(
            keys.keys[0].fingerprint,
            fingerprint(&public_key()).unwrap()
        );
        adapter.delete(&repo, "17").unwrap();
        assert!(adapter.inventory(&repo).unwrap().keys.is_empty());
        let paths = requests.lock().unwrap();
        assert!(paths[0].contains(if repo.provider == Provider::Github {
            "per_page=100"
        } else {
            "limit=100"
        }));
        assert!(paths[1].contains("page=2"));
        drop(paths);
        handle.join().unwrap();
    }
}
#[test]
fn redirects_denials_malformed_data_and_unconfigured_scope_fail_closed() {
    for mode in ["redirect", "denied", "malformed"] {
        let (mut adapter, repo, requests, handle) = fake(Provider::Github, mode);
        assert!(adapter.inventory(&repo).is_err());
        assert_eq!(requests.lock().unwrap().len(), 1);
        let mut other = repo.clone();
        other.repository = "another/vault".into();
        assert!(adapter.delete(&other, "17").is_err());
        assert!(adapter.delete(&repo, "../17").is_err());
        assert_eq!(requests.lock().unwrap().len(), 1);
        handle.join().unwrap();
    }
}
#[test]
fn configuration_requires_https_owner_only_and_known_provider_prefix() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("hosts.json");
    let file = StoreFile::lock(&path).unwrap();
    file.write(br#"{"version":1,"hosts":[{"repository":{"provider":"github","management_origin":"http://localhost/","repository":"synthetic/vault"},"api_prefix":"","token":"synthetic-local-only"}]}"#,true).unwrap();
    drop(file);
    assert!(ConfiguredHosts::load(&path).is_err());
    let encoded = std::fs::read_to_string(&path)
        .unwrap()
        .replace("http://localhost/", "https://api.example/");
    std::fs::write(&path, encoded).unwrap();
    assert!(ConfiguredHosts::load(&path).is_ok());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert!(ConfiguredHosts::load(&path).is_ok());
        let alias = dir.path().join("alias.json");
        std::os::unix::fs::symlink(&path, &alias).unwrap();
        assert!(ConfiguredHosts::load(&alias).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(ConfiguredHosts::load(&path).is_err());
    }
}

#[test]
fn repository_key_creation_and_uncertain_http_reply_are_reconcilable() {
    for provider in [Provider::Github, Provider::Gitea] {
        for mode in ["registration", "registration-lost"] {
            let (mut adapter, repo, requests, handle) = fake(provider.clone(), mode);
            assert!(adapter.authorized(&repo, &"b".repeat(64), true, 300));
            assert!(!adapter.authorized(&repo, &"b".repeat(64), false, 300));
            assert!(!adapter.authorized(&repo, &"a".repeat(64), true, 300));
            assert!(adapter.inventory(&repo).unwrap().keys.is_empty());
            let marker = format!("petika-lease:v1:{}", "f".repeat(64));
            let result = adapter.create(&repo, &marker, &public_key(), true);
            assert_eq!(result.is_ok(), mode == "registration");
            let inventory = adapter.inventory(&repo).unwrap();
            assert_eq!(inventory.keys.len(), 1);
            assert_eq!(inventory.keys[0].marker, marker);
            assert_eq!(inventory.keys[0].read_only, Some(true));
            adapter.delete(&repo, &inventory.keys[0].id).unwrap();
            assert!(adapter.inventory(&repo).unwrap().keys.is_empty());
            assert_eq!(
                requests
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|r| r.starts_with("POST "))
                    .count(),
                1
            );
            handle.join().unwrap();
        }
    }
}
