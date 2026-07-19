use std::{
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard},
};

use tempfile::TempDir;
use tough::schema::key::{EcdsaScheme, Key};

use crate::signer::{KeyId, TokenId};

const TEST_PIN: &str = "12345678";
const TEST_SO_PIN: &str = "00000000";
const TEST_TOKEN_LABEL: &str = "test-token";
const TEST_KEY_LABEL: &str = "test-key";

struct SoftHsmEnv {
    _dir: TempDir,
    module: PathBuf,
    conf_path: PathBuf,
    // Should be last to release the test lock only after all clenaup
    _guard: MutexGuard<'static, ()>,
}

static TEST_MUTEX: Mutex<()> = Mutex::new(());

impl SoftHsmEnv {
    fn setup() -> Self {
        let guard = TEST_MUTEX.lock().unwrap_or_else(|p| p.into_inner());

        let module = find_softhsm2_lib();

        let dir = TempDir::new().expect("tempdir");
        let tokens_dir = dir.path().join("tokens");
        std::fs::create_dir(&tokens_dir).expect("create tokens dir");

        let conf_path = dir.path().join("softhsm2.conf");
        std::fs::write(
            &conf_path,
            format!("directories.tokendir = {}\n", tokens_dir.display()),
        )
        .expect("write softhsm2.conf");

        // Safety: TEST_MUTEX is held by the caller for the duration of this
        // test, so no other thread reads SOFTHSM2_CONF concurrently.
        unsafe { std::env::set_var("SOFTHSM2_CONF", &conf_path) };

        Self {
            _dir: dir,
            conf_path,
            module,
            _guard: guard,
        }
    }

    fn key_source(&self, token: TokenId, key: KeyId) -> super::Pkcs11KeySource {
        super::Pkcs11KeySource {
            module_path: self.module.clone(),
            token,
            key,
            pin: Some(TEST_PIN.into()),
        }
    }

    fn init_token(&self, label: &str) {
        let status = std::process::Command::new("softhsm2-util")
            .args([
                "--init-token",
                "--free",
                "--so-pin",
                TEST_SO_PIN,
                "--pin",
                TEST_PIN,
                "--label",
                label,
            ])
            .env("SOFTHSM2_CONF", &self.conf_path)
            .status()
            .expect("softhsm2-util failed");

        assert!(status.success(), "softhsm2-util --init-token failed");
    }

    fn pksc11_tool(&self, token_label: &str) -> std::process::Command {
        let mut cmd = std::process::Command::new("pkcs11-tool");
        cmd.arg("--module")
            .arg(&self.module)
            .arg("--token-label")
            .arg(token_label)
            .arg("--login")
            .arg("--pin")
            .arg(TEST_PIN)
            .env("SOFTHSM2_CONF", &self.conf_path);

        cmd
    }

    fn generate_ecdsa_key(&self, token_label: &str, id: &str, label: &str) {
        let status = self
            .pksc11_tool(token_label)
            .arg("--keypairgen")
            .arg("--key-type=EC:prime256v1")
            .arg("--id")
            .arg(id)
            .arg("--label")
            .arg(label)
            .status()
            .expect("pkcs11-tool failed");

        assert!(status.success(), "pkcs11-tool failed");
    }
}

fn find_softhsm2_lib() -> PathBuf {
    if let Some(path) = std::env::var_os("SOFTHSM2_SO_PATH") {
        let path = PathBuf::from(path);
        assert!(path.exists(), "SOFTHSM2_SO_PATH doesn't exist ({:?})", path);
        return path;
    }

    let candidates = [
        "/usr/lib/softhsm/libsofthsm2.so",
        "/usr/local/lib/softhsm/libsofthsm2.so",
        "/opt/homebrew/lib/softhsm/libsofthsm2.so",
        "/opt/homebrew/opt/softhsm/lib/softhsm/libsofthsm2.so",
        "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
        "/usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so",
    ];
    candidates
        .iter()
        .map(Path::new)
        .find(|p| p.exists())
        .map(PathBuf::from)
        .expect("libsofthsm2.so not found; install SoftHSM2 or disable the softhsm-tests feature")
}

#[test]
fn test_match_key_by_id() {
    let env = SoftHsmEnv::setup();
    env.init_token(TEST_TOKEN_LABEL);
    env.generate_ecdsa_key(TEST_TOKEN_LABEL, "01", TEST_KEY_LABEL);

    let source = env.key_source(
        TokenId::Label(TEST_TOKEN_LABEL.into()),
        KeyId::Id(vec![0x01]),
    );

    let key = source.to_key().unwrap();
    let Key::Ecdsa {
        scheme: EcdsaScheme::EcdsaSha2Nistp256,
        ..
    } = key.pub_key()
    else {
        panic!("key is not ecdsa");
    };
}

#[test]
fn test_sign_ecdsa_p256() {
    let env = SoftHsmEnv::setup();
    env.init_token(TEST_TOKEN_LABEL);
    env.generate_ecdsa_key(TEST_TOKEN_LABEL, "01", TEST_KEY_LABEL);

    let source = env.key_source(
        TokenId::Label(TEST_TOKEN_LABEL.into()),
        KeyId::Label(TEST_KEY_LABEL.into()),
    );

    let key = source.to_key().unwrap();
    let Key::Ecdsa {
        scheme: EcdsaScheme::EcdsaSha2Nistp256,
        ..
    } = key.pub_key()
    else {
        panic!("key is not ecdsa");
    };

    let signature = key.sign(b"test_message").unwrap();
    key.pub_key().verify(b"test_message", &signature);
}
