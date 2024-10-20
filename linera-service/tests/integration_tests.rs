// Copyright (c) Facebook, Inc. and its affiliates.
// Copyright (c) Zefchain Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use async_graphql::InputType;
use linera_base::identifiers::{ChainId, EffectId, Owner};
use linera_execution::Bytecode;
use linera_service::config::WalletState;
#[cfg(feature = "aws")]
use linera_views::test_utils::LocalStackTestContext;
use once_cell::sync::{Lazy, OnceCell};
use serde_json::{json, Value};
use std::{
    collections::{HashMap, HashSet},
    env, fs,
    io::Write,
    ops::Range,
    path::PathBuf,
    process::Stdio,
    rc::Rc,
    str::FromStr,
    time::Duration,
};
use tempfile::{tempdir, TempDir};
use tokio::{
    process::{Child, Command},
    sync::Mutex,
};
use tonic_health::proto::{
    health_check_response::ServingStatus, health_client::HealthClient, HealthCheckRequest,
};
use tracing::{info, warn};

/// A static lock to prevent integration tests from running in parallel.
static INTEGRATION_TEST_GUARD: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

/// The name of the environment variable that allows specifying additional arguments to be passed
/// to `cargo` when starting client, server and proxy processes.
const CARGO_ENV: &str = "INTEGRATION_TEST_CARGO_PARAMS";

/// The name of the environment variable that allows specifying additional arguments to be passed
/// to the binary when starting a server.
const SERVER_ENV: &str = "INTEGRATION_TEST_SERVER_PARAMS";

#[test_log::test(tokio::test)]
async fn test_examples_in_readme() -> std::io::Result<()> {
    let _guard = INTEGRATION_TEST_GUARD.lock().await;

    let dir = tempdir().unwrap();
    let file = std::io::BufReader::new(std::fs::File::open("../README.md")?);
    let mut quotes = get_bash_quotes(file)?;
    // Check that we have the expected number of examples starting with "```bash".
    assert_eq!(quotes.len(), 1);
    let quote = quotes.pop().unwrap();

    let mut test_script = std::fs::File::create(dir.path().join("test.sh"))?;
    write!(&mut test_script, "{}", quote)?;

    let status = Command::new("bash")
        .current_dir("..") // root of the repo
        .arg("-e")
        .arg("-x")
        .arg(dir.path().join("test.sh"))
        .status()
        .await?;
    assert!(status.success());
    Ok(())
}

#[allow(clippy::while_let_on_iterator)]
fn get_bash_quotes(reader: impl std::io::BufRead) -> std::io::Result<Vec<String>> {
    let mut result = Vec::new();
    let mut lines = reader.lines();

    while let Some(line) = lines.next() {
        let line = line?;
        if line.starts_with("```bash") {
            let mut quote = String::new();
            while let Some(line) = lines.next() {
                let line = line?;
                if line.starts_with("```") {
                    break;
                }
                quote += &line;
                quote += "\n";
            }
            result.push(quote);
        }
    }

    Ok(result)
}

#[cfg(feature = "aws")]
mod aws_test {
    use super::*;

    const ROCKSDB_STORAGE: &str = "--storage rocksdb:server_\"$I\"_\"$J\".db";
    const DYNAMO_DB_STORAGE: &str = "--storage dynamodb:server-\"$I\":localstack";

    const BUILD: &str = "cargo build";
    const AWS_BUILD: &str = "cargo build --features aws";

    #[test_log::test(tokio::test)]
    async fn test_examples_in_readme_with_dynamo_db() -> anyhow::Result<()> {
        let _localstack_guard = LocalStackTestContext::new().await?;
        let dir = tempdir().unwrap();
        let file = std::io::BufReader::new(std::fs::File::open("../README.md")?);
        let mut quotes = get_bash_quotes(file)?;
        // Check that we have the expected number of examples starting with "```bash".
        assert_eq!(quotes.len(), 1);
        let quote = quotes.pop().unwrap();
        assert_eq!(quote.matches(ROCKSDB_STORAGE).count(), 1);
        let quote = quote.replace(ROCKSDB_STORAGE, DYNAMO_DB_STORAGE);
        let quote = quote.replace(BUILD, AWS_BUILD);

        let mut test_script = std::fs::File::create(dir.path().join("test.sh"))?;
        write!(&mut test_script, "{}", quote)?;

        let status = Command::new("bash")
            .current_dir("..") // root of the repo
            .arg("-e")
            .arg("-x")
            .arg(dir.path().join("test.sh"))
            .status()
            .await?;
        assert!(status.success());
        Ok(())
    }
}

#[derive(Copy, Clone)]
enum Network {
    Grpc,
    Simple,
}

impl Network {
    fn internal(&self) -> &'static str {
        match self {
            Network::Grpc => "\"Grpc\"",
            Network::Simple => "{ Simple = \"Tcp\" }",
        }
    }

    fn external(&self) -> &'static str {
        match self {
            Network::Grpc => "\"Grpc\"",
            Network::Simple => "{ Simple = \"Tcp\" }",
        }
    }

    fn external_short(&self) -> &'static str {
        match self {
            Network::Grpc => "grpc",
            Network::Simple => "tcp",
        }
    }
}

async fn cargo_force_build_binary(name: &'static str) -> PathBuf {
    let mut build_command = Command::new("cargo");
    build_command.arg("build");
    let is_release = if let Ok(var) = env::var(CARGO_ENV) {
        let extra_args = var.split_whitespace();
        build_command.args(extra_args.clone());
        let extra_args: HashSet<_> = extra_args.into_iter().map(str::trim).collect();
        extra_args.contains("-r") || extra_args.contains("--release")
    } else {
        false
    };
    build_command
        .args(["--features", "benchmark"])
        .args(["--bin", name]);
    info!("Running compiler: {:?}", build_command);
    build_command.spawn().unwrap().wait().await.unwrap();
    if is_release {
        env::current_dir()
            .unwrap()
            .join("../target/release")
            .join(name)
            .canonicalize()
            .unwrap()
    } else {
        env::current_dir()
            .unwrap()
            .join("../target/debug")
            .join(name)
            .canonicalize()
            .unwrap()
    }
}

async fn cargo_build_binary(name: &'static str) -> PathBuf {
    static COMPILED_BINARIES: OnceCell<Mutex<HashMap<&'static str, PathBuf>>> = OnceCell::new();
    let mut binaries = COMPILED_BINARIES.get_or_init(Default::default).lock().await;
    match binaries.get(name) {
        Some(path) => path.clone(),
        None => {
            let path = cargo_force_build_binary(name).await;
            binaries.insert(name, path.clone());
            path
        }
    }
}

struct Client {
    tmp_dir: Rc<TempDir>,
    storage: String,
    wallet: String,
    max_pending_messages: usize,
    network: Network,
}

impl Client {
    fn new(tmp_dir: Rc<TempDir>, network: Network, id: usize) -> Self {
        Self {
            tmp_dir,
            storage: format!("rocksdb:client_{}.db", id),
            wallet: format!("wallet_{}.json", id),
            max_pending_messages: 10_000,
            network,
        }
    }

    async fn run(&self) -> Command {
        let path = cargo_build_binary("linera").await;
        let mut command = Command::new(path);
        command
            .current_dir(&self.tmp_dir.path().canonicalize().unwrap())
            .kill_on_drop(true)
            .args(["--wallet", &self.wallet])
            .args(["--send-timeout-us", "10000000"])
            .args(["--recv-timeout-us", "10000000"]);
        command
    }

    async fn run_with_storage(&self) -> Command {
        let mut command = self.run().await;
        command
            .args(["--storage", &self.storage.to_string()])
            .args([
                "--max-pending-messages",
                &self.max_pending_messages.to_string(),
            ]);
        command
    }

    async fn create_genesis_config(&self) {
        self.run()
            .await
            .args(["create_genesis_config", "10"])
            .args(["--initial-funding", "10"])
            .args(["--committee", "committee.json"])
            .args(["--genesis", "genesis.json"])
            .spawn()
            .unwrap()
            .wait()
            .await
            .unwrap();
    }

    async fn init(&self) {
        self.run()
            .await
            .args(["wallet", "init"])
            .args(["--genesis", "genesis.json"])
            .spawn()
            .unwrap()
            .wait()
            .await
            .unwrap();
    }

    async fn run_command(command: &mut Command) -> String {
        let output = command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
            .wait_with_output()
            .await
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(0),
            "Command {:?} failed; stderr:\n{}\n(end stderr)",
            command,
            String::from_utf8_lossy(&output.stderr),
        );
        String::from_utf8(output.stdout).unwrap()
    }

    async fn publish_and_create(
        &self,
        contract: PathBuf,
        service: PathBuf,
        arg: impl ToString,
        publisher: impl Into<Option<ChainId>>,
    ) -> String {
        let stdout = Self::run_command(
            self.run_with_storage()
                .await
                .arg("publish_and_create")
                .args([contract, service])
                .arg(arg.to_string())
                .args(publisher.into().iter().map(ChainId::to_string)),
        )
        .await;
        stdout.trim().to_string()
    }

    async fn publish_bytecode(
        &self,
        contract: PathBuf,
        service: PathBuf,
        publisher: impl Into<Option<ChainId>>,
    ) -> String {
        let stdout = Self::run_command(
            self.run_with_storage()
                .await
                .arg("publish_bytecode")
                .args([contract, service])
                .args(publisher.into().iter().map(ChainId::to_string)),
        )
        .await;
        stdout.trim().to_string()
    }

    async fn create_application(
        &self,
        bytecode_id: String,
        arg: impl ToString,
        creator: impl Into<Option<ChainId>>,
    ) -> String {
        let stdout = Self::run_command(
            self.run_with_storage()
                .await
                .arg("create_application")
                .args([bytecode_id, arg.to_string()])
                .args(creator.into().iter().map(ChainId::to_string)),
        )
        .await;
        stdout.trim().to_string()
    }

    async fn run_node_service(
        &self,
        chain_id: impl Into<Option<ChainId>>,
        port: impl Into<Option<u16>>,
    ) -> NodeService {
        let chain_id = chain_id.into();
        let port = port.into().unwrap_or(8080);
        let child = self
            .run_with_storage()
            .await
            .arg("service")
            .args(chain_id.as_ref().map(ChainId::to_string))
            .args(["--port".to_string(), port.to_string()])
            .spawn()
            .unwrap();
        let client = reqwest::Client::new();
        for i in 0..10 {
            tokio::time::sleep(Duration::from_secs(i)).await;
            let request = client
                .get(format!("http://localhost:{}/", port))
                .send()
                .await;
            if request.is_ok() {
                info!("Node service has started");
                return NodeService {
                    port,
                    chain_id,
                    _child: child,
                };
            } else {
                warn!("Waiting for node service to start");
            }
        }
        panic!("Failed to start node service");
    }

    async fn query_validators(&self, chain_id: Option<ChainId>) {
        let mut command = self.run_with_storage().await;
        command.arg("query_validators");
        if let Some(chain_id) = chain_id {
            command.arg(&chain_id.to_string());
        }
        Self::run_command(&mut command).await;
    }

    async fn query_balance(&self, chain_id: ChainId) -> anyhow::Result<usize> {
        let stdout = Self::run_command(
            self.run_with_storage()
                .await
                .arg("query_balance")
                .arg(&chain_id.to_string()),
        )
        .await;
        let amount = stdout.trim().parse()?;
        Ok(amount)
    }

    async fn transfer(&self, amount: usize, from: ChainId, to: ChainId) {
        Self::run_command(
            self.run_with_storage()
                .await
                .arg("transfer")
                .arg(&amount.to_string())
                .args(["--from", &from.to_string()])
                .args(["--to", &to.to_string()]),
        )
        .await;
    }

    async fn benchmark(&self, max_in_flight: usize) {
        self.run_with_storage()
            .await
            .arg("benchmark")
            .args(["--max-in-flight", &max_in_flight.to_string()])
            .spawn()
            .unwrap()
            .wait()
            .await
            .unwrap();
    }

    async fn open_chain(
        &self,
        from: ChainId,
        to_owner: Option<Owner>,
    ) -> anyhow::Result<(EffectId, ChainId)> {
        let mut command = self.run_with_storage().await;
        command
            .arg("open_chain")
            .args(["--from", &from.to_string()]);

        if let Some(owner) = to_owner {
            command.args(["--to-public-key", &owner.to_string()]);
        }

        let stdout = Self::run_command(&mut command).await;
        let mut split = stdout.split('\n');
        let effect_id: EffectId = split.next().unwrap().parse()?;
        let chain_id = ChainId::from_str(split.next().unwrap())?;

        Ok((effect_id, chain_id))
    }

    fn get_wallet(&self) -> WalletState {
        WalletState::read(self.tmp_dir.path().join(&self.wallet).as_path()).unwrap()
    }

    async fn check_for_chain_in_wallet(&self, chain: ChainId) -> bool {
        self.get_wallet().get(chain).is_some()
    }

    async fn set_validator(&self, name: &str, port: usize, votes: usize) {
        let address = format!("{}:127.0.0.1:{}", self.network.external_short(), port);
        Self::run_command(
            self.run_with_storage()
                .await
                .arg("set_validator")
                .args(["--name", name])
                .args(["--address", &address])
                .args(["--votes", &votes.to_string()]),
        )
        .await;
    }

    async fn remove_validator(&self, name: &str) {
        Self::run_command(
            self.run_with_storage()
                .await
                .arg("remove_validator")
                .args(["--name", name]),
        )
        .await;
    }

    async fn keygen(&self) -> anyhow::Result<Owner> {
        let stdout = Self::run_command(self.run().await.arg("keygen")).await;
        Ok(Owner::from_str(stdout.trim())?)
    }

    async fn assign(&self, owner: Owner, effect_id: EffectId) -> anyhow::Result<ChainId> {
        let stdout = Self::run_command(
            self.run_with_storage()
                .await
                .arg("assign")
                .args(["--key", &owner.to_string()])
                .args(["--effect-id", &effect_id.to_string()]),
        )
        .await;

        let chain_id = ChainId::from_str(stdout.trim())?;

        Ok(chain_id)
    }

    async fn synchronize_balance(&self, chain_id: ChainId) {
        Self::run_command(
            self.run_with_storage()
                .await
                .arg("sync_balance")
                .arg(&chain_id.to_string()),
        )
        .await;
    }
}

struct Validator {
    _proxy: Child,
    servers: Vec<Child>,
}

impl Validator {
    fn new(proxy: Child) -> Self {
        Self {
            _proxy: proxy,
            servers: vec![],
        }
    }

    fn add_server(&mut self, server: Child) {
        self.servers.push(server)
    }

    fn kill_server(&mut self, index: usize) {
        self.servers.remove(index);
    }
}

struct TestRunner {
    tmp_dir: Rc<TempDir>,
    network: Network,
    next_client_id: usize,
}

impl TestRunner {
    fn new(network: Network) -> Self {
        Self {
            tmp_dir: Rc::new(tempdir().unwrap()),
            network,
            next_client_id: 0,
        }
    }

    fn make_client(&mut self, network: Network) -> Client {
        let client = Client::new(self.tmp_dir.clone(), network, self.next_client_id);
        self.next_client_id += 1;
        client
    }

    async fn command_for_binary(&self, name: &'static str) -> Command {
        let path = cargo_build_binary(name).await;
        let mut command = Command::new(path);
        command
            .current_dir(&self.tmp_dir.path().canonicalize().unwrap())
            .kill_on_drop(true);
        command
    }

    fn proxy_port(i: usize) -> usize {
        9000 + i * 100
    }

    fn shard_port(i: usize, j: usize) -> usize {
        9000 + i * 100 + j
    }

    fn internal_port(i: usize) -> usize {
        10000 + i * 100
    }

    fn metrics_port(i: usize) -> usize {
        11000 + i * 100
    }

    fn configuration_string(&self, server_number: usize) -> String {
        let n = server_number;
        let path = self
            .tmp_dir
            .path()
            .canonicalize()
            .unwrap()
            .join(format!("validator_{n}.toml"));
        let port = Self::proxy_port(n);
        let internal_port = Self::internal_port(n);
        let metrics_port = Self::metrics_port(n);
        let external_protocol = self.network.external();
        let internal_protocol = self.network.internal();
        let mut content = format!(
            r#"
                server_config_path = "server_{n}.json"
                host = "127.0.0.1"
                port = {port}
                internal_host = "127.0.0.1"
                internal_port = {internal_port}
                external_protocol = {external_protocol}
                internal_protocol = {internal_protocol}
            "#
        );
        for k in 1..=4 {
            let shard_port = Self::shard_port(n, k);
            let shard_metrics_port = metrics_port + k;
            content.push_str(&format!(
                r#"
                
                [[shards]]
                host = "127.0.0.1"
                port = {shard_port}
                metrics_host = "127.0.0.1"
                metrics_port = {shard_metrics_port}
                "#
            ));
        }
        fs::write(&path, content).unwrap();
        path.into_os_string().into_string().unwrap()
    }

    async fn generate_initial_server_config(&self, n_validators: usize) {
        let mut command = self.command_for_binary("server").await;
        command.arg("generate").arg("--validators");
        for i in 1..n_validators + 1 {
            command.arg(&self.configuration_string(i));
        }
        command
            .args(["--committee", "committee.json"])
            .status()
            .await
            .unwrap();
    }

    async fn generate_server_config(&self, server_number: usize) -> anyhow::Result<String> {
        let output = self
            .command_for_binary("server")
            .await
            .arg("generate")
            .arg("--validators")
            .arg(&self.configuration_string(server_number))
            .stdout(Stdio::piped())
            .spawn()?
            .wait_with_output()
            .await?;
        Ok(String::from_utf8_lossy(output.stdout.as_slice())
            .to_string()
            .trim()
            .to_string())
    }

    async fn run_proxy(&self, i: usize) -> Child {
        let child = self
            .command_for_binary("proxy")
            .await
            .arg(format!("server_{}.json", i))
            .spawn()
            .unwrap();

        match self.network {
            Network::Grpc => {
                let port = Self::proxy_port(i);
                let nickname = format!("validator proxy {i}");
                Self::ensure_grpc_server_has_started(&nickname, port).await;
            }
            Network::Simple => {
                info!("Letting validator proxy {i} start");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
        child
    }

    async fn ensure_grpc_server_has_started(nickname: &str, port: usize) {
        let connection = tonic::transport::Endpoint::new(format!("http://127.0.0.1:{port}"))
            .unwrap()
            .connect_lazy();
        let mut client = HealthClient::new(connection);
        for i in 0..10 {
            tokio::time::sleep(Duration::from_secs(i)).await;
            let result = client.check(HealthCheckRequest::default()).await;
            if result.is_ok() && result.unwrap().get_ref().status() == ServingStatus::Serving {
                info!("Successfully started {nickname}");
                return;
            } else {
                warn!("Waiting for {nickname} to start");
            }
        }
        panic!("Failed to start {nickname}");
    }

    async fn run_server(&self, i: usize, j: usize) -> Child {
        let mut command = self.command_for_binary("server").await;
        command.arg("run");
        if let Ok(var) = env::var(SERVER_ENV) {
            command.args(var.split_whitespace());
        }
        let child = command
            .args(["--storage", &format!("rocksdb:server_{}_{}.db", i, j)])
            .args(["--server", &format!("server_{}.json", i)])
            .args(["--shard", &j.to_string()])
            .args(["--genesis", "genesis.json"])
            .spawn()
            .unwrap();

        match self.network {
            Network::Grpc => {
                let port = Self::shard_port(i, j);
                let nickname = format!("validator server {i}:{j}");
                Self::ensure_grpc_server_has_started(&nickname, port).await;
            }
            Network::Simple => {
                info!("Letting validator server {i}:{j} start");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
        child
    }

    async fn run_local_net(&self, n_validators: usize) -> Vec<Validator> {
        self.start_validators(1..n_validators + 1).await
    }

    async fn start_validators(&self, validator_range: Range<usize>) -> Vec<Validator> {
        let mut validators = vec![];
        for i in validator_range {
            let proxy = self.run_proxy(i).await;
            let mut validator = Validator::new(proxy);
            for j in 0..4 {
                let server = self.run_server(i, j).await;
                validator.add_server(server);
            }
            validators.push(validator);
        }
        validators
    }

    async fn build_application(&self, name: &str) -> (PathBuf, PathBuf) {
        let examples_dir = env::current_dir().unwrap().join("../linera-examples/");
        Command::new("cargo")
            .current_dir(self.tmp_dir.path().canonicalize().unwrap())
            .arg("build")
            .arg("--release")
            .args(["--target", "wasm32-unknown-unknown"])
            .arg("--manifest-path")
            .arg(examples_dir.join(name).join("Cargo.toml"))
            .stdout(Stdio::piped())
            .spawn()
            .unwrap()
            .wait()
            .await
            .unwrap();

        let release_dir = examples_dir.join("target/wasm32-unknown-unknown/release");
        let contract = release_dir.join(format!("{}_contract.wasm", name.replace('-', "_")));
        let service = release_dir.join(format!("{}_service.wasm", name.replace('-', "_")));

        (contract, service)
    }
}

struct NodeService {
    chain_id: Option<ChainId>,
    port: u16,
    _child: Child,
}

impl NodeService {
    async fn make_application(&self, application_id: &str) -> Application {
        for i in 0..10 {
            tokio::time::sleep(Duration::from_secs(i)).await;
            let values = self.try_get_applications_uri().await;
            if let Some(link) = values.get(application_id) {
                return Application {
                    uri: link.to_string(),
                };
            }
            warn!(
                "Waiting for application {application_id:?} to be visible on chain {:?}",
                self.chain_id
            );
        }
        panic!("Could not find application URI");
    }

    async fn try_get_applications_uri(&self) -> HashMap<String, String> {
        let query_string = if let Some(chain_id) = self.chain_id {
            format!(
                "query {{ applications(chainId: \"{}\") {{ id link }}}}",
                chain_id
            )
        } else {
            "query { applications { id link }}".to_string()
        };
        let query = json!({ "query": query_string });
        let client = reqwest::Client::new();
        let response = client
            .post(format!("http://localhost:{}/", self.port))
            .json(&query)
            .send()
            .await
            .unwrap();
        let body: Value = response.json().await.unwrap();
        body["data"]["applications"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| {
                let id = a["id"].as_str().unwrap().to_string();
                let link = a["link"].as_str().unwrap().to_string();
                (id, link)
            })
            .collect()
    }

    async fn publish_bytecode(&self, contract: PathBuf, service: PathBuf) -> String {
        let contract_code = Bytecode::load_from_file(&contract).await.unwrap();
        let service_code = Bytecode::load_from_file(&service).await.unwrap();
        let query_string = format!(
            "mutation {{ publishBytecode(contract: {}, service: {}) }}",
            contract_code.to_value(),
            service_code.to_value(),
        );
        let response_body = self.query(&query_string).await;
        if let Some(errors) = response_body.get("errors") {
            let mut error_string = errors.to_string();
            if error_string.len() > 10000 {
                error_string = format!(
                    "{}..{}",
                    &error_string[..5000],
                    &error_string[(error_string.len() - 5000)..]
                );
            }
            panic!("publish_and_create failed: {}", error_string);
        }
        serde_json::from_value(response_body["data"]["publishBytecode"].clone()).unwrap()
    }

    async fn query(&self, query_string: &str) -> Value {
        let query = json!({ "query": query_string });
        let url = format!("http://localhost:{}/", self.port);
        let client = reqwest::Client::new();
        let response = client.post(url).json(&query).send().await.unwrap();
        response.json().await.unwrap()
    }

    async fn create_application(&self, bytecode_id: &str) -> String {
        let query_string = format!(
            "mutation {{ createApplication(\
                bytecodeId: \"{bytecode_id}\", \
                parameters: [], \
                initializationArgument: [], \
                requiredApplicationIds: []) \
            }}"
        );
        let query = json!({ "query": query_string });
        let client = reqwest::Client::new();
        let response = client
            .post(format!("http://localhost:{}/", self.port))
            .json(&query)
            .send()
            .await
            .unwrap();
        let response_body: Value = response.json().await.unwrap();
        if let Some(errors) = response_body.get("errors") {
            panic!("create_application failed: {}", errors);
        }
        serde_json::from_value(response_body["data"]["createApplication"].clone()).unwrap()
    }
}

struct Application {
    uri: String,
}

impl Application {
    async fn get_counter_value(&self) -> u64 {
        let response_body = self.query_application("query { value }").await;
        serde_json::from_value(response_body["data"]["value"].clone()).unwrap()
    }

    async fn query_application(&self, query_string: &str) -> Value {
        let query = json!({ "query": query_string });
        let client = reqwest::Client::new();
        let response = client.post(&self.uri).json(&query).send().await.unwrap();
        if !response.status().is_success() {
            panic!(
                "Query \"{}\" failed: {}",
                query_string,
                response.text().await.unwrap()
            );
        }
        response.json().await.unwrap()
    }

    async fn increment_counter_value(&self, increment: u64) {
        let query_string = format!(
            "mutation {{  executeOperation(operation: {{ increment: {} }})}}",
            increment
        );
        let query = json!({ "query": query_string });
        let client = reqwest::Client::new();
        client.post(&self.uri).json(&query).send().await.unwrap();
    }
}

#[test_log::test(tokio::test)]
async fn test_end_to_end_counter() {
    let _guard = INTEGRATION_TEST_GUARD.lock().await;

    let network = Network::Grpc;
    let mut runner = TestRunner::new(network);
    let client = runner.make_client(network);
    let n_validators = 4;

    let original_counter_value = 35;
    let increment = 5;

    runner.generate_initial_server_config(n_validators).await;
    client.create_genesis_config().await;
    let _local_net = runner.run_local_net(n_validators).await;
    let (contract, service) = runner.build_application("counter-graphql").await;

    let application_id = client
        .publish_and_create(contract, service, original_counter_value, None)
        .await;
    let node_service = client.run_node_service(None, None).await;

    let application = node_service.make_application(&application_id).await;

    let counter_value = application.get_counter_value().await;
    assert_eq!(counter_value, original_counter_value);

    application.increment_counter_value(increment).await;

    let counter_value = application.get_counter_value().await;
    assert_eq!(counter_value, original_counter_value + increment);
}

#[test_log::test(tokio::test)]
async fn test_end_to_end_counter_publish_create() {
    let _guard = INTEGRATION_TEST_GUARD.lock().await;

    let network = Network::Grpc;
    let mut runner = TestRunner::new(network);
    let client = runner.make_client(network);
    let n_validators = 4;

    let original_counter_value = 35;
    let increment = 5;

    runner.generate_initial_server_config(n_validators).await;
    client.create_genesis_config().await;
    let _local_net = runner.run_local_net(n_validators).await;
    let (contract, service) = runner.build_application("counter-graphql").await;

    let bytecode_id = client.publish_bytecode(contract, service, None).await;
    let application_id = client
        .create_application(bytecode_id, original_counter_value, None)
        .await;
    let node_service = client.run_node_service(None, None).await;

    let application = node_service.make_application(&application_id).await;

    let counter_value = application.get_counter_value().await;
    assert_eq!(counter_value, original_counter_value);

    application.increment_counter_value(increment).await;

    let counter_value = application.get_counter_value().await;
    assert_eq!(counter_value, original_counter_value + increment);
}

#[test_log::test(tokio::test)]
async fn test_end_to_end_multiple_wallets() {
    let _guard = INTEGRATION_TEST_GUARD.lock().await;

    // Create runner and two clients.
    let mut runner = TestRunner::new(Network::Grpc);
    let client_1 = runner.make_client(Network::Grpc);
    let client_2 = runner.make_client(Network::Grpc);
    let n_validators = 4;

    // Create initial server and client config.
    runner.generate_initial_server_config(n_validators).await;
    client_1.create_genesis_config().await;
    client_2.init().await;

    // Start local network.
    let _local_net = runner.run_local_net(n_validators).await;

    // Get some chain owned by Client 1.
    let chain_1 = *client_1.get_wallet().chain_ids().first().unwrap();

    // Generate a key for Client 2.
    let client_2_key = client_2.keygen().await.unwrap();

    // Open chain on behalf of Client 2.
    let (effect_id, chain_2) = client_1
        .open_chain(chain_1, Some(client_2_key))
        .await
        .unwrap();

    // Assign chain_2 to client_2_key.
    assert_eq!(
        chain_2,
        client_2.assign(client_2_key, effect_id).await.unwrap()
    );

    // Check initial balance of Chain 1.
    assert_eq!(client_1.query_balance(chain_1).await.unwrap(), 10);

    // Transfer 5 units from Chain 1 to Chain 2.
    client_1.transfer(5, chain_1, chain_2).await;
    client_2.synchronize_balance(chain_2).await;

    assert_eq!(client_1.query_balance(chain_1).await.unwrap(), 5);
    assert_eq!(client_2.query_balance(chain_2).await.unwrap(), 5);

    // Transfer 2 units from Chain 2 to Chain 1.
    client_2.transfer(2, chain_2, chain_1).await;
    client_1.synchronize_balance(chain_1).await;

    assert_eq!(client_1.query_balance(chain_1).await.unwrap(), 7);
    assert_eq!(client_2.query_balance(chain_2).await.unwrap(), 3);
}

#[test_log::test(tokio::test)]
async fn test_end_to_end_reconfiguration_grpc() {
    let _guard = INTEGRATION_TEST_GUARD.lock().await;
    test_reconfiguration(Network::Grpc).await;
}

#[test_log::test(tokio::test)]
async fn test_end_to_end_reconfiguration_simple() {
    let _guard = INTEGRATION_TEST_GUARD.lock().await;
    test_reconfiguration(Network::Simple).await;
}

async fn test_reconfiguration(network: Network) {
    let mut runner = TestRunner::new(network);
    let client = runner.make_client(network);
    let n_validators = 4;

    runner.generate_initial_server_config(n_validators).await;
    client.create_genesis_config().await;
    let mut local_net = runner.run_local_net(n_validators).await;

    client.query_validators(None).await;

    // Query balance for first and last user chain
    let chain_1 = ChainId::root(0);
    let chain_2 = ChainId::root(9);
    assert_eq!(client.query_balance(chain_1).await.unwrap(), 10);
    assert_eq!(client.query_balance(chain_2).await.unwrap(), 10);

    // Transfer 10 units then 5 back
    client.transfer(10, chain_1, chain_2).await;
    client.transfer(5, chain_2, chain_1).await;

    // Restart last server (dropping it kills the process)
    let validator_4 = local_net.get_mut(3).unwrap();
    validator_4.kill_server(3);
    validator_4.add_server(runner.run_server(4, 3).await);

    // Query balances again
    assert_eq!(client.query_balance(chain_1).await.unwrap(), 5);
    assert_eq!(client.query_balance(chain_2).await.unwrap(), 15);

    // Launch local benchmark using all user chains
    client.benchmark(500).await;

    // Create derived chain
    let (_, chain_3) = client.open_chain(chain_1, None).await.unwrap();

    // Inspect state of derived chain
    assert!(client.check_for_chain_in_wallet(chain_3).await);

    // Create configurations for two more validators
    let server_5 = runner.generate_server_config(5).await.unwrap();
    let server_6 = runner.generate_server_config(6).await.unwrap();

    // Start the validators
    local_net.extend(runner.start_validators(5..7).await);

    // Add validator 5
    client.set_validator(&server_5, 9500, 100).await;

    assert_eq!(client.query_balance(chain_1).await.unwrap(), 5);
    client.query_validators(None).await;
    client.query_validators(Some(chain_1)).await;

    // Add validator 6
    client.set_validator(&server_6, 9600, 100).await;

    // Remove validator 5
    client.remove_validator(&server_5).await;
    local_net.remove(4);

    assert_eq!(client.query_balance(chain_1).await.unwrap(), 5);
    client.query_validators(None).await;
    client.query_validators(Some(chain_1)).await;
}

#[test_log::test(tokio::test)]
async fn test_end_to_end_social_user_pub_sub() {
    let _guard = INTEGRATION_TEST_GUARD.lock().await;

    let network = Network::Grpc;
    let mut runner = TestRunner::new(network);
    let client1 = runner.make_client(network);
    let client2 = runner.make_client(network);
    let n_validators = 4;

    // Create initial server and client config.
    runner.generate_initial_server_config(n_validators).await;
    client1.create_genesis_config().await;
    client2.init().await;

    // Start local network.
    let _local_net = runner.run_local_net(n_validators).await;
    let (contract, service) = runner.build_application("social").await;

    let chain1 = client1.get_wallet().default_chain().unwrap();
    let client2key = client2.keygen().await.unwrap();

    // Open chain on behalf of Client 2.
    let (effect_id, chain2) = client1.open_chain(chain1, Some(client2key)).await.unwrap();

    // Assign chain_2 to client_2_key.
    assert_eq!(chain2, client2.assign(client2key, effect_id).await.unwrap());

    let node_service1 = client1.run_node_service(chain1, 8080).await;
    let node_service2 = client2.run_node_service(chain2, 8081).await;

    let bytecode_id = node_service1.publish_bytecode(contract, service).await;
    let application_id = node_service1.create_application(&bytecode_id).await;

    let app1 = node_service1.make_application(&application_id).await;
    let subscribe = format!("mutation {{ subscribe(chainId: \"{}\") }}", chain2);
    let response = app1.query_application(&subscribe).await;
    let hash = &response["data"];

    // The returned hash should now be the latest one.
    let query = format!("query {{ chain(chainId: \"{chain1}\") {{ tipState {{ blockHash }} }} }}");
    let response = node_service1.query(&query).await;
    assert_eq!(*hash, response["data"]["chain"]["tipState"]["blockHash"]);

    let app2 = node_service2.make_application(&application_id).await;
    let post = "mutation { post(text: \"Linera Social is the new Mastodon!\") }";
    app2.query_application(post).await;

    let query = "query { receivedPostsKeys(count: 5) { author, index } }";
    let expected_response = json!({"data": { "receivedPostsKeys": [
        { "author": chain2, "index": 0 }
    ]}});
    'success: {
        for i in 0..10 {
            tokio::time::sleep(Duration::from_secs(i)).await;
            let response = app1.query_application(query).await;
            if response == expected_response {
                info!("Confirmed post");
                break 'success;
            }
            warn!("Waiting to confirm post");
        }
        panic!("Failed to confirm post");
    }
}
