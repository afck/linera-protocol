// Copyright (c) Zefchain Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::chain_listener::{ChainListener, ChainListenerConfig, ClientContext};
use async_graphql::{
    futures_util::Stream,
    http::GraphiQLSource,
    parser::types::{DocumentOperations, ExecutableDocument, OperationType},
    Error, MergedObject, Object, Request, ScalarType, Schema, ServerError, SimpleObject,
    Subscription,
};
use async_graphql_axum::{GraphQLRequest, GraphQLResponse, GraphQLSubscription};
use axum::{
    extract::Path,
    http::{StatusCode, Uri},
    response,
    response::IntoResponse,
    Extension, Router, Server,
};
use futures::{
    future,
    lock::{Mutex, MutexGuard, OwnedMutexGuard},
};
use linera_base::{
    crypto::{CryptoError, CryptoHash, PublicKey},
    data_types::Amount,
    identifiers::{ApplicationId, BytecodeId, ChainId, Owner},
    BcsHexParseError,
};
use linera_chain::{data_types::HashedValue, ChainStateView};
use linera_core::{
    client::{ChainClient, ValidatorNodeProvider},
    worker::Notification,
};
use linera_execution::{
    committee::{Committee, Epoch},
    system::{AdminOperation, Recipient, SystemChannel, UserData},
    Bytecode, Operation, Query, Response, SystemOperation, UserApplicationDescription,
    UserApplicationId,
};
use linera_storage::Store;
use linera_views::views::ViewError;
use serde_json::json;
use std::{collections::BTreeMap, net::SocketAddr, num::NonZeroU16, sync::Arc};
use thiserror::Error as ThisError;
use tower_http::cors::CorsLayer;
use tracing::{debug, error, info};

#[derive(SimpleObject, Clone)]
pub struct Chains {
    pub list: Vec<ChainId>,
    pub default: Option<ChainId>,
}

pub(crate) type ClientMapInner<P, S> = BTreeMap<ChainId, Arc<Mutex<ChainClient<P, S>>>>;
pub(crate) struct ClientMap<P, S>(Arc<Mutex<ClientMapInner<P, S>>>);

impl<P, S> Clone for ClientMap<P, S> {
    fn clone(&self) -> Self {
        ClientMap(self.0.clone())
    }
}

impl<P, S> Default for ClientMap<P, S> {
    fn default() -> Self {
        Self(Arc::new(Mutex::new(BTreeMap::new())))
    }
}

impl<P, S> ClientMap<P, S> {
    async fn client(&self, chain_id: &ChainId) -> Option<Arc<Mutex<ChainClient<P, S>>>> {
        Some(self.0.lock().await.get(chain_id)?.clone())
    }

    pub(crate) async fn client_lock(
        &self,
        chain_id: &ChainId,
    ) -> Option<OwnedMutexGuard<ChainClient<P, S>>> {
        Some(self.client(chain_id).await?.lock_owned().await)
    }

    pub(crate) async fn map_lock(&self) -> MutexGuard<ClientMapInner<P, S>> {
        self.0.lock().await
    }
}

/// Our root GraphQL query type.
struct QueryRoot<P, S> {
    clients: ClientMap<P, S>,
    port: NonZeroU16,
    chains: Chains,
}

/// Our root GraphQL subscription type.
struct SubscriptionRoot<P, S> {
    clients: ClientMap<P, S>,
}

/// Our root GraphQL mutation type.
struct MutationRoot<P, S> {
    clients: ClientMap<P, S>,
}

#[derive(Debug, ThisError)]
enum NodeServiceError {
    #[error(transparent)]
    BcsHexError(#[from] BcsHexParseError),
    #[error("could not decode query string")]
    QueryStringError(#[from] hex::FromHexError),
    #[error(transparent)]
    BcsError(#[from] bcs::Error),
    #[error(transparent)]
    JsonError(#[from] serde_json::Error),
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
    #[error("missing graphql operation")]
    MissingOperation,
    #[error("unsupported query type: subscription")]
    UnsupportedQueryType,
    #[error("graphql operations of different types submitted")]
    HeterogeneousOperations,
    #[error("failed to parse graphql query: {error}")]
    GraphQLParseError { error: String },
    #[error("malformed application response")]
    MalformedApplicationResponse,
    #[error("application service error")]
    ApplicationServiceError { errors: Vec<String> },
    #[error("chain ID not found")]
    UnknownChainId,
    #[error("malformed chain ID")]
    InvalidChainId(CryptoError),
}

impl From<ServerError> for NodeServiceError {
    fn from(value: ServerError) -> Self {
        NodeServiceError::GraphQLParseError {
            error: value.to_string(),
        }
    }
}

impl IntoResponse for NodeServiceError {
    fn into_response(self) -> response::Response {
        let tuple = match self {
            NodeServiceError::BcsHexError(e) => (StatusCode::BAD_REQUEST, vec![e.to_string()]),
            NodeServiceError::QueryStringError(e) => (StatusCode::BAD_REQUEST, vec![e.to_string()]),
            NodeServiceError::BcsError(e) => {
                (StatusCode::INTERNAL_SERVER_ERROR, vec![e.to_string()])
            }
            NodeServiceError::JsonError(e) => {
                (StatusCode::INTERNAL_SERVER_ERROR, vec![e.to_string()])
            }
            NodeServiceError::Internal(e) => {
                (StatusCode::INTERNAL_SERVER_ERROR, vec![e.to_string()])
            }
            NodeServiceError::MalformedApplicationResponse => {
                (StatusCode::INTERNAL_SERVER_ERROR, vec![self.to_string()])
            }
            NodeServiceError::MissingOperation
            | NodeServiceError::HeterogeneousOperations
            | NodeServiceError::UnsupportedQueryType => {
                (StatusCode::BAD_REQUEST, vec![self.to_string()])
            }
            NodeServiceError::GraphQLParseError { error } => (StatusCode::BAD_REQUEST, vec![error]),
            NodeServiceError::ApplicationServiceError { errors } => {
                (StatusCode::BAD_REQUEST, errors)
            }
            NodeServiceError::UnknownChainId => (
                StatusCode::BAD_REQUEST,
                vec!["unknown chain ID".to_string()],
            ),
            NodeServiceError::InvalidChainId(_) => (
                StatusCode::BAD_REQUEST,
                vec!["invalid chain ID".to_string()],
            ),
        };
        let tuple = (tuple.0, json!({"error": tuple.1}).to_string());
        tuple.into_response()
    }
}

#[Subscription]
impl<P, S> SubscriptionRoot<P, S>
where
    P: ValidatorNodeProvider + Send + Sync + 'static,
    S: Store + Clone + Send + Sync + 'static,
    ViewError: From<S::ContextError>,
{
    /// Subscribes to notifications from the current chain.
    async fn notifications(
        &self,
        chain_id: ChainId,
    ) -> Result<impl Stream<Item = Notification>, Error> {
        let Some(client) = self.clients.client(&chain_id).await else {
            return Err(Error::new("Unknown chain ID"));
        };
        Ok(ChainClient::listen(client).await?)
    }
}

impl<P, S> MutationRoot<P, S>
where
    P: ValidatorNodeProvider + Send + Sync + 'static,
    S: Store + Clone + Send + Sync + 'static,
    ViewError: From<S::ContextError>,
{
    async fn execute_system_operation(
        &self,
        system_operation: SystemOperation,
        chain_id: ChainId,
    ) -> Result<CryptoHash, Error> {
        let Some(mut client) = self.clients.client_lock(&chain_id).await else {
            return Err(Error::new("Unknown chain ID"));
        };
        let operation = Operation::System(system_operation);
        Ok(client.execute_operation(operation).await?.value.hash())
    }
}

#[Object]
impl<P, S> MutationRoot<P, S>
where
    P: ValidatorNodeProvider + Send + Sync + 'static,
    S: Store + Clone + Send + Sync + 'static,
    ViewError: From<S::ContextError>,
{
    /// Processes the inbox and returns the lists of certificate hashes that were created, if any.
    async fn process_inbox(&self, chain_id: ChainId) -> Result<Vec<CryptoHash>, Error> {
        let Some(mut client) = self.clients.client_lock(&chain_id).await else {
            return Err(Error::new("Unknown chain ID"));
        };
        client.synchronize_from_validators().await?;
        let certificates = client.process_inbox().await?;
        let hashes = certificates.into_iter().map(|cert| cert.hash()).collect();
        Ok(hashes)
    }

    /// Transfers `amount` units of value from the given owner's account to the recipient.
    /// If no owner is given, try to take the units out of the unattributed account.
    async fn transfer(
        &self,
        chain_id: ChainId,
        owner: Option<Owner>,
        recipient: Recipient,
        amount: Amount,
        user_data: Option<UserData>,
    ) -> Result<CryptoHash, Error> {
        let Some(mut client) = self.clients.client_lock(&chain_id).await else {
            return Err(Error::new("Unknown chain ID"));
        };
        let certificate = client
            .transfer(owner, amount, recipient, user_data.unwrap_or_default())
            .await?;
        Ok(certificate.hash())
    }

    /// Claims `amount` units of value from the given owner's account in
    /// the remote `target` chain. Depending on its configuration (see also #464), the
    /// `target` chain may refuse to process the message.
    #[allow(clippy::too_many_arguments)]
    async fn claim(
        &self,
        chain_id: ChainId,
        owner: Owner,
        target: ChainId,
        recipient: Recipient,
        amount: Amount,
        user_data: Option<UserData>,
    ) -> Result<CryptoHash, Error> {
        let Some(mut client) = self.clients.client_lock(&chain_id).await else {
            return Err(Error::new("Unknown chain ID"));
        };
        let certificate = client
            .claim(
                owner,
                target,
                recipient,
                amount,
                user_data.unwrap_or_default(),
            )
            .await?;
        Ok(certificate.hash())
    }

    /// Creates (or activates) a new chain by installing the given authentication key.
    /// This will automatically subscribe to the future committees created by `admin_id`.
    async fn open_chain(&self, chain_id: ChainId, public_key: PublicKey) -> Result<ChainId, Error> {
        let Some(mut client) = self.clients.client_lock(&chain_id).await else {
            return Err(Error::new("Unknown chain ID"));
        };
        let (message_id, _) = client.open_chain(public_key).await?;
        Ok(ChainId::child(message_id))
    }

    /// Closes the chain.
    async fn close_chain(&self, chain_id: ChainId) -> Result<CryptoHash, Error> {
        let Some(mut client) = self.clients.client_lock(&chain_id).await else {
            return Err(Error::new("Unknown chain ID"));
        };
        let certificate = client.close_chain().await?;
        Ok(certificate.hash())
    }

    /// Changes the authentication key of the chain.
    async fn change_owner(
        &self,
        chain_id: ChainId,
        new_public_key: PublicKey,
    ) -> Result<CryptoHash, Error> {
        let operation = SystemOperation::ChangeOwner { new_public_key };
        self.execute_system_operation(operation, chain_id).await
    }

    /// Changes the authentication key of the chain.
    async fn change_multiple_owners(
        &self,
        chain_id: ChainId,
        new_public_keys: Vec<PublicKey>,
    ) -> Result<CryptoHash, Error> {
        let operation = SystemOperation::ChangeMultipleOwners { new_public_keys };
        self.execute_system_operation(operation, chain_id).await
    }

    /// (admin chain only) Registers a new committee. This will notify the subscribers of
    /// the admin chain so that they can migrate to the new epoch (by accepting the
    /// notification as an "incoming message" in a next block).
    async fn create_committee(
        &self,
        chain_id: ChainId,
        epoch: Epoch,
        committee: Committee,
    ) -> Result<CryptoHash, Error> {
        let operation =
            SystemOperation::Admin(AdminOperation::CreateCommittee { epoch, committee });
        self.execute_system_operation(operation, chain_id).await
    }

    /// Subscribes to a system channel.
    async fn subscribe(
        &self,
        subscriber_chain_id: ChainId,
        publisher_chain_id: ChainId,
        channel: SystemChannel,
    ) -> Result<CryptoHash, Error> {
        let operation = SystemOperation::Subscribe {
            chain_id: publisher_chain_id,
            channel,
        };
        self.execute_system_operation(operation, subscriber_chain_id)
            .await
    }

    /// Unsubscribes from a system channel.
    async fn unsubscribe(
        &self,
        subscriber_chain_id: ChainId,
        publisher_chain_id: ChainId,
        channel: SystemChannel,
    ) -> Result<CryptoHash, Error> {
        let operation = SystemOperation::Unsubscribe {
            chain_id: publisher_chain_id,
            channel,
        };
        self.execute_system_operation(operation, subscriber_chain_id)
            .await
    }

    /// (admin chain only) Removes a committee. Once this message is accepted by a chain,
    /// blocks from the retired epoch will not be accepted until they are followed (hence
    /// re-certified) by a block certified by a recent committee.
    async fn remove_committee(&self, chain_id: ChainId, epoch: Epoch) -> Result<CryptoHash, Error> {
        let operation = SystemOperation::Admin(AdminOperation::RemoveCommittee { epoch });
        self.execute_system_operation(operation, chain_id).await
    }

    /// Publishes a new application bytecode.
    async fn publish_bytecode(
        &self,
        chain_id: ChainId,
        contract: Bytecode,
        service: Bytecode,
    ) -> Result<BytecodeId, Error> {
        let Some(mut client) = self.clients.client_lock(&chain_id).await else {
            return Err(Error::new("Unknown chain ID"));
        };
        let (bytecode_id, _) = client.publish_bytecode(contract, service).await?;
        Ok(bytecode_id)
    }

    /// Creates a new application.
    async fn create_application(
        &self,
        chain_id: ChainId,
        bytecode_id: BytecodeId,
        parameters: String,
        initialization_argument: String,
        required_application_ids: Vec<UserApplicationId>,
    ) -> Result<ApplicationId, Error> {
        let Some(mut client) = self.clients.client_lock(&chain_id).await else {
            return Err(Error::new("Unknown chain ID"));
        };
        let (application_id, _) = client
            .create_application_untyped(
                bytecode_id,
                parameters.as_bytes().to_vec(),
                initialization_argument.as_bytes().to_vec(),
                required_application_ids,
            )
            .await?;
        Ok(application_id)
    }

    /// Requests a `RegisterApplications` message from another chain so the application can be used
    /// on this one.
    async fn request_application(
        &self,
        chain_id: ChainId,
        application_id: UserApplicationId,
        target_chain_id: Option<ChainId>,
    ) -> Result<CryptoHash, Error> {
        let Some(mut client) = self.clients.client_lock(&chain_id).await else {
            return Err(Error::new("Unknown chain ID"));
        };
        let certificate = client
            .request_application(application_id, target_chain_id)
            .await?;
        Ok(certificate.hash())
    }
}

#[Object]
impl<P, S> QueryRoot<P, S>
where
    P: ValidatorNodeProvider + Send + Sync + 'static,
    S: Store + Clone + Send + Sync + 'static,
    ViewError: From<S::ContextError>,
{
    async fn chain(&self, chain_id: ChainId) -> Result<ChainStateExtendedView<S::Context>, Error> {
        let Some(client) = self.clients.client_lock(&chain_id).await else {
            return Err(Error::new("Unknown chain ID"));
        };
        let view = client.chain_state_view(Some(chain_id)).await?;
        Ok(ChainStateExtendedView::new(view))
    }

    async fn applications(&self, chain_id: ChainId) -> Result<Vec<ApplicationOverview>, Error> {
        let Some(client) = self.clients.client_lock(&chain_id).await else {
            return Err(Error::new("Unknown chain ID"));
        };
        let applications = client
            .chain_state_view(Some(chain_id))
            .await?
            .execution_state
            .list_applications()
            .await?;

        let overviews = applications
            .into_iter()
            .map(|(id, description)| ApplicationOverview::new(id, description, self.port, chain_id))
            .collect();

        Ok(overviews)
    }

    async fn chains(&self) -> Result<Chains, Error> {
        Ok(self.chains.clone())
    }

    async fn block(
        &self,
        hash: Option<CryptoHash>,
        chain_id: ChainId,
    ) -> Result<Option<HashedValue>, Error> {
        let Some(client) = self.clients.client_lock(&chain_id).await else {
            return Ok(None);
        };
        let hash = match hash {
            Some(hash) => Some(hash),
            None => {
                let view = client.chain_state_view(Some(chain_id)).await?;
                view.tip_state.get().block_hash
            }
        };
        if let Some(hash) = hash {
            let block = client.read_value(hash).await?;
            Ok(Some(block))
        } else {
            Ok(None)
        }
    }

    async fn blocks(
        &self,
        from: Option<CryptoHash>,
        chain_id: ChainId,
        limit: Option<u32>,
    ) -> Result<Vec<HashedValue>, Error> {
        let Some(client) = self.clients.client_lock(&chain_id).await else {
            return Ok(vec![]);
        };
        let limit = limit.unwrap_or(10);
        let from = match from {
            Some(from) => Some(from),
            None => {
                let view = client.chain_state_view(Some(chain_id)).await?;
                view.tip_state.get().block_hash
            }
        };
        if let Some(from) = from {
            let values = client.read_values_downward(from, limit).await?;
            Ok(values)
        } else {
            Ok(vec![])
        }
    }
}

// What follows is a hack to add a chain_id field to `ChainStateView` based on
// https://async-graphql.github.io/async-graphql/en/merging_objects.html

struct ChainStateViewExtension(ChainId);

#[Object]
impl ChainStateViewExtension {
    async fn chain_id(&self) -> ChainId {
        self.0
    }
}

#[derive(MergedObject)]
struct ChainStateExtendedView<C>(ChainStateViewExtension, Arc<ChainStateView<C>>)
where
    C: linera_views::common::Context + Clone + Send + Sync + 'static,
    ViewError: From<C::Error>,
    C::Extra: linera_execution::ExecutionRuntimeContext;

impl<C> ChainStateExtendedView<C>
where
    C: linera_views::common::Context + Clone + Send + Sync + 'static,
    ViewError: From<C::Error>,
    C::Extra: linera_execution::ExecutionRuntimeContext,
{
    fn new(view: Arc<ChainStateView<C>>) -> Self {
        Self(ChainStateViewExtension(view.chain_id()), view)
    }
}

#[derive(SimpleObject)]
pub struct ApplicationOverview {
    id: UserApplicationId,
    description: UserApplicationDescription,
    link: String,
}

impl ApplicationOverview {
    fn new(
        id: UserApplicationId,
        description: UserApplicationDescription,
        port: NonZeroU16,
        chain_id: ChainId,
    ) -> Self {
        Self {
            id,
            description,
            link: format!(
                "http://localhost:{}/chains/{}/applications/{}",
                port.get(),
                chain_id,
                id
            ),
        }
    }
}

/// Given a parsed GraphQL query (or `ExecutableDocument`), returns the `OperationType`.
///
/// Errors:
///
/// If we have no `OperationType`s or the `OperationTypes` are heterogeneous, i.e. a query
/// was submitted with a `mutation` and `subscription`.
fn operation_type(document: &ExecutableDocument) -> Result<OperationType, NodeServiceError> {
    match &document.operations {
        DocumentOperations::Single(op) => Ok(op.node.ty),
        DocumentOperations::Multiple(ops) => {
            let mut op_types = ops.values().map(|v| v.node.ty);
            let first = op_types.next().ok_or(NodeServiceError::MissingOperation)?;
            op_types
                .all(|x| x == first)
                .then_some(first)
                .ok_or(NodeServiceError::HeterogeneousOperations)
        }
    }
}

/// Extracts the underlying byte vector from a serialized GraphQL response
/// from an application.
fn bytes_from_response(data: async_graphql::Value) -> Vec<Vec<u8>> {
    if let async_graphql::Value::Object(map) = data {
        map.values()
            .filter_map(|value| {
                if let async_graphql::Value::List(list) = value {
                    bytes_from_list(list)
                } else {
                    None
                }
            })
            .collect()
    } else {
        vec![]
    }
}

fn bytes_from_list(list: &[async_graphql::Value]) -> Option<Vec<u8>> {
    list.iter()
        .map(|item| {
            if let async_graphql::Value::Number(n) = item {
                n.as_u64().map(|n| n as u8)
            } else {
                None
            }
        })
        .collect()
}

/// An HTML response constructing the GraphiQL web page.
async fn graphiql(uri: Uri) -> impl IntoResponse {
    response::Html(
        GraphiQLSource::build()
            .endpoint(uri.path())
            .subscription_endpoint("/ws")
            .finish(),
    )
}

/// The `NodeService` is a server that exposes a web-server to the client.
/// The node service is primarily used to explore the state of a chain in GraphQL.
pub struct NodeService<P, S> {
    clients: ClientMap<P, S>,
    config: ChainListenerConfig,
    port: NonZeroU16,
    chains: Chains,
    storage: S,
}

impl<P, S: Clone> Clone for NodeService<P, S> {
    fn clone(&self) -> Self {
        Self {
            clients: self.clients.clone(),
            config: self.config.clone(),
            port: self.port,
            chains: self.chains.clone(),
            storage: self.storage.clone(),
        }
    }
}

impl<P, S> NodeService<P, S>
where
    P: ValidatorNodeProvider + Send + Sync + 'static,
    S: Store + Clone + Send + Sync + 'static,
    ViewError: From<S::ContextError>,
{
    /// Creates a new instance of the node service given a client chain and a port.
    pub fn new(config: ChainListenerConfig, port: NonZeroU16, chains: Chains, storage: S) -> Self {
        Self {
            clients: ClientMap::default(),
            config,
            port,
            chains,
            storage,
        }
    }

    fn schema(&self) -> Schema<QueryRoot<P, S>, MutationRoot<P, S>, SubscriptionRoot<P, S>> {
        Schema::build(
            QueryRoot {
                clients: self.clients.clone(),
                port: self.port,
                chains: self.chains.clone(),
            },
            MutationRoot {
                clients: self.clients.clone(),
            },
            SubscriptionRoot {
                clients: self.clients.clone(),
            },
        )
        .finish()
    }

    /// Runs the node service.
    pub async fn run<C, F>(self, context: C, wallet_updater: F) -> Result<(), anyhow::Error>
    where
        for<'a> F: (Fn(&'a mut C, &'a mut ChainClient<P, S>) -> futures::future::BoxFuture<'a, ()>)
            + Send
            + Clone,
        C: ClientContext<P>,
    {
        let port = self.port.get();
        let index_handler = axum::routing::get(graphiql).post(Self::index_handler);
        let applications_handler = axum::routing::get(graphiql).post(Self::application_handler);

        let app = Router::new()
            .route("/", index_handler)
            .route(
                "/chains/:chain_id/applications/:application_id",
                applications_handler,
            )
            .route("/ready", axum::routing::get(|| async { "ready!" }))
            .route_service("/ws", GraphQLSubscription::new(self.schema()))
            .layer(Extension(self.clone()))
            // TODO(#551): Provide application authentication.
            .layer(CorsLayer::permissive());

        info!("GraphiQL IDE: http://localhost:{}", port);

        let sync_fut = Box::pin(ChainListener::new(self.config, self.clients.clone()).run(
            context,
            wallet_updater,
            self.storage.clone(),
        ));
        let serve_fut =
            Server::bind(&SocketAddr::from(([127, 0, 0, 1], port))).serve(app.into_make_service());

        match future::select(sync_fut, serve_fut).await {
            future::Either::Left((value, _)) => {
                value?;
                error!("Chain listener was terminated.");
            }
            future::Either::Right((value, _)) => {
                value?;
                error!("Node service was terminated.");
            }
        }

        Ok(())
    }

    /// Handles queries for user applications.
    async fn user_application_query(
        &self,
        application_id: UserApplicationId,
        request: &Request,
        chain_id: ChainId,
    ) -> Result<async_graphql::Response, NodeServiceError> {
        let bytes = serde_json::to_vec(&request)?;
        let query = Query::User {
            application_id,
            bytes,
        };
        let Some(mut client) = self.clients.client_lock(&chain_id).await else {
            return Err(NodeServiceError::UnknownChainId);
        };
        let response = client.query_application(&query).await?;
        let user_response_bytes = match response {
            Response::System(_) => unreachable!("cannot get a system response for a user query"),
            Response::User(user) => user,
        };
        Ok(serde_json::from_slice(&user_response_bytes)?)
    }

    /// Handles mutations for user applications.
    async fn user_application_mutation(
        &self,
        application_id: UserApplicationId,
        request: &Request,
        chain_id: ChainId,
    ) -> Result<async_graphql::Response, NodeServiceError> {
        debug!("Request: {:?}", &request);
        let graphql_response = self
            .user_application_query(application_id, request, chain_id)
            .await?;
        if graphql_response.is_err() {
            let errors = graphql_response
                .errors
                .iter()
                .map(|e| e.to_string())
                .collect();
            return Err(NodeServiceError::ApplicationServiceError { errors });
        }
        debug!("Response: {:?}", &graphql_response);
        let bcs_bytes_list = bytes_from_response(graphql_response.data);
        if bcs_bytes_list.is_empty() {
            return Err(NodeServiceError::MalformedApplicationResponse);
        }
        let operations = bcs_bytes_list
            .into_iter()
            .map(|bytes| Operation::User {
                application_id,
                bytes,
            })
            .collect();

        let Some(mut client) = self.clients.client_lock(&chain_id).await else {
            return Err(NodeServiceError::UnknownChainId);
        };
        let hash = client.execute_operations(operations).await?.value.hash();
        Ok(async_graphql::Response::new(hash.to_value()))
    }

    /// Executes a GraphQL query and generates a response for our `Schema`.
    async fn index_handler(service: Extension<Self>, request: GraphQLRequest) -> GraphQLResponse {
        service
            .0
            .schema()
            .execute(request.into_inner())
            .await
            .into()
    }

    /// Executes a GraphQL query against an application.
    /// Pattern matches on the `OperationType` of the query and routes the query
    /// accordingly.
    async fn application_handler(
        Path((chain_id, application_id)): Path<(String, String)>,
        service: Extension<Self>,
        request: GraphQLRequest,
    ) -> Result<GraphQLResponse, NodeServiceError> {
        let mut request = request.into_inner();

        let parsed_query = request.parsed_query()?;
        let operation_type = operation_type(parsed_query)?;

        let chain_id: ChainId = chain_id.parse().map_err(NodeServiceError::InvalidChainId)?;
        let application_id: UserApplicationId = application_id.parse()?;

        let response = match operation_type {
            OperationType::Query => {
                service
                    .0
                    .user_application_query(application_id, &request, chain_id)
                    .await?
            }
            OperationType::Mutation => {
                service
                    .0
                    .user_application_mutation(application_id, &request, chain_id)
                    .await?
            }
            OperationType::Subscription => return Err(NodeServiceError::UnsupportedQueryType),
        };

        Ok(response.into())
    }
}
