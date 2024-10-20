// Copyright (c) Zefchain Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use async_graphql::{
    futures_util::Stream,
    http::GraphiQLSource,
    parser::types::{DocumentOperations, ExecutableDocument, OperationType},
    Error, Object, Request, ScalarType, Schema, ServerError, SimpleObject, Subscription,
};
use async_graphql_axum::{GraphQLRequest, GraphQLResponse, GraphQLSubscription};
use axum::{
    extract::Path,
    http::{StatusCode, Uri},
    response,
    response::IntoResponse,
    Extension, Router, Server,
};
use futures::{lock::Mutex, StreamExt};
use linera_base::{
    crypto::{CryptoHash, PublicKey},
    data_types::Amount,
    identifiers::{ApplicationId, BytecodeId, ChainId, Owner},
    BcsHexParseError,
};
use linera_chain::ChainStateView;
use linera_core::{
    client::{ChainClient, ValidatorNodeProvider},
    tracker::NotificationTracker,
    worker::{Notification, Reason},
};
use linera_execution::{
    committee::{Committee, Epoch},
    system::{Recipient, SystemChannel, UserData},
    Bytecode, Operation, Query, Response, SystemOperation, UserApplicationDescription,
    UserApplicationId,
};
use linera_storage::Store;
use linera_views::views::ViewError;
use std::{net::SocketAddr, num::NonZeroU16, ops::DerefMut, sync::Arc};
use thiserror::Error as ThisError;
use tower_http::cors::CorsLayer;
use tracing::{debug, error, info, warn};

/// Our root GraphQL query type.
struct QueryRoot<P, S> {
    client: Arc<Mutex<ChainClient<P, S>>>,
    port: NonZeroU16,
}

/// Our root GraphQL subscription type.
struct SubscriptionRoot<P, S> {
    client: Arc<Mutex<ChainClient<P, S>>>,
}

/// Our root GraphQL mutation type.
struct MutationRoot<P, S> {
    client: Arc<Mutex<ChainClient<P, S>>>,
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
    GraphQLServerError { error: String },
    #[error("malformed application response")]
    MalformedApplicationResponse,
}

impl From<ServerError> for NodeServiceError {
    fn from(value: ServerError) -> Self {
        NodeServiceError::GraphQLServerError {
            error: value.to_string(),
        }
    }
}

impl IntoResponse for NodeServiceError {
    fn into_response(self) -> response::Response {
        let tuple = match self {
            NodeServiceError::BcsHexError(e) => (StatusCode::BAD_REQUEST, e.to_string()),
            NodeServiceError::QueryStringError(e) => (StatusCode::BAD_REQUEST, e.to_string()),
            NodeServiceError::BcsError(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            NodeServiceError::JsonError(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            NodeServiceError::Internal(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            NodeServiceError::MalformedApplicationResponse => {
                (StatusCode::INTERNAL_SERVER_ERROR, self.to_string())
            }
            NodeServiceError::MissingOperation
            | NodeServiceError::HeterogeneousOperations
            | NodeServiceError::UnsupportedQueryType => (StatusCode::BAD_REQUEST, self.to_string()),
            NodeServiceError::GraphQLServerError { error } => (StatusCode::BAD_REQUEST, error),
        };
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
    /// Gets a subscription to a stream of `Notification`s for a collection of `ChainId`s.
    async fn notifications(
        &self,
        chain_ids: Vec<ChainId>,
    ) -> Result<impl Stream<Item = Notification>, Error> {
        Ok(self.client.lock().await.subscribe_all(chain_ids).await?)
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
    ) -> Result<CryptoHash, Error> {
        let operation = Operation::System(system_operation);
        let mut client = self.client.lock().await;
        client.process_inbox().await?;
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
    /// Transfers `amount` units of value from the given owner's account to the recipient.
    /// If no owner is given, try to take the units out of the unattributed account.
    async fn transfer(
        &self,
        owner: Option<Owner>,
        recipient: Recipient,
        amount: Amount,
        user_data: Option<UserData>,
    ) -> Result<CryptoHash, Error> {
        let mut client = self.client.lock().await;
        let certificate = client
            .transfer(owner, amount, recipient, user_data.unwrap_or_default())
            .await?;
        Ok(certificate.value.hash())
    }

    /// Claims `amount` units of value from the given owner's account in
    /// the remote `target` chain. Depending on its configuration (see also #464), the
    /// `target` chain may refuse to process the message.
    async fn claim(
        &self,
        owner: Owner,
        target: ChainId,
        recipient: Recipient,
        amount: Amount,
        user_data: Option<UserData>,
    ) -> Result<CryptoHash, Error> {
        let mut client = self.client.lock().await;
        let certificate = client
            .claim(
                owner,
                target,
                recipient,
                amount,
                user_data.unwrap_or_default(),
            )
            .await?;
        Ok(certificate.value.hash())
    }

    /// Creates (or activates) a new chain by installing the given authentication key.
    /// This will automatically subscribe to the future committees created by `admin_id`.
    async fn open_chain(&self, public_key: PublicKey) -> Result<ChainId, Error> {
        let mut client = self.client.lock().await;
        let (effect_id, _) = client.open_chain(public_key).await?;
        Ok(ChainId::child(effect_id))
    }

    /// Closes the chain.
    async fn close_chain(&self) -> Result<CryptoHash, Error> {
        let mut client = self.client.lock().await;
        let certificate = client.close_chain().await?;
        Ok(certificate.value.hash())
    }

    /// Changes the authentication key of the chain.
    async fn change_owner(&self, new_public_key: PublicKey) -> Result<CryptoHash, Error> {
        let operation = SystemOperation::ChangeOwner { new_public_key };
        self.execute_system_operation(operation).await
    }

    /// Changes the authentication key of the chain.
    async fn change_multiple_owners(
        &self,
        new_public_keys: Vec<PublicKey>,
    ) -> Result<CryptoHash, Error> {
        let operation = SystemOperation::ChangeMultipleOwners { new_public_keys };
        self.execute_system_operation(operation).await
    }

    /// (admin chain only) Registers a new committee. This will notify the subscribers of
    /// the admin chain so that they can migrate to the new epoch (by accepting the
    /// notification as an "incoming message" in a next block).
    async fn create_committee(
        &self,
        admin_id: ChainId,
        epoch: Epoch,
        committee: Committee,
    ) -> Result<CryptoHash, Error> {
        let operation = SystemOperation::CreateCommittee {
            admin_id,
            epoch,
            committee,
        };
        self.execute_system_operation(operation).await
    }

    /// Subscribes to a system channel.
    async fn subscribe(
        &self,
        chain_id: ChainId,
        channel: SystemChannel,
    ) -> Result<CryptoHash, Error> {
        let operation = SystemOperation::Subscribe { chain_id, channel };
        self.execute_system_operation(operation).await
    }

    /// Unsubscribes from a system channel.
    async fn unsubscribe(
        &self,
        chain_id: ChainId,
        channel: SystemChannel,
    ) -> Result<CryptoHash, Error> {
        let operation = SystemOperation::Unsubscribe { chain_id, channel };
        self.execute_system_operation(operation).await
    }

    /// (admin chain only) Removes a committee. Once this message is accepted by a chain,
    /// blocks from the retired epoch will not be accepted until they are followed (hence
    /// re-certified) by a block certified by a recent committee.
    async fn remove_committee(&self, admin_id: ChainId, epoch: Epoch) -> Result<CryptoHash, Error> {
        let operation = SystemOperation::RemoveCommittee { admin_id, epoch };
        self.execute_system_operation(operation).await
    }

    /// Publishes a new application bytecode.
    async fn publish_bytecode(
        &self,
        contract: Bytecode,
        service: Bytecode,
    ) -> Result<BytecodeId, Error> {
        let mut client = self.client.lock().await;
        let (bytecode_id, _) = client.publish_bytecode(contract, service).await?;
        Ok(bytecode_id)
    }

    async fn create_application(
        &self,
        bytecode_id: BytecodeId,
        parameters: Vec<u8>,
        initialization_argument: Vec<u8>,
        required_application_ids: Vec<UserApplicationId>,
    ) -> Result<ApplicationId, Error> {
        let mut client = self.client.lock().await;
        let (application_id, _) = client
            .create_application(
                bytecode_id,
                parameters,
                initialization_argument,
                required_application_ids,
            )
            .await?;
        Ok(application_id)
    }
}

#[Object]
impl<P, S> QueryRoot<P, S>
where
    P: ValidatorNodeProvider + Send + Sync + 'static,
    S: Store + Clone + Send + Sync + 'static,
    ViewError: From<S::ContextError>,
{
    async fn chain(
        &self,
        chain_id: Option<ChainId>,
    ) -> Result<Arc<ChainStateView<S::Context>>, Error> {
        Ok(self.client.lock().await.chain_state_view(chain_id).await?)
    }

    async fn applications(
        &self,
        chain_id: Option<ChainId>,
    ) -> Result<Vec<ApplicationOverview>, Error> {
        let applications = self
            .client
            .lock()
            .await
            .chain_state_view(chain_id)
            .await?
            .execution_state
            .list_applications()
            .await?;

        let overviews = applications
            .into_iter()
            .map(|(id, description)| ApplicationOverview::new(id, description, self.port))
            .map(ApplicationOverview::from)
            .collect();

        Ok(overviews)
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
    ) -> Self {
        Self {
            id,
            description,
            link: format!("http://localhost:{}/applications/{}", port.get(), id),
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
    client: Arc<Mutex<ChainClient<P, S>>>,
    port: NonZeroU16,
}

impl<P, S> Clone for NodeService<P, S> {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            port: self.port,
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
    pub fn new(client: ChainClient<P, S>, port: NonZeroU16) -> Self {
        let client = Arc::new(Mutex::new(client));
        Self { client, port }
    }

    fn schema(&self) -> Schema<QueryRoot<P, S>, MutationRoot<P, S>, SubscriptionRoot<P, S>> {
        Schema::build(
            QueryRoot {
                client: self.client.clone(),
                port: self.port,
            },
            MutationRoot {
                client: self.client.clone(),
            },
            SubscriptionRoot {
                client: self.client.clone(),
            },
        )
        .finish()
    }

    /// Runs the node service.
    pub async fn run<C, F>(self, mut context: C, wallet_updater: F) -> Result<(), anyhow::Error>
    where
        for<'a> F:
            (Fn(&'a mut C, &'a mut ChainClient<P, S>) -> futures::future::BoxFuture<'a, ()>) + Send,
    {
        let port = self.port.get();
        let chain_id = self.client.lock().await.chain_id();

        let index_handler = axum::routing::get(graphiql).post(Self::index_handler);
        let applications_handler = axum::routing::get(graphiql).post(Self::application_handler);

        let app = Router::new()
            .route("/", index_handler)
            .route("/applications/:id", applications_handler)
            .route("/ready", axum::routing::get(|| async { "ready!" }))
            .route_service("/ws", GraphQLSubscription::new(self.schema()))
            .layer(Extension(self.clone()))
            // TODO(#551): Provide application authentication.
            .layer(CorsLayer::permissive());

        info!("GraphiQL IDE: http://localhost:{}", port);

        // TODO(#646): Deduplicate with linera.rs synchronize handling.
        let sync_fut = async move {
            let mut notification_stream = self
                .client
                .lock()
                .await
                .subscribe_all(vec![chain_id])
                .await?;
            let mut tracker = NotificationTracker::default();
            while let Some(notification) = notification_stream.next().await {
                debug!("Received notification: {:?}", notification);
                let mut client = self.client.lock().await;
                if tracker.insert(notification.clone()) {
                    if let Err(e) = client.synchronize_and_recompute_balance().await {
                        warn!(
                            "Failed to synchronize and recompute balance for notification {:?} \
                            with error: {:?}",
                            notification, e
                        );
                        // If synchronization failed there is nothing to update validators
                        // about.
                        continue;
                    }
                    match &notification.reason {
                        Reason::NewBlock { .. } => {
                            if let Err(e) = client.update_validators_about_local_chain().await {
                                warn!(
                                    "Failed to update validators about the local chain after \
                                         receiving notification {:?} with error: {:?}",
                                    notification, e
                                );
                            }
                        }
                        Reason::NewMessage { .. } => {
                            if let Err(e) = client.process_inbox().await {
                                warn!(
                                    "Failed to process inbox after receiving new message: {:?} \
                                    with error: {:?}",
                                    notification, e
                                );
                            }
                        }
                    }
                    wallet_updater(&mut context, client.deref_mut()).await;
                }
            }
            Ok::<(), anyhow::Error>(())
        };

        let serve_fut =
            Server::bind(&SocketAddr::from(([127, 0, 0, 1], port))).serve(app.into_make_service());

        let (serve_response, sync_response) = futures::join!(serve_fut, sync_fut);
        serve_response?;
        sync_response?;

        Ok(())
    }

    /// Handles queries for user applications.
    async fn user_application_query(
        &self,
        application_id: UserApplicationId,
        request: &Request,
    ) -> Result<async_graphql::Response, NodeServiceError> {
        let bytes = serde_json::to_vec(&request)?;
        let query = Query::User {
            application_id,
            bytes,
        };
        let response = self.client.lock().await.query_application(&query).await?;
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
    ) -> Result<async_graphql::Response, NodeServiceError> {
        let graphql_response = self.user_application_query(application_id, request).await?;
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

        let mut client = self.client.lock().await;
        client.process_inbox().await?;
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
        Path(application_id): Path<String>,
        service: Extension<Self>,
        request: GraphQLRequest,
    ) -> Result<GraphQLResponse, NodeServiceError> {
        let mut request = request.into_inner();

        let parsed_query = request.parsed_query()?;
        let operation_type = operation_type(parsed_query)?;

        let application_id: UserApplicationId = application_id.parse()?;

        let response = match operation_type {
            OperationType::Query => {
                service
                    .0
                    .user_application_query(application_id, &request)
                    .await?
            }
            OperationType::Mutation => {
                service
                    .0
                    .user_application_mutation(application_id, &request)
                    .await?
            }
            OperationType::Subscription => return Err(NodeServiceError::UnsupportedQueryType),
        };

        Ok(response.into())
    }
}
