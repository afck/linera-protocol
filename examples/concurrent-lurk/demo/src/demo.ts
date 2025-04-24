/* eslint-disable no-console */
import * as fs from 'fs';
import assert from 'node:assert';
import { ChildProcess, execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
const LOG_FILE = process.env.LURKSCRIPT_LINERA_LOG_FILE;

// Configuration
const OWNER = process.env.LURKSCRIPT_LINERA_OWNER!;
const CHAIN_ID = process.env.LURKSCRIPT_LINERA_CHAIN_ID!;
assert(OWNER && CHAIN_ID, 'Set LURKSCRIPT_LINERA_OWNER and *_CHAIN_ID');

const CONTRACT_WASM = './assets/concurrent_lurk_contract.wasm';
const SERVICE_WASM = './assets/concurrent_lurk_service.wasm';
const GRAPHQL_PORT = 8082;

const INITIAL_STATE = [1, 1, 1];
const PROOF_BYTES = [1, 0, 1];
const NULL_CHAIN = '0'.repeat(64);

const N = 200;
const BATCH_SIZE = 100;

export function debugLog(message: string): void {
  // const logEntry = `${new Date().toISOString()} - ${message}\n`;
  const logEntry = `  ${message}\n`;

  if (LOG_FILE) {
    fs.appendFileSync(LOG_FILE, logEntry, 'utf8');
  }
}

// A global map of service handles keyed by port.
const SERVICE_HANDLES: Map<number, ChildProcess> = new Map();

export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Spawns a background task that runs the linera service.
 *
 * @param wallet - (Optional) Wallet number.
 * @param port - The port on which the service should run (as a string).
 * @param quiet - If true, suppresses standard output and error.
 * @returns A promise that resolves once the service is started.
 */
export async function lineraService(wallet: number | undefined, port: number, _quiet: boolean): Promise<void> {
  // Construct the command-line arguments.
  // In Rust, the command is built using a helper `linera(wallet)`. Here we assume
  // the executable is named "linera". Adjust accordingly.
  const args: string[] = ['--wait-for-outgoing-messages', 'service', '--port', port.toString()];

  if (wallet !== undefined) {
    args.unshift(`-w${wallet}`);
  }

  // Spawn the linera service process.
  // This is the equivalent of command.spawn() in Rust.
  const child: ChildProcess = spawn('linera', args, {
    env: { ...process.env, RUST_LOG: 'info,linera_core::client=debug' },
    stdio: 'inherit',
  });

  // Save the child handle in the global map keyed by port.
  SERVICE_HANDLES.set(port, child);

  // Wait for 1 second to give the process time to start.
  await sleep(1000);
  debugLog(`// starting linera service on ${port}...`);
}

/**
 * Kills the linera service running on the specified port.
 *
 * @param port - The port on which the service is running.
 * @returns A promise that resolves once the service is (attempted to be) killed.
 */
export async function lineraServiceKill(port: number): Promise<void> {
  const child = SERVICE_HANDLES.get(port);
  if (child) {
    try {
      // In Node.js, child.kill() sends a signal to terminate the process.
      child.kill();
    } catch (error) {
      // eslint-disable-next-line no-console
      console.log(`Error killing service on port ${port}:`, error);
    }
    // Remove the child process handle from the map.
    SERVICE_HANDLES.delete(port);
  } else {
    // eslint-disable-next-line no-console
    console.log(`No service running on port ${port}`);
  }

  debugLog(`// ... killed linera service on ${port}`);

  // Wait for 1 second to allow for cleanup.
  await sleep(1000);
}

async function lineraCreate(
  wallet: number | undefined,
  chainId: string,
  contract: string,
  service: string,
): Promise<string> {
  const args: string[] = ['--wait-for-outgoing-messages', 'publish-and-create', contract, service, chainId];
  if (wallet !== undefined) {
    args.unshift(`-w${wallet}`);
  }

  const { stdout } = await execFileAsync('linera', args);
  return stdout.trim();
}

// Ultra-simple GraphQL client using plain fetch
async function gqlRequest(url: string, query: string, variables = {}, timeoutMs = 100000) {
  // Create an AbortController for timeout management
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(url, {
      body: JSON.stringify({ query, variables }),
      headers: { 'Content-Type': 'application/json' },
      method: 'POST',
      signal: controller.signal,
    });

    const text = await response.text();

    // Try to parse as JSON, fall back to raw text if needed
    try {
      const data = JSON.parse(text);

      if (data.errors) {
        throw new Error(`GraphQL errors: ${JSON.stringify(data.errors)}`);
      }

      return data.data;
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
    } catch (e) {
      if (response.ok) {
        return { rawResponse: text };
      }
      throw new Error(`Invalid response: ${text}`);
    }
  } finally {
    clearTimeout(timeoutId);
  }
}

// GraphQL operations with simple fetch
async function publishDataBlob(port: number, chainId: string, bytes: number[]): Promise<string> {
  const query = `
    mutation PublishDataBlob($chainId: ChainId!, $bytes: [Int!]!) {
      publishDataBlob(chainId: $chainId, bytes: $bytes)
    }
  `;

  const url = `http://localhost:${port}/`;
  const result = await gqlRequest(url, query, { bytes, chainId });

  if (result && result.publishDataBlob) {
    return result.publishDataBlob;
  } else if (result && result.rawResponse) {
    // Try to extract hash from raw response
    const match = result.rawResponse.match(/"([0-9a-f]{64})"/);
    if (match) return match[1];
    return result.rawResponse;
  }

  throw new Error(`Unexpected response: ${JSON.stringify(result)}`);
}

async function microchainStart(
  port: number,
  chainId: string,
  applicationId: string,
  owner: string,
  chainState: string,
  post: { kind: string; message: number[]; pid: string },
): Promise<void> {
  const query = `
    mutation Start(
      $owner: String!
      $chainState: String!
      $postKind: String!
      $postMessage: [Int!]!
      $postPid: ChainId!
      $verify: Boolean!
    ) {
      start(
        owner: $owner
        chainState: $chainState
        postKind: $postKind
        postMessage: $postMessage
        postPid: $postPid
        verify: $verify
      )
    }
  `;

  const url = `http://localhost:${port}/chains/${chainId}/applications/${applicationId}`;
  await gqlRequest(url, query, {
    chainState,
    owner,
    postKind: post.kind,
    postMessage: post.message,
    postPid: post.pid,
    verify: false,
  });
}

async function microchainTransition(
  port: number,
  chainId: string,
  applicationId: string,
  chainProof: string,
  pre: { kind: string; message: number[]; pid: string },
  post: { kind: string; message: number[]; pid: string },
): Promise<void> {
  const query = `
    mutation Transition(
      $preKind: String!
      $preMessage: [Int!]!
      $prePid: ChainId!
      $postKind: String!
      $postMessage: [Int!]!
      $postPid: ChainId!
      $chainProof: String!
      $verify: Boolean!
    ) {
      transition(
        preKind: $preKind
        preMessage: $preMessage
        prePid: $prePid
        postKind: $postKind
        postMessage: $postMessage
        postPid: $postPid
        chainProof: $chainProof
        verify: $verify
      )
    }
  `;

  const url = `http://localhost:${port}/chains/${chainId}/applications/${applicationId}`;
  await gqlRequest(url, query, {
    chainProof,
    postKind: post.kind,
    postMessage: post.message,
    postPid: post.pid,
    preKind: pre.kind,
    preMessage: pre.message,
    prePid: pre.pid,
    verify: false,
  });
}

async function queryReady(
  port: number,
  chainId: string,
  applicationId: string,
): Promise<{ chainId: string; messageId: string }> {
  const query = `
    query {
      ready {
        chainId
        messageId
      }
    }
  `;

  const url = `http://localhost:${port}/chains/${chainId}/applications/${applicationId}`;
  const result = await gqlRequest(url, query);

  if (result && result.ready) {
    return result.ready;
  }

  throw new Error(`Unexpected response: ${JSON.stringify(result)}`);
}

// Helper function for retrying operations
// Helper function for retrying operations
async function withRetry<T>(
  operation: () => Promise<T>,
  options: { label?: string; retries?: number; wallet?: number } = {},
): Promise<T> {
  const { label = 'operation', retries = 3, wallet = 1 } = options;

  let lastError: unknown;

  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      if (attempt > 0) {
        console.log(`Retry ${attempt}/${retries} for ${label}...`);

        // Restart the service on each retry
        console.log(`Restarting linera service on port ${GRAPHQL_PORT}...`);
        await lineraServiceKill(GRAPHQL_PORT);
        await lineraService(wallet, GRAPHQL_PORT, false);
      }

      return await operation();
    } catch (error) {
      lastError = error;
      console.error(`Error in ${label} (attempt ${attempt + 1}/${retries + 1}):`, error);
    }
  }

  throw lastError || new Error(`All ${retries + 1} attempts failed for ${label}`);
}

// Main function
async function main() {
  try {
    console.log(`Running ${N} micro‑chain transitions…`);

    // 1. Deploy contract + service
    const appId = await lineraCreate(1, CHAIN_ID, CONTRACT_WASM, SERVICE_WASM);
    await lineraService(1, GRAPHQL_PORT, false);
    console.log('Linera service up:', { appId });

    // 2. Initialize state
    const stateHash = await withRetry(() => publishDataBlob(GRAPHQL_PORT, CHAIN_ID, INITIAL_STATE), {
      label: 'publishDataBlob',
      retries: 5,
    });

    // 3. Start the microchain
    await withRetry(
      () =>
        microchainStart(GRAPHQL_PORT, CHAIN_ID, appId, OWNER, stateHash, {
          kind: 'spawn',
          message: [],
          pid: NULL_CHAIN,
        }),
      { label: 'microchainStart', retries: 5 },
    );

    // 4. Get initial ready state
    let prevReady = await withRetry(() => queryReady(GRAPHQL_PORT, CHAIN_ID, appId), {
      label: 'queryReady',
      retries: 5,
    });

    // 5. Run transitions in batches
    for (let i = 0; i < N; i += BATCH_SIZE) {
      const endIndex = Math.min(i + BATCH_SIZE, N);
      console.log(`Processing batch ${i + 1}-${endIndex} of ${N}...`);

      for (let j = i; j < endIndex; j++) {
        try {
          const proofHash = await withRetry(() => publishDataBlob(GRAPHQL_PORT, CHAIN_ID, PROOF_BYTES), {
            label: `publishDataBlob-${j + 1}`,
            retries: 3,
          });

          await withRetry(
            () =>
              microchainTransition(
                GRAPHQL_PORT,
                CHAIN_ID,
                appId,
                proofHash,
                { kind: 'spawn', message: [], pid: prevReady.chainId },
                { kind: 'spawn', message: [], pid: NULL_CHAIN },
              ),
            { label: `microchainTransition-${j + 1}`, retries: 3 },
          );

          prevReady = await withRetry(() => queryReady(GRAPHQL_PORT, CHAIN_ID, appId), {
            label: `queryReady-${j + 1}`,
            retries: 3,
          });

          console.log(`✓ transition ${j + 1}/${N} completed`);
        } catch (error) {
          console.error(`Error in transition ${j + 1}:`, error);
          j--; // retry this iteration
        }
      }
    }

    console.log('All transitions done. Latest ready:', prevReady);
  } finally {
    // Always clean up at the end
    await lineraServiceKill(GRAPHQL_PORT);
  }
}

// Run the script
main().catch(async (err) => {
  console.error('❌ failed:', err);
  await lineraServiceKill(GRAPHQL_PORT).catch(() => {});
  process.exitCode = 1;
});
