import { isObolDVTService } from "@/share/ObolDVTServices";
import * as log from "electron-log";
import YAML from "yaml";
import { validatorPorts } from "./ethereum-services/ServicePort.js";
import { StringUtils } from "./StringUtils.js";
import { parseKeystore, checkSlashingProtection, hasDoppelgangerProtection } from "@/share/keystores";
import { exitBlocker, beaconBlocker, checkSignedExit } from "@/share/exits";
import {
  SIGNER_PATH_KEYS,
  normalizeSignerUrl,
  prysmSignerFlags,
  prysmSignerPlan,
  withPrysmSignerFlags,
  tekuSignerPlan,
  withTekuSignerFlag,
} from "@/share/remoteKeys";
import { ServiceVolume } from "./ethereum-services/ServiceVolume.js";
import { GROUP_ID } from "@/share/keyGroups";
import { csmQueueMap } from "@/share/validatorStatus";
import { chainClock, nextPeriodStart, attestationSummary, syncSummary } from "@/share/validatorDuties";
import { getSigningKeysWithQueueInfo } from "./web3/CSM.js";

// Validator clients that hold keystores themselves (keymanager API)
const KEYSTORE_CLIENTS = [
  "LighthouseValidatorService",
  "PrysmValidatorService",
  "NimbusValidatorService",
  "TekuValidatorService",
  "LodestarValidatorService",
];
const PUBKEY = /^0x[0-9a-f]{96}$/;
const STATES_CHUNK = 500;
const STATES_MARKER = "=====STEREUM_VALIDATOR_STATES";
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const KEYMANAGER_BATCH = 200;
// keys per DELETE: large deletes made validator clients run out of memory (curl exit 52)
const REMOVE_CHUNK = 100;
const SLASHING_DIR = "/etc/stereum/slashing-protection";
// keystores per import request: the client decrypts each one, which is slow for many at once
const IMPORT_CHUNK = 50;
// keys signed and broadcast per exec pair
const EXIT_CHUNK = 100;
const HTTP_MARKER = "=====STEREUM_HTTP";
const HTTP_WRITE_OUT = `write-out = "\\n${HTTP_MARKER} %{http_code}\\n"`;
// remote keys per POST /eth/v1/remotekeys
const REMOTE_IMPORT_CHUNK = 100;
// a client restarted with remote signer flags is polled until its keymanager API answers
const RESTART_READY_TIMEOUT_MS = 90000;
const RESTART_POLL_MS = 5000;
const PRYSM_WALLETS = "/opt/app/data/wallets";
const KEYS_FILE = "/etc/stereum/keys.yaml";
const KEYS_MARKER = "=====STEREUM_KEYS";
// bytes per exec: sshd hands the whole command to the shell as one argv string, capped at 128 KiB on Linux
const KEYS_CHUNK = 65536;
const KEY_FIELDS = ["keyName", "groupName", "groupID", "validatorClientID"];
const KEY_PATCH_MAX = 50000;
// eslint-disable-next-line no-control-regex
const CONTROL_CHARS = /[\u0000-\u001f\u007f]/;
const INDEX = /^\d{1,12}$/;
const BEACON_MARKER = "=====STEREUM_BEACON_BATCH";
const INDEX_CHUNK = 1000;
// bytes per beacon batch exec: sshd runs it as one sh -c argument, and Linux caps one argument at 128 KiB
const EXEC_BUDGET = 64 * 1024;
const MAX_SLOTS = 64;
// a sync committee has 512 members
const SYNC_COMMITTEE_SIZE = 512;
const CSM_CACHE_MS = 5 * 60000;
const UNSUPPORTED = [404, 405, 501];

// lowercased, unique and valid public keys, so nothing else reaches a command
const cleanKeys = (list) => [...new Set((list || []).map((p) => String(p).toLowerCase()))].filter((p) => PUBKEY.test(p));
// unique validator indices as strings, only digits reach a command
const cleanIndices = (list) => [...new Set((Array.isArray(list) ? list : []).map((i) => String(i)))].filter((i) => INDEX.test(i));
const epochOrSlot = (x) => Number.isSafeInteger(x) && x >= 0;
const chunked = (list, size) => Array.from({ length: Math.ceil(list.length / size) }, (_, i) => list.slice(i * size, (i + 1) * size));
// every answer of a kind is 404/405/501 without data: the beacon node does not serve that endpoint
const allUnsupported = (answers) => answers.length > 0 && answers.every((a) => UNSUPPORTED.includes(a.status) && !a.body?.data);

// Backend of the validators page (the staking page rebuild). It works on top of Monitoring so it
// shares its service snapshot, beacon resolution and DV key lookup instead of reading them again.
export class Validators {
  constructor(monitoring) {
    this.monitoring = monitoring;
    this.nodeConnection = monitoring.nodeConnection;
    this.specByBase = {};
  }

  // per-server caches: a beacon on the same local port of another server has another chain
  reset() {
    this.specByBase = {};
    this.csmCache = null;
  }

  // one CSM lookup at a time, shared with the old staking page: two runs would close each other's RPC tunnels
  csmSigningKeys() {
    this.csmPromise ??= getSigningKeysWithQueueInfo(this.monitoring).finally(() => (this.csmPromise = null));
    return this.csmPromise;
  }

  /**
   * One holder per key-holding service, with the role that decides what its keys are:
   * - validator: a validator client with its own keystores
   * - share: a validator client behind Charon/Pluto, its keys are shares and not on chain
   * - distributed: Charon/Pluto, holding the cluster's distributed validator keys
   * - ssv: an SSV node, its validators come from the SSV network
   * - signer: Web3Signer, holding keys other validator clients use remotely
   */
  static classifyHolders(serviceInfos = []) {
    return serviceInfos
      .map((info) => {
        const base = { id: info.config?.serviceID, service: info.service, network: info.config?.network, state: info.state };
        if (isObolDVTService(info.service)) return { ...base, role: "distributed" };
        if (info.service === "SSVNetworkService") return { ...base, role: "ssv" };
        if (info.service === "Web3SignerService") return { ...base, role: "signer" };
        if (!KEYSTORE_CLIENTS.includes(info.service)) return null;
        const dvt = (info.config?.dependencies?.consensusClients || []).find((d) => isObolDVTService(d.service));
        // only to explain Prysm's signer mode in the UI, the backend checks again before writing
        if (info.service === "PrysmValidatorService") base.signerUrl = prysmSignerFlags(info.config?.command).url;
        return dvt ? { ...base, role: "share", dvtVia: dvt.id } : { ...base, role: "validator" };
      })
      .filter((holder) => holder?.id);
  }

  async getValidatorHolders() {
    return Validators.classifyHolders(await this.monitoring.getServiceInfos());
  }

  /**
   * Keys of one holder: [{ pubkey, remote }]. Read straight from the client (or the cluster lock /
   * SSV network for DVT holders), without the task panel entries the staking page listing creates.
   */
  async listHolderKeys(serviceID) {
    try {
      const holder = (await this.getValidatorHolders()).find((h) => h.id === serviceID);
      if (!holder) throw new Error("no validator service " + serviceID);
      const vam = this.monitoring.validatorAccountManager;

      if (holder.role === "distributed" || holder.role === "ssv") {
        const dvs = await vam.getDVTKeys(serviceID);
        const keys = dvs.map((dv) => ({
          pubkey: (holder.role === "distributed" ? dv.distributed_public_key : "0x" + dv.public_key).toLowerCase(),
          remote: false,
        }));
        return { code: 0, keys };
      }

      const client = await this.nodeConnection.readServiceConfiguration(serviceID);
      // Prysm answers an error for keystores in remote signer mode and for remote keys in local mode
      const prysm = client.service === "PrysmValidatorService";
      const prysmRemote = prysm && !!prysmSignerFlags(client.command).url;
      const keystores = prysmRemote ? [] : await this.keymanagerList(vam, client, "/eth/v1/keystores");
      const keys = keystores.map((k) => ({ pubkey: k.validating_pubkey.toLowerCase(), remote: !!k.readonly }));
      if (holder.role !== "signer" && (!prysm || prysmRemote)) {
        for (const k of await this.keymanagerList(vam, client, "/eth/v1/remotekeys")) {
          const pubkey = k.pubkey.toLowerCase();
          const url = typeof k.url === "string" && k.url ? { url: k.url } : {};
          // Lighthouse lists Web3Signer keys as readonly keystores too
          const existing = keys.find((key) => key.pubkey === pubkey);
          if (existing) Object.assign(existing, url);
          else keys.push({ pubkey, remote: true, ...url });
        }
      }
      return { code: 0, keys };
    } catch (err) {
      log.error("Listing validator keys of " + serviceID + " failed: ", err);
      return { code: 1, info: String(err?.message || err), keys: [] };
    }
  }

  /**
   * Fee recipient a validator client uses for one key, read without a task panel entry since the
   * drawer asks every time a key is opened. Returns { code, address } or { code, info }.
   */
  async getFeeRecipient(serviceID, pubkey) {
    try {
      if (!PUBKEY.test(String(pubkey).toLowerCase())) throw new Error("invalid public key");
      const client = await this.nodeConnection.readServiceConfiguration(serviceID);
      const result = await this.monitoring.validatorAccountManager.keymanagerAPI(client, "GET", `/eth/v1/validator/${pubkey}/feerecipient`);
      const data = Validators.parseJson(result.stdout);
      if (!data?.data?.ethaddress) throw new Error(data?.message || result.stderr || "no fee recipient returned");
      return { code: 0, address: data.data.ethaddress };
    } catch (err) {
      log.error("Reading the fee recipient of " + pubkey + " failed: ", err);
      return { code: 1, info: String(err?.message || err) };
    }
  }

  /**
   * Run many keymanager requests in one exec: a single curl container reads one config block per
   * request from stdin (so the token never shows up in a process list) and prints each status code.
   * requests: [{ method, path, body }]. Returns the HTTP status per request, in order (0 if missing).
   */
  async keymanagerBatch(serviceID, requests) {
    const { base, token, tls, curlTag } = await this.keymanagerTarget(serviceID);
    const statuses = [];
    for (let i = 0; i < requests.length; i += KEYMANAGER_BATCH) {
      const blocks = requests
        .slice(i, i + KEYMANAGER_BATCH)
        .map((r) => Validators.curlBlock(base, token, tls, r, [`output = "/dev/null"`, `write-out = "%{http_code}\\n"`]));
      const cmd = `docker run --rm -i --network=stereum curlimages/curl:${curlTag} -K - <<'=====KEYMANAGER'\n${blocks.join("\nnext\n")}\n=====KEYMANAGER`;
      const result = await this.nodeConnection.sshService.exec(cmd);
      const codes = result.stdout.split("\n").filter((l) => /^\d{3}$/.test(l.trim()));
      for (let j = 0; j < blocks.length; j++) statuses.push(parseInt(codes[j]) || 0);
    }
    return statuses;
  }

  // Where and how a validator client's keymanager API is reached: { base, token, tls, curlTag }
  async keymanagerTarget(serviceID) {
    const client = await this.nodeConnection.readServiceConfiguration(serviceID);
    const token = await this.monitoring.validatorAccountManager.getApiToken(client);
    const curlTag = await this.nodeConnection.ensureCurlImage();
    const tls = client.service.includes("Teku");
    const base = `${tls ? "https" : "http"}://stereum-${client.id}:${validatorPorts[client.service]}`;
    return { base, token, tls, curlTag };
  }

  /**
   * Many keymanager requests whose answers are needed, in KEYMANAGER_BATCH requests per exec with the
   * token only in the stdin config. Returns [{ status, body }] in request order.
   */
  async keymanagerCalls(serviceID, requests) {
    const { base, token, tls, curlTag } = await this.keymanagerTarget(serviceID);
    const prefix = `docker run --rm -i --network=stereum curlimages/curl:${curlTag}`;
    const results = [];
    for (let i = 0; i < requests.length; i += KEYMANAGER_BATCH) {
      const blocks = requests.slice(i, i + KEYMANAGER_BATCH).map((r) => Validators.curlBlock(base, token, tls, r, [HTTP_WRITE_OUT]));
      results.push(...(await this.curlConfigRun(prefix, blocks)));
    }
    return results;
  }

  // Run curl config blocks (built with HTTP_WRITE_OUT) read from stdin, so nothing goes on argv
  async curlConfigRun(prefix, blocks) {
    const result = await this.nodeConnection.sshService.exec(`${prefix} -K - <<'=====CURLCFG'\n${blocks.join("\nnext\n")}\n=====CURLCFG`);
    return Validators.splitMarked(result.stdout, blocks.length);
  }

  // Output of HTTP_WRITE_OUT requests -> [{ status, body }] in order; curl prints 000 for a failed transfer
  static splitMarked(stdout, count) {
    const text = String(stdout ?? "");
    const marker = new RegExp(`\\n?${HTTP_MARKER} (\\d+)(?:\\n|$)`, "g");
    const results = [];
    let last = 0;
    let match;
    while (results.length < count && (match = marker.exec(text)) !== null) {
      const body = text.slice(last, match.index).trim();
      results.push({ status: parseInt(match[1]) || 0, body: body ? Validators.parseJson(body) : null });
      last = marker.lastIndex;
    }
    while (results.length < count) results.push({ status: 0, body: null });
    return results;
  }

  // Config file lines for one keymanager request, read by curl from stdin
  static curlBlock(base, token, tls, { method, path, body }, extra = []) {
    const value = (v) => `"${String(v).replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
    return [
      `url = ${value(base + path)}`,
      `request = ${value(method)}`,
      `header = "Content-Type: application/json"`,
      token ? `header = ${value("Authorization: Bearer " + token)}` : "",
      body ? `data = ${value(JSON.stringify(body))}` : "",
      "silent",
      tls ? "insecure" : "",
      ...extra,
    ]
      .filter(Boolean)
      .join("\n");
  }

  // One keymanager request whose answer is needed, with the token passed on stdin: { status, rc, body, stderr }
  async keymanagerRequest(serviceID, request) {
    const { base, token, tls, curlTag } = await this.keymanagerTarget(serviceID);
    const block = Validators.curlBlock(base, token, tls, request, [`write-out = "\\n%{http_code}"`]);
    return this.curlRequest(block, curlTag);
  }

  // One curl config block (ending with write-out "\n%{http_code}") run from the stereum network, read from stdin
  async curlRequest(block, curlTag = null) {
    const tag = curlTag ?? (await this.nodeConnection.ensureCurlImage());
    const result = await this.nodeConnection.sshService.exec(
      `docker run --rm -i --network=stereum curlimages/curl:${tag} -K - <<'=====KEYMANAGER'\n${block}\n=====KEYMANAGER`
    );
    const lines = String(result.stdout ?? "")
      .trimEnd()
      .split("\n");
    const status = parseInt(lines.pop()) || 0;
    return { status, rc: result.rc, body: Validators.parseJson(lines.join("\n")), stderr: result.stderr };
  }

  // Why a curl request failed, from curl's exit code or the answer
  static curlFailure(rc, status, body) {
    if (rc === 6) return "host not found";
    if (rc === 7) return "connection refused";
    if (rc === 28) return "timed out";
    if ([35, 51, 58, 60].includes(rc)) return "TLS error";
    if (rc === 52) return "validator client ran out of memory";
    return body?.message || `HTTP ${status}`;
  }

  /**
   * Public keys a Web3Signer holds, read from the stereum network like the validator client will:
   * signerId for a Web3Signer on this node, url for any other. Returns { code, url, keys } or { code, info }.
   */
  async listSignerKeys({ signerId = null, url = null } = {}) {
    try {
      let base;
      if (signerId) {
        const holder = (await this.getValidatorHolders()).find((h) => h.id === signerId);
        if (holder?.role !== "signer") return { code: 1, info: "no Web3Signer " + signerId };
        base = `http://stereum-${holder.id}:9000`;
      } else {
        const normalized = normalizeSignerUrl(url);
        if (normalized.error) return { code: 1, info: "invalid url: " + normalized.error };
        base = normalized.url;
      }
      // the public keys endpoint needs no token and works for local and remote signers alike; no insecure, like the client
      const block = Validators.curlBlock(base, null, false, { method: "GET", path: SIGNER_PATH_KEYS }, [
        `write-out = "\\n%{http_code}"`,
        "connect-timeout = 5",
        "max-time = 20",
        `proto = "=http,https"`,
      ]);
      const { status, rc, body } = await this.curlRequest(block);
      // the url still comes back, so keys can be added by hand when the list cannot be read
      if (status !== 200 || !Array.isArray(body)) return { code: 2, info: Validators.curlFailure(rc, status, body), url: base };
      const keys = [...new Set(body.map((k) => String(k).toLowerCase()))].filter((k) => PUBKEY.test(k));
      return { code: 0, url: base, keys };
    } catch (err) {
      log.error("Listing the signer keys failed: ", err);
      return { code: 2, info: String(err?.message || err) };
    }
  }

  /**
   * Remove keys from a validator client. local: keystores (their slashing protection is exported),
   * remote: remote keys. Deleted in chunks; the slashing protection of all chunks is merged into one
   * EIP-3076 file, returned and also kept on the node so it is not lost if the download is skipped.
   * Returns { code, results: { pubkey: status }, slashingProtection, savedTo } or { code, info }.
   */
  async removeKeys(serviceID, { local = [], remote = [] } = {}) {
    const localKeys = cleanKeys(local);
    const remoteKeys = cleanKeys(remote);
    if (!localKeys.length && !remoteKeys.length) return { code: 1, info: "no valid keys" };

    const ref = StringUtils.createRandomString();
    const task = `Removing ${localKeys.length + remoteKeys.length} keys`;
    this.nodeConnection.taskManager?.otherTasksHandler(ref, task);
    const results = {};
    let interchange = null;
    try {
      for (const [keys, path] of [
        [localKeys, "/eth/v1/keystores"],
        [remoteKeys, "/eth/v1/remotekeys"],
      ]) {
        for (let i = 0; i < keys.length; i += REMOVE_CHUNK) {
          const chunk = keys.slice(i, i + REMOVE_CHUNK);
          const { status, rc, body } = await this.keymanagerRequest(serviceID, { method: "DELETE", path, body: { pubkeys: chunk } });
          if (!Array.isArray(body?.data)) {
            const reason = Validators.curlFailure(rc, status, body);
            chunk.forEach((key) => (results[key] = "error: " + reason));
            continue;
          }
          // the answer lists one status per requested key, in request order
          chunk.forEach((key, j) => (results[key] = body.data[j]?.status ?? "error"));
          if (body.slashing_protection) interchange = Validators.mergeInterchange(interchange, body.slashing_protection);
        }
      }

      let savedTo = null;
      if (interchange) {
        savedTo = `${SLASHING_DIR}/${serviceID}-${Date.now()}.json`;
        const write = await this.nodeConnection.sshService.exec(
          `mkdir -p ${SLASHING_DIR} && cat > ${savedTo} <<'=====SLASHING'\n${JSON.stringify(interchange)}\n=====SLASHING`
        );
        if (write.rc != 0) savedTo = null;
      }

      const failed = Object.entries(results).filter(([, status]) => String(status).startsWith("error"));
      this.nodeConnection.taskManager?.otherTasksHandler(
        ref,
        task,
        !failed.length,
        failed.length ? failed.map(([key, status]) => `${key}: ${status}`).join("\n") : ""
      );
      return { code: 0, results, slashingProtection: interchange ? JSON.stringify(interchange, null, 2) : null, savedTo };
    } catch (err) {
      log.error(task + " failed: ", err);
      this.nodeConnection.taskManager?.otherTasksHandler(ref, task, false, String(err?.message || err));
      return { code: 2, info: String(err?.message || err), results };
    } finally {
      this.nodeConnection.taskManager?.otherTasksHandler(ref);
    }
  }

  /**
   * What the user has to know before keys are imported into a validator client:
   * - alreadyImported: keys this client holds already (the client skips them as duplicates)
   * - onChain: { pubkey: { index, status } } for keys the beacon node knows
   * - live: active keys that attested in the last epoch, so they run somewhere else right now
   * - genesisRoot: to check that a slashing protection file belongs to this chain
   * - doppelganger: whether the client holds new keys back for a few epochs
   * - remoteSigner (with remoteUrl): { mode: "ready" | "switch" | "blocked", reason? }, see prysmSignerPlan
   */
  async prepareImport(serviceID, pubkeys = [], { remoteUrl = null } = {}) {
    try {
      const holder = (await this.getValidatorHolders()).find((h) => h.id === serviceID);
      const roles = remoteUrl ? ["validator"] : ["validator", "signer"];
      if (!holder || !roles.includes(holder.role)) throw new Error("keys cannot be imported into this service");
      const signer = remoteUrl ? normalizeSignerUrl(remoteUrl) : null;
      if (signer?.error) return { code: 1, info: "invalid url: " + signer.error };
      const keys = cleanKeys(pubkeys);

      const info = (await this.monitoring.getServiceInfos()).find((i) => i.config?.serviceID === serviceID);
      const prysm = info?.service === "PrysmValidatorService";
      if (prysm && !signer && prysmSignerFlags(info.config?.command).url) {
        return { code: 1, info: "Prysm runs in remote signer mode and cannot import keystores" };
      }

      const listed = await this.listHolderKeys(serviceID);
      // a failed listing would make Prysm look empty and switch it
      if (prysm && signer && listed.code) throw new Error(listed.info);
      const present = new Set(listed.keys.map((k) => k.pubkey));
      let remoteSigner;
      if (signer) {
        remoteSigner = prysm
          ? prysmSignerPlan({
              command: info.config?.command,
              localCount: listed.keys.filter((k) => !k.remote).length,
              remoteCount: listed.keys.filter((k) => k.remote).length,
              url: signer.url,
            })
          : info?.service === "TekuValidatorService"
            ? tekuSignerPlan(info.config?.command)
            : { mode: "ready" };
      }
      const states = keys.length ? await this.getValidatorStates(keys, serviceID) : { code: 0, byPubkey: {} };
      const beacon = await this.findHolderBeacon(serviceID);
      const genesis = beacon.code ? null : await this.monitoring.queryBeaconApi(beacon.data.url, "/eth/v1/beacon/genesis");

      // liveness of the previous epoch: an attestation there means the key validates somewhere already
      const live = [];
      const activeIndices = Object.values(states.byPubkey ?? {})
        .filter((s) => String(s.status).startsWith("active"))
        .map((s) => String(s.index));
      if (activeIndices.length && states.headSlot && !beacon.code) {
        const epoch = Math.floor(states.headSlot / states.slotsPerEpoch) - 1;
        const res = await this.monitoring.queryBeaconApi(beacon.data.url, `/eth/v1/validator/liveness/${epoch}`, activeIndices, "POST");
        const liveIndices = new Set(
          (res.code ? [] : (res.data.api_reponse?.data ?? [])).filter((l) => l.is_live).map((l) => String(l.index))
        );
        for (const [pubkey, state] of Object.entries(states.byPubkey)) if (liveIndices.has(String(state.index))) live.push(pubkey);
      }

      return {
        code: 0,
        ...(remoteSigner ? { remoteSigner } : {}),
        alreadyImported: keys.filter((k) => present.has(k)),
        onChain: Object.fromEntries(Object.entries(states.byPubkey ?? {}).map(([k, s]) => [k, { index: s.index, status: s.status }])),
        statesKnown: states.code === 0,
        live,
        genesisRoot: genesis && !genesis.code ? (genesis.data.api_reponse?.data?.genesis_validators_root ?? null) : null,
        doppelganger: hasDoppelgangerProtection(info?.service, info?.config?.command),
      };
    } catch (err) {
      log.error("Preparing the key import failed: ", err);
      return { code: 1, info: String(err?.message || err) };
    }
  }

  /**
   * Import keystores (JSON texts) with one password each into a validator client, in chunks.
   * The slashing protection (EIP-3076 text) is checked against the chain before anything is sent.
   * Returns { code, results: [{ pubkey, status, message }] } in keystore order, or { code, info }.
   */
  async importKeys(serviceID, keystores = [], passwords = [], slashingProtection = null) {
    if (!keystores.length || keystores.length !== passwords.length) return { code: 1, info: "every keystore needs a password" };
    const parsed = keystores.map(parseKeystore);
    const broken = parsed.findIndex((p) => p.error);
    if (broken >= 0) return { code: 1, info: `keystore ${broken + 1}: ${parsed[broken].error}` };

    if (slashingProtection) {
      const beacon = await this.findHolderBeacon(serviceID);
      const genesis = beacon.code ? null : await this.monitoring.queryBeaconApi(beacon.data.url, "/eth/v1/beacon/genesis");
      const genesisRoot = genesis && !genesis.code ? genesis.data.api_reponse?.data?.genesis_validators_root : null;
      if (!genesisRoot) return { code: 1, info: "the chain's genesis could not be read to check the slashing protection" };
      const check = checkSlashingProtection(slashingProtection, { genesisRoot, pubkeys: parsed.map((p) => p.pubkey) });
      if (!check.ok) return { code: 1, info: "slashing protection rejected: " + check.errors.join(", ") };
    }

    const ref = StringUtils.createRandomString();
    const task = `Importing ${keystores.length} keys`;
    this.nodeConnection.taskManager?.otherTasksHandler(ref, task);
    const results = [];
    try {
      for (let i = 0; i < keystores.length; i += IMPORT_CHUNK) {
        const body = { keystores: keystores.slice(i, i + IMPORT_CHUNK), passwords: passwords.slice(i, i + IMPORT_CHUNK) };
        if (slashingProtection) body.slashing_protection = slashingProtection;
        const { status, rc, body: answer } = await this.keymanagerRequest(serviceID, { method: "POST", path: "/eth/v1/keystores", body });
        body.keystores.forEach((_, j) => {
          const entry = answer?.data?.[j];
          results.push({
            pubkey: parsed[i + j].pubkey,
            status: entry?.status ?? "error",
            message: entry ? (entry.message ?? "") : Validators.curlFailure(rc, status, answer),
          });
        });
      }
      const failed = results.filter((r) => r.status === "error");
      this.nodeConnection.taskManager?.otherTasksHandler(
        ref,
        task,
        !failed.length,
        failed.length ? failed.map((r) => `${r.pubkey}: ${r.message}`).join("\n") : ""
      );
      return { code: 0, results };
    } catch (err) {
      log.error(task + " failed: ", err);
      this.nodeConnection.taskManager?.otherTasksHandler(ref, task, false, String(err?.message || err));
      return { code: 2, info: String(err?.message || err), results };
    } finally {
      this.nodeConnection.taskManager?.otherTasksHandler(ref);
    }
  }

  /**
   * Import remote keys (signed by the Web3Signer at url) into a validator client, in chunks. A Prysm without
   * local keys is switched to remote signer mode and a Teku without signer url gets one, both restarted first.
   * Returns { code, results: [{ pubkey, status, message }], restarted } in key order, or { code, info }.
   */
  async importRemoteKeys(serviceID, pubkeys = [], url) {
    const holder = (await this.getValidatorHolders()).find((h) => h.id === serviceID);
    if (holder?.role !== "validator") return { code: 1, info: "remote keys cannot be imported into this service" };
    const signer = normalizeSignerUrl(url);
    if (signer.error) return { code: 1, info: "invalid url: " + signer.error };
    let keys = cleanKeys(pubkeys);
    if (!keys.length) return { code: 1, info: "no valid keys" };

    const ref = StringUtils.createRandomString();
    const task = `Importing ${keys.length} remote keys`;
    this.nodeConnection.taskManager?.otherTasksHandler(ref, task);
    const results = [];
    let restarted = false;
    try {
      if (holder.service === "PrysmValidatorService") {
        const client = await this.nodeConnection.readServiceConfiguration(serviceID);
        const listed = await this.listHolderKeys(serviceID);
        if (listed.code) throw new Error(listed.info);
        const plan = prysmSignerPlan({
          command: client.command,
          localCount: listed.keys.filter((k) => !k.remote).length,
          remoteCount: listed.keys.filter((k) => k.remote).length,
          url: signer.url,
        });
        if (plan.mode === "blocked") {
          this.nodeConnection.taskManager?.otherTasksHandler(ref, "Prysm cannot use this remote signer", false, plan.reason);
          return { code: 1, info: plan.reason, reason: plan.reason };
        }
        if (plan.mode === "switch") {
          // set first: a switch that fails after the restart still changed the client
          restarted = true;
          await this.switchPrysmToSigner(client, signer.url, ref);
          // without a key file Prysm forgets its remote keys on restart (they can only use this signer)
          const kept = listed.keys.filter((k) => k.remote).map((k) => k.pubkey);
          keys = [...keys, ...cleanKeys(kept).filter((k) => !keys.includes(k))];
        }
      } else if (holder.service === "TekuValidatorService") {
        const client = await this.nodeConnection.readServiceConfiguration(serviceID);
        if (tekuSignerPlan(client.command).mode === "switch") {
          restarted = true;
          client.command = withTekuSignerFlag(client.command, signer.url);
          await this.restartWithCommand(client, "Teku", ref);
        }
      }

      for (let i = 0; i < keys.length; i += REMOTE_IMPORT_CHUNK) {
        const chunk = keys.slice(i, i + REMOTE_IMPORT_CHUNK);
        const {
          status,
          rc,
          body: answer,
        } = await this.keymanagerRequest(serviceID, {
          method: "POST",
          path: "/eth/v1/remotekeys",
          body: { remote_keys: chunk.map((pubkey) => ({ pubkey, url: signer.url })) },
        });
        // the answer lists one status per requested key, in request order
        chunk.forEach((pubkey, j) => {
          const entry = answer?.data?.[j];
          results.push({
            pubkey,
            status: entry ? (entry.status ?? "error") : "error",
            message: entry ? (entry.message ?? "") : Validators.curlFailure(rc, status, answer),
          });
        });
      }
      const failed = results.filter((r) => r.status === "error");
      this.nodeConnection.taskManager?.otherTasksHandler(
        ref,
        task,
        !failed.length,
        failed.length ? failed.map((r) => `${r.pubkey}: ${r.message}`).join("\n") : ""
      );
      return { code: 0, results, restarted };
    } catch (err) {
      log.error(task + " failed: ", err);
      this.nodeConnection.taskManager?.otherTasksHandler(ref, task, false, String(err?.message || err));
      return { code: 2, info: String(err?.message || err), results, restarted };
    } finally {
      this.nodeConnection.taskManager?.otherTasksHandler(ref);
    }
  }

  // Prysm cannot mix local and remote keys and needs the key file flag, or it does not start (v7)
  async switchPrysmToSigner(client, url, ref) {
    const volumes = (client.volumes || []).map((v) => (typeof v === "string" ? ServiceVolume.buildByConfig(v) : v));
    const hostWallets = volumes.find((v) => v?.servicePath === PRYSM_WALLETS)?.destinationPath;
    // a config-derived path, but it still goes into single quotes
    if (!hostWallets || hostWallets.includes("'")) throw new Error("Prysm's wallets volume was not found");
    const touch = await this.nodeConnection.sshService.exec("touch '" + hostWallets + "/remote-keys.txt'");
    if (touch.rc != 0) throw new Error("the remote key file could not be created: " + (touch.stderr || "rc " + touch.rc));

    client.command = withPrysmSignerFlags(client.command, url);
    await this.restartWithCommand(client, "Prysm", ref);
  }

  // Write the changed client config, restart it and wait until its keymanager API answers again
  async restartWithCommand(client, name, ref) {
    await this.nodeConnection.writeServiceConfiguration(client);
    const serviceManager = this.monitoring.serviceManager;
    await serviceManager.manageServiceState(client.id, "stopped");
    await serviceManager.manageServiceState(client.id, "started");

    // instead of a fixed sleep: poll the API
    for (let waited = 0; ; waited += RESTART_POLL_MS) {
      const answer = await this.keymanagerRequest(client.id, { method: "GET", path: "/eth/v1/remotekeys" }).catch(() => null);
      if (answer?.status === 200) break;
      if (waited + RESTART_POLL_MS > RESTART_READY_TIMEOUT_MS) throw new Error(`${name} did not come back with its keymanager API`);
      await new Promise((resolve) => setTimeout(resolve, RESTART_POLL_MS));
    }
    this.nodeConnection.taskManager?.otherTasksHandler(ref, `Restarted ${name} with remote signer`, true);
  }

  /**
   * What an exit of the given keys would do, checked against the chain and the holder's beacon node.
   * Returns { code: 0, role, keys: { pubkey: { index, status, activationEpoch, credentials, dvPubkey?, blocker } },
   * eligible, exportable, blsCredentials, beacon: { base, source, blocker }, currentEpoch, shardCommitteePeriod,
   * secondsPerEpoch, signEpoch, target } or { code, info }. target stays in the backend (stripped in IPC).
   */
  async prepareExit(serviceID, pubkeys = []) {
    try {
      const holders = await this.getValidatorHolders();
      const holder = holders.find((h) => h.id === serviceID);
      // reason picks the modal's translated message, info stays for the log
      if (!holder || !["validator", "share"].includes(holder.role)) {
        return { code: 1, reason: "notAvailable", info: "exit is not available for this service" };
      }
      if (holder.state !== "running") return { code: 1, reason: "notRunning", info: "the validator client is not running" };
      if (holder.role === "share" && holders.find((h) => h.id === holder.dvtVia)?.state !== "running") {
        return { code: 1, reason: "dvtNotRunning", info: "the distributed validator client is not running" };
      }

      const requested = [...new Set((pubkeys || []).map((p) => String(p).toLowerCase()))].filter((p) => PUBKEY.test(p));
      const listed = await this.listHolderKeys(serviceID);
      if (listed.code) throw new Error(listed.info);
      const present = new Set(listed.keys.map((k) => k.pubkey));
      const keys = {};
      // only the holder's own keys, so the renderer cannot exit keys of another client
      for (const p of requested) if (!present.has(p)) keys[p] = { blocker: { reason: "notOnChain" } };
      const own = requested.filter((p) => present.has(p));

      // shares are not on chain: their distributed validator is
      let chainKey = (p) => p;
      if (holder.role === "share") {
        const shares = Validators.mapShares(await this.monitoring.validatorAccountManager.getDVTKeys(holder.dvtVia));
        chainKey = (p) => shares.get(p);
        for (const p of own) if (!chainKey(p)) keys[p] = { blocker: { reason: "notInCluster" } };
      }
      const onChain = own.filter((p) => chainKey(p));

      const states = await this.getValidatorStates(onChain.map(chainKey), serviceID);
      if (states.code) return { code: 1, info: states.info };
      // without the head every key would look too young
      if (!states.headSlot) return { code: 1, reason: "noHead", info: "the beacon node did not report its head" };
      const spec = await this.getSpec(states.base);
      const shardCommitteePeriod = spec.shardCommitteePeriod ?? 256;
      const currentEpoch = Math.floor(states.headSlot / states.slotsPerEpoch);

      const syncing = await this.monitoring.queryBeaconApi(states.base, "/eth/v1/node/syncing");
      const beacon = {
        base: states.base,
        source: states.source,
        blocker: beaconBlocker(syncing.code ? null : syncing.data?.api_reponse?.data),
      };

      for (const p of onChain) {
        const state = states.byPubkey[chainKey(p)];
        keys[p] = {
          index: state?.index,
          status: state?.status,
          activationEpoch: state?.activationEpoch,
          credentials: state?.withdrawalCredentials,
          ...(holder.role === "share" ? { dvPubkey: chainKey(p) } : {}),
          blocker: exitBlocker(state, currentEpoch, shardCommitteePeriod),
        };
      }
      const eligible = requested.filter((p) => !keys[p].blocker);
      // a message signed now becomes valid once the key is active long enough, also for a pending key with an index
      const exportable =
        holder.role === "validator"
          ? requested.filter(
              (p) =>
                !keys[p].blocker || keys[p].blocker.reason === "tooYoung" || (keys[p].blocker.reason === "pending" && keys[p].index != null)
            )
          : [];
      const blsCredentials = requested.filter(
        (p) => (eligible.includes(p) || exportable.includes(p)) && String(keys[p].credentials).startsWith("0x00")
      );

      let signEpoch = null;
      let target = { prefix: "curl", base: states.base };
      if (holder.role === "share") {
        // Charon only aggregates partial exits signed for the same epoch, and Obol tells operators to use Capella's
        signEpoch = spec.capellaForkEpoch;
        if (signEpoch == null) return { code: 1, reason: "noCapella", info: "the beacon node did not report the Capella fork epoch" };
        const curlTag = await this.nodeConnection.ensureCurlImage();
        target = {
          prefix: `docker run --rm -i --network=stereum curlimages/curl:${curlTag}`,
          base: `http://stereum-${holder.dvtVia}:3600`,
        };
      }

      return {
        code: 0,
        role: holder.role,
        keys,
        eligible,
        exportable,
        blsCredentials,
        beacon,
        currentEpoch,
        shardCommitteePeriod,
        secondsPerEpoch: states.slotsPerEpoch * states.secondsPerSlot,
        signEpoch,
        target,
      };
    } catch (err) {
      log.error("Preparing the exit failed: ", err);
      return { code: 1, info: String(err?.message || err) };
    }
  }

  // share pubkey -> distributed validator pubkey, from a cluster lock's distributed_validators
  static mapShares(dvs = []) {
    const map = new Map();
    for (const dv of dvs || []) {
      const dvPubkey = String(dv?.distributed_public_key || "").toLowerCase();
      if (!PUBKEY.test(dvPubkey)) continue;
      for (const share of dv.public_shares || []) map.set(String(share).toLowerCase(), dvPubkey);
    }
    return map;
  }

  // Signed exits from the validator client: { signed: Map(pubkey -> message), failed: { pubkey: { message, error? } } }
  async signExits(serviceID, keys, indexByPubkey, epoch) {
    const answers = await this.keymanagerCalls(
      serviceID,
      // body [] as the staking page sent it, which every client accepted
      keys.map((pubkey) => ({
        method: "POST",
        path: `/eth/v1/validator/${pubkey}/voluntary_exit${epoch != null ? `?epoch=${epoch}` : ""}`,
        body: [],
      }))
    );
    const signed = new Map();
    const failed = {};
    keys.forEach((pubkey, i) => {
      const { status, body } = answers[i] ?? {};
      const message = checkSignedExit(body, indexByPubkey[pubkey]);
      if (message) signed.set(pubkey, message);
      else if (checkSignedExit(body, null)) failed[pubkey] = { message: "signed for another validator", error: "wrongIndex" };
      else failed[pubkey] = { message: body?.message || "HTTP " + status };
    });
    return { signed, failed };
  }

  /**
   * Sign and broadcast voluntary exits for the eligible keys (partial exits to Charon/Pluto for shares).
   * Returns { code: 0, results: { pubkey: { status, message?, reason?, eligibleEpoch? } }, partial, signEpoch }.
   */
  async exitKeys(serviceID, pubkeys) {
    // checked again here, the renderer's preflight is never trusted
    const prep = await this.prepareExit(serviceID, pubkeys);
    if (prep.code) return prep;
    if (prep.beacon.blocker) return { code: 1, beaconBlocker: prep.beacon.blocker, info: "beacon node " + prep.beacon.blocker };

    const partial = prep.role === "share";
    const results = {};
    for (const [pubkey, key] of Object.entries(prep.keys)) {
      if (key.blocker) results[pubkey] = { status: "skipped", ...key.blocker };
    }
    const indexByPubkey = Object.fromEntries(Object.entries(prep.keys).map(([p, k]) => [p, k.index]));
    const total = prep.eligible.length;
    if (!total) return { code: 0, results, partial, signEpoch: prep.signEpoch };

    const ref = StringUtils.createRandomString();
    const task = `Exiting ${total} validators`;
    this.nodeConnection.taskManager?.otherTasksHandler(ref, task);
    try {
      for (let i = 0; i < total; i += EXIT_CHUNK) {
        const chunk = prep.eligible.slice(i, i + EXIT_CHUNK);
        const { signed, failed } = await this.signExits(serviceID, chunk, indexByPubkey, prep.signEpoch);
        for (const [pubkey, failure] of Object.entries(failed)) results[pubkey] = { status: "signFailed", ...failure };
        const sent = [...signed.keys()];
        if (sent.length) {
          const answers = await this.curlConfigRun(
            prep.target.prefix,
            sent.map((pubkey) =>
              Validators.curlBlock(
                prep.target.base,
                null,
                false,
                { method: "POST", path: "/eth/v1/beacon/pool/voluntary_exits", body: signed.get(pubkey) },
                [HTTP_WRITE_OUT]
              )
            )
          );
          sent.forEach((pubkey, j) => {
            const { status, body } = answers[j];
            results[pubkey] = status === 200 ? { status: "submitted" } : { status: "rejected", message: body?.message || `HTTP ${status}` };
          });
        }
        const chunkFailed = chunk.filter((p) => results[p].status !== "submitted");
        this.nodeConnection.taskManager?.otherTasksHandler(
          ref,
          `Sent ${Math.min(i + EXIT_CHUNK, total)} of ${total}`,
          !chunkFailed.length,
          chunkFailed.map((p) => `${p}: ${results[p].message}`).join("\n")
        );
      }

      const failed = prep.eligible.filter((p) => results[p].status !== "submitted");
      this.nodeConnection.taskManager?.otherTasksHandler(
        ref,
        task,
        !failed.length,
        failed.map((p) => `${p}: ${results[p].message}`).join("\n")
      );
      log.info(`${task}: ${total - failed.length} submitted, ${failed.length} failed`);
      return { code: 0, results, partial, signEpoch: prep.signEpoch };
    } catch (err) {
      log.error(task + " failed: ", err);
      this.nodeConnection.taskManager?.otherTasksHandler(ref, task, false, String(err?.message || err));
      return { code: 2, info: String(err?.message || err), results };
    } finally {
      this.nodeConnection.taskManager?.otherTasksHandler(ref);
    }
  }

  /**
   * Signed exits to keep offline (validator holders only, epoch left to the client). The only path where
   * signed messages leave the backend. Returns { code: 0, messages, failed: [{ pubkey, message }], skipped }.
   */
  async exportExitMessages(serviceID, pubkeys) {
    const holder = (await this.getValidatorHolders()).find((h) => h.id === serviceID);
    if (holder?.role !== "validator") {
      return { code: 1, reason: "noExport", info: "signed exits can only be exported from a validator client" };
    }
    const prep = await this.prepareExit(serviceID, pubkeys);
    if (prep.code) return prep;

    const skipped = {};
    for (const [pubkey, key] of Object.entries(prep.keys)) {
      if (!prep.exportable.includes(pubkey)) skipped[pubkey] = key.blocker?.reason ?? "notOnChain";
    }
    const indexByPubkey = Object.fromEntries(Object.entries(prep.keys).map(([p, k]) => [p, k.index]));
    const total = prep.exportable.length;
    const messages = [];
    const failed = [];
    if (!total) return { code: 0, messages, failed, skipped };

    const ref = StringUtils.createRandomString();
    const task = `Signing ${total} exit messages`;
    this.nodeConnection.taskManager?.otherTasksHandler(ref, task);
    try {
      for (let i = 0; i < total; i += EXIT_CHUNK) {
        const chunk = prep.exportable.slice(i, i + EXIT_CHUNK);
        const result = await this.signExits(serviceID, chunk, indexByPubkey, null);
        const chunkFailed = [];
        for (const pubkey of chunk) {
          if (result.signed.has(pubkey)) messages.push(result.signed.get(pubkey));
          else chunkFailed.push({ pubkey, ...result.failed[pubkey] });
        }
        failed.push(...chunkFailed);
        this.nodeConnection.taskManager?.otherTasksHandler(
          ref,
          `Signed ${Math.min(i + EXIT_CHUNK, total)} of ${total}`,
          !chunkFailed.length,
          chunkFailed.map((f) => `${f.pubkey}: ${f.message}`).join("\n")
        );
      }
      this.nodeConnection.taskManager?.otherTasksHandler(
        ref,
        task,
        !failed.length,
        failed.map((f) => `${f.pubkey}: ${f.message}`).join("\n")
      );
      log.info(`${task}: ${messages.length} signed, ${failed.length} failed`);
      return { code: 0, messages, failed, skipped };
    } catch (err) {
      log.error(task + " failed: ", err);
      this.nodeConnection.taskManager?.otherTasksHandler(ref, task, false, String(err?.message || err));
      return { code: 2, info: String(err?.message || err) };
    } finally {
      this.nodeConnection.taskManager?.otherTasksHandler(ref);
    }
  }

  // keys.yaml as an object; a missing file is empty, anything unreadable throws so it is never overwritten
  async readKeyEntries() {
    const result = await this.nodeConnection.sshService.exec("cat " + KEYS_FILE);
    if (result.rc != 0) {
      if (/No such file/.test(result.stderr || "")) return {};
      throw new Error("reading " + KEYS_FILE + " failed: " + (result.stderr || "rc " + result.rc));
    }
    const data = YAML.parse(result.stdout || "");
    if (data === null || data === undefined || data === "") return {};
    if (typeof data !== "object" || Array.isArray(data)) throw new Error(KEYS_FILE + " is not a map of keys");
    return data;
  }

  // { entries } with lowercased pubkeys, or { error }; holderIds are the valid validatorClientIDs
  static validateKeyPatch(patch, holderIds = []) {
    if (!patch || typeof patch !== "object" || Array.isArray(patch)) return { error: "invalid patch" };
    const keys = Object.keys(patch);
    if (keys.length > KEY_PATCH_MAX) return { error: "too many keys" };
    const entries = {};
    for (const key of keys) {
      const pubkey = key.toLowerCase();
      if (!PUBKEY.test(pubkey)) return { error: "invalid public key " + key };
      const fields = patch[key];
      if (!fields || typeof fields !== "object" || Array.isArray(fields)) return { error: "invalid entry for " + pubkey };
      for (const [field, value] of Object.entries(fields)) {
        if (!KEY_FIELDS.includes(field)) return { error: "unknown field " + field };
        if (field === "keyName" || field === "groupName") {
          if (typeof value !== "string" || value.length > 30 || /\s/.test(value) || CONTROL_CHARS.test(value))
            return { error: "invalid " + field + " for " + pubkey };
        } else if (field === "groupID") {
          if (value !== null && !(typeof value === "string" && GROUP_ID.test(value))) return { error: "invalid groupID for " + pubkey };
        } else if (value !== null && !holderIds.includes(value)) {
          return { error: "unknown validator client for " + pubkey };
        }
      }
      entries[pubkey] = { ...entries[pubkey], ...fields };
    }
    return { entries };
  }

  // Commands writing text to file through quoted heredocs in chunks, so neither argv limits nor echo -e apply
  static keysYamlCommands(text, file = KEYS_FILE) {
    const lines = text.replace(/\n$/, "").split("\n");
    if (lines.some((line) => line === KEYS_MARKER || line === "=====EOF")) throw new Error("keys file contains a heredoc marker");
    const chunks = [];
    let current = [];
    let size = 0;
    for (const line of lines) {
      const bytes = Buffer.byteLength(line, "utf8") + 1;
      if (current.length && size + bytes > KEYS_CHUNK) {
        chunks.push(current.join("\n"));
        current = [];
        size = 0;
      }
      current.push(line);
      size += bytes;
    }
    chunks.push(current.join("\n"));
    // the move is chained to the last write, so a failed write never replaces the file
    return chunks.map((chunk, i) => {
      const move = i === chunks.length - 1 ? ` && mv -f ${file}.tmp ${file}` : "";
      return `cat ${i ? ">>" : ">"} ${file}.tmp <<'${KEYS_MARKER}'${move}\n${chunk}\n${KEYS_MARKER}`;
    });
  }

  /**
   * Merge per-key fields into /etc/stereum/keys.yaml (aliases and groups). Writes are serialized so
   * concurrent read-modify-writes never lose an update. Returns { code: 0, aliases } or { code: 1, info }.
   */
  async writeKeyEntries(patch) {
    const run = async () => {
      try {
        const needsHolders = Object.values(patch || {}).some((f) => f?.validatorClientID !== undefined && f?.validatorClientID !== null);
        const holderIds = needsHolders ? (await this.getValidatorHolders()).map((h) => h.id) : [];
        const { entries, error } = Validators.validateKeyPatch(patch, holderIds);
        if (error) return { code: 1, info: error };

        const merged = await this.readKeyEntries();
        // an existing mixed-case entry is updated in place instead of duplicated
        const existing = {};
        for (const key of Object.keys(merged)) {
          const lower = key.toLowerCase();
          if (!(lower in existing) || key === lower) existing[lower] = key;
        }
        for (const [pubkey, fields] of Object.entries(entries)) {
          const key = existing[pubkey] ?? pubkey;
          const current = merged[key] && typeof merged[key] === "object" ? merged[key] : {};
          merged[key] = { keyName: "", groupName: "", groupID: null, validatorClientID: null, ...current, ...fields };
        }

        // the real file is only replaced by the final mv, a failed chunk leaves just the .tmp file
        for (const cmd of Validators.keysYamlCommands(YAML.stringify(merged))) {
          const result = await this.nodeConnection.sshService.exec(cmd);
          if (result.rc != 0) throw new Error("writing " + KEYS_FILE + " failed: " + (result.stderr || "rc " + result.rc));
        }
        return { code: 0, aliases: merged };
      } catch (err) {
        log.error("Writing the keys file failed: ", err);
        return { code: 1, info: String(err?.message || err) };
      }
    };
    // the queue lives on the connection, so ValidatorAccountManager.writeKeys waits in it too
    const queue = this.nodeConnection;
    queue.keysWrite = (queue.keysWrite ?? Promise.resolve()).then(run, run);
    return queue.keysWrite;
  }

  // Merge EIP-3076 interchange data (object or JSON string) of several deletes into one
  static mergeInterchange(merged, next) {
    const data = typeof next === "string" ? Validators.parseJson(next) : next;
    if (!data?.data) return merged;
    if (!merged) return { metadata: data.metadata, data: [...data.data] };
    return { metadata: merged.metadata, data: [...merged.data, ...data.data] };
  }

  /**
   * Set (value given) or reset (value null, back to the client default) a per-key setting through the
   * keymanager API for many keys at once. setting: "graffiti" | "feerecipient".
   * Returns { code, ok: [pubkeys], failed: [pubkeys] } or { code, info } on invalid input.
   */
  async setKeySetting(serviceID, pubkeys, setting, value) {
    const keys = [...new Set((pubkeys || []).map((p) => String(p).toLowerCase()))].filter((p) => PUBKEY.test(p));
    if (!keys.length) return { code: 1, info: "no valid keys" };
    let body = null;
    if (value !== null && value !== undefined) {
      if (setting === "graffiti") {
        // graffiti is 32 bytes on chain, and control characters have no place in it
        if (Buffer.byteLength(value, "utf8") > 32 || [...value].some((c) => c.charCodeAt(0) < 32))
          return { code: 1, info: "invalid graffiti" };
        body = { graffiti: value };
      } else if (setting === "feerecipient") {
        if (!ADDRESS.test(value)) return { code: 1, info: "invalid fee recipient" };
        body = { ethaddress: value };
      } else {
        return { code: 1, info: "unknown setting " + setting };
      }
    }

    const ref = StringUtils.createRandomString();
    const task = `${body ? "Setting" : "Resetting"} ${setting === "graffiti" ? "Graffiti" : "Fee Recipient"} (${keys.length} keys)`;
    this.nodeConnection.taskManager?.otherTasksHandler(ref, task);
    try {
      const statuses = await this.keymanagerBatch(
        serviceID,
        keys.map((pubkey) => ({ method: body ? "POST" : "DELETE", path: `/eth/v1/validator/${pubkey}/${setting}`, body }))
      );
      // 202 accepted on set, 204 no content on delete
      const ok = keys.filter((_, i) => statuses[i] === 202 || statuses[i] === 204 || statuses[i] === 200);
      const failed = keys.filter((k) => !ok.includes(k));
      this.nodeConnection.taskManager?.otherTasksHandler(
        ref,
        task,
        !failed.length,
        failed.length ? `Failed for:\n${failed.join("\n")}` : ""
      );
      return { code: 0, ok, failed };
    } catch (err) {
      log.error(task + " failed: ", err);
      this.nodeConnection.taskManager?.otherTasksHandler(ref, task, false, String(err?.message || err));
      return { code: 2, info: String(err?.message || err) };
    } finally {
      this.nodeConnection.taskManager?.otherTasksHandler(ref);
    }
  }

  // Current per-key graffiti (without a task panel entry), { code, graffiti } or { code, info }
  async getGraffiti(serviceID, pubkey) {
    try {
      if (!PUBKEY.test(String(pubkey).toLowerCase())) throw new Error("invalid public key");
      const client = await this.nodeConnection.readServiceConfiguration(serviceID);
      const result = await this.monitoring.validatorAccountManager.keymanagerAPI(client, "GET", `/eth/v1/validator/${pubkey}/graffiti`);
      const data = Validators.parseJson(result.stdout);
      if (!data?.data) throw new Error(data?.message || result.stderr || "no graffiti returned");
      return { code: 0, graffiti: data.data.graffiti ?? "" };
    } catch (err) {
      log.error("Reading the graffiti of " + pubkey + " failed: ", err);
      return { code: 1, info: String(err?.message || err) };
    }
  }

  async keymanagerList(vam, client, path) {
    const result = await vam.keymanagerAPI(client, "GET", path);
    if (result.rc != 0 || !result.stdout) throw new Error(`keymanager ${path} failed: ${result.stderr || "rc " + result.rc}`);
    const data = JSON.parse(result.stdout);
    if (!Array.isArray(data.data)) throw new Error(`keymanager ${path}: ${data.message || "unexpected answer"}`);
    return data.data;
  }

  /**
   * Beacon states of the given keys in one exec, plus the chain time to date them.
   * Returns { code, byPubkey, source, base, headSlot, slotsPerEpoch, secondsPerSlot }. Keys the beacon
   * does not know are simply missing from byPubkey; code != 0 means nothing could be asked, so the
   * caller keeps the stats it has.
   */
  async getValidatorStates(pubkeys = [], serviceID = null) {
    const ids = [...new Set(pubkeys.map((p) => String(p).toLowerCase()))].filter((p) => PUBKEY.test(p));
    const beacon = await this.findHolderBeacon(serviceID);
    if (beacon.code) return { code: 1, info: "no beacon node available (" + beacon.info + ")", byPubkey: {} };
    const base = beacon.data.url;
    const source = beacon.data.source;

    const spec = await this.getSpec(base);
    const parts = [`curl -s '${base}/eth/v1/beacon/headers/head'; printf '\\n${STATES_MARKER}\\n'`];
    for (let i = 0; i < ids.length; i += STATES_CHUNK) {
      const body = JSON.stringify({ ids: ids.slice(i, i + STATES_CHUNK) });
      parts.push(
        `curl -s -X POST '${base}/eth/v1/beacon/states/head/validators' -H 'Content-Type: application/json' -d '${body}'; printf '\\n${STATES_MARKER}\\n'`
      );
    }
    const result = await this.nodeConnection.sshService.execShared(parts.join("\n"));
    if (result.rc != 0 && !result.stdout) return { code: 2, info: "state query failed: " + result.stderr, byPubkey: {}, source, base };

    const [head, ...chunks] = result.stdout.split(`\n${STATES_MARKER}\n`).map((s) => s.trim());
    const byPubkey = {};
    let answered = 0;
    for (const chunk of chunks.slice(0, Math.ceil(ids.length / STATES_CHUNK))) {
      const json = Validators.parseJson(chunk);
      if (!json) continue;
      // 404: none of the keys in this chunk are on chain yet, which is an answer too
      if (Array.isArray(json.data) || json.code == 404) answered++;
      for (const v of json.data || []) byPubkey[v.validator.pubkey.toLowerCase()] = Validators.toState(v);
    }
    if (ids.length && !answered) return { code: 3, info: "the beacon node did not answer the state query", byPubkey: {}, source, base };

    return {
      code: 0,
      byPubkey,
      source,
      base,
      headSlot: parseInt(Validators.parseJson(head)?.data?.header?.message?.slot) || null,
      slotsPerEpoch: spec.slotsPerEpoch,
      secondsPerSlot: spec.secondsPerSlot,
      // lets the duties tab show the chain clock before any duties are read
      genesisTime: spec.genesisTime ?? null,
    };
  }

  /**
   * The beacon node a holder's validators run on: the consensus client it depends on (through
   * Charon/Pluto for DV setups), so a node with several networks asks the right chain. Falls back to
   * the first available or a configured beacon node.
   */
  async findHolderBeacon(serviceID) {
    if (serviceID) {
      const infos = await this.monitoring.getServiceInfos();
      const byId = (id) => infos.find((i) => i.config?.serviceID === id);
      let dep = (byId(serviceID)?.config?.dependencies?.consensusClients || [])[0];
      if (dep && isObolDVTService(dep.service)) dep = (byId(dep.id)?.config?.dependencies?.consensusClients || [])[0];
      if (dep) {
        const status = await this.monitoring.getBeaconStatus();
        const own = status.code ? null : status.data.find((d) => d.sid === dep.id);
        if (own) {
          return {
            code: 0,
            data: { url: `http://${own.beacon.destinationIp}:${own.beacon.destinationPort}`, source: "local" },
          };
        }
      }
    }
    return this.monitoring.findBeaconPort();
  }

  /**
   * Many beacon API requests in as few execs as possible: one curl per request, its status code on the last
   * line and a marker after it, grouped into execs of at most EXEC_BUDGET bytes. requests: [{ path, ids? }],
   * ids makes it a POST with the JSON array as body. Only validated integers and indices are ever in path
   * and ids. Returns [{ status, body }] in request order ({ status: 0, body: null } when missing).
   */
  async beaconBatch(base, requests) {
    // a configured endpoint may carry a path; it goes into single quotes, so none may be in it
    if (!/^https?:\/\/[^\s'"\\]+$/.test(String(base))) throw new Error("invalid beacon node address");
    const lines = requests.map(({ path, ids }) => {
      const post = ids ? ` -X POST -H 'Content-Type: application/json' -d '${JSON.stringify(ids)}'` : "";
      return `curl -s -w '\\n%{http_code}'${post} '${base}${path}'; printf '\\n${BEACON_MARKER}\\n'`;
    });
    const groups = [];
    let current = [];
    let size = 0;
    for (const line of lines) {
      const bytes = Buffer.byteLength(line, "utf8") + 1;
      if (current.length && size + bytes > EXEC_BUDGET) {
        groups.push(current);
        current = [];
        size = 0;
      }
      current.push(line);
      size += bytes;
    }
    if (current.length) groups.push(current);

    const results = [];
    for (const group of groups) {
      const result = await this.nodeConnection.sshService.execShared(group.join("\n"));
      const parts = String(result?.stdout ?? "").split(`\n${BEACON_MARKER}\n`);
      for (let i = 0; i < group.length; i++) results.push(Validators.parseBeaconPart(parts[i]));
    }
    return results;
  }

  // "<body>\n<http code>" -> { status, body }
  static parseBeaconPart(part) {
    if (part === undefined) return { status: 0, body: null };
    const text = part.replace(/^\n+/, "");
    const cut = text.lastIndexOf("\n");
    const status = parseInt(cut < 0 ? text : text.slice(cut + 1)) || 0;
    const body = cut < 0 ? "" : text.slice(0, cut).trim();
    return { status, body: body ? Validators.parseJson(body) : null };
  }

  // Holder (not a share, its keys are not on chain) with the beacon node and chain timing it runs on
  async dutiesTarget(serviceID) {
    const holder = (await this.getValidatorHolders()).find((h) => h.id === serviceID);
    if (!holder || holder.role === "share") return { code: 1, info: "duties are not available for this service" };
    const beacon = await this.findHolderBeacon(serviceID);
    if (beacon.code) return { code: 1, info: "no beacon node available (" + beacon.info + ")" };
    const base = beacon.data.url;
    return { code: 0, holder, base, source: beacon.data.source, spec: await this.getSpec(base) };
  }

  /**
   * Proposer and sync committee duties of the given validator indices for the current epoch (proposals
   * also for the previous and the next one, sync also for the next period), in one batch on the holder's beacon node.
   * Returns { code: 0, epoch, slot, headSlot, finalizedEpoch, genesisTime, slotsPerEpoch, secondsPerSlot,
   * proposals: [{ slot, index, pubkey }], sync: { current, next, periodStart, nextPeriodStart } } or { code, info }.
   */
  async getDuties(serviceID, indices = []) {
    try {
      const ids = cleanIndices(indices);
      if (!ids.length) return { code: 0, empty: true };
      const target = await this.dutiesTarget(serviceID);
      if (target.code) return target;
      const { base, spec } = target;
      const { slotsPerEpoch, secondsPerSlot, genesisTime, epochsPerSyncCommitteePeriod } = spec;

      // the wall clock, or the head when the genesis time is unknown
      let slot = chainClock(spec, Date.now())?.slot;
      if (slot === undefined) {
        const [head] = await this.beaconBatch(base, [{ path: "/eth/v1/beacon/headers/head" }]);
        slot = parseInt(head.body?.data?.header?.message?.slot);
        if (head.status !== 200 || !Number.isFinite(slot)) return { code: 2, info: "the beacon node did not report its head" };
      }
      const epoch = Math.floor(slot / slotsPerEpoch);
      const periodStart = nextPeriodStart(epoch, epochsPerSyncCommitteePeriod);
      const chunks = chunked(ids, INDEX_CHUNK);

      const answers = await this.beaconBatch(base, [
        { path: "/eth/v1/beacon/headers/head" },
        { path: "/eth/v1/beacon/states/head/finality_checkpoints" },
        // the previous epoch too, since its rewards are accounted once it is over
        { path: `/eth/v1/validator/duties/proposer/${Math.max(epoch - 1, 0)}` },
        { path: `/eth/v1/validator/duties/proposer/${epoch}` },
        { path: `/eth/v1/validator/duties/proposer/${epoch + 1}` },
        ...chunks.map((chunk) => ({ path: `/eth/v1/validator/duties/sync/${epoch}`, ids: chunk })),
        ...chunks.map((chunk) => ({ path: `/eth/v1/validator/duties/sync/${periodStart}`, ids: chunk })),
      ]);
      const [head, finality, ...proposerAnswers] = answers.slice(0, 5);
      const headSlot = parseInt(head.body?.data?.header?.message?.slot);
      if (head.status !== 200 || !Number.isFinite(headSlot)) return { code: 2, info: "the beacon node did not report its head" };
      const finalized = parseInt(finality.body?.data?.finalized?.epoch);

      // a Set keeps the filter linear with thousands of keys; the next epoch is optional in the spec
      const own = new Set(ids);
      const proposals = [];
      for (const answer of epoch > 0 ? proposerAnswers : proposerAnswers.slice(1)) {
        if (answer.status !== 200 || !Array.isArray(answer.body?.data)) continue;
        for (const duty of answer.body.data) {
          const index = String(duty.validator_index);
          if (own.has(index)) proposals.push({ slot: parseInt(duty.slot), index, pubkey: String(duty.pubkey).toLowerCase() });
        }
      }
      const syncIndices = (list) => [
        ...new Set(list.flatMap((a) => (Array.isArray(a.body?.data) ? a.body.data.map((d) => String(d.validator_index)) : []))),
      ];
      const syncAnswers = answers.slice(5);

      return {
        code: 0,
        epoch,
        slot,
        headSlot,
        finalizedEpoch: Number.isFinite(finalized) ? finalized : null,
        genesisTime,
        slotsPerEpoch,
        secondsPerSlot,
        proposals: proposals.sort((a, b) => a.slot - b.slot),
        sync: {
          current: syncIndices(syncAnswers.slice(0, chunks.length)),
          next: syncIndices(syncAnswers.slice(chunks.length)),
          periodStart: periodStart - epochsPerSyncCommitteePeriod,
          nextPeriodStart: periodStart,
        },
      };
    } catch (err) {
      log.error("Reading the duties of " + serviceID + " failed: ", err);
      return { code: 1, info: String(err?.message || err) };
    }
  }

  /**
   * Rewards of a completed epoch in one batch: attestations (finalized epoch), sync committee (per slot of
   * epoch, only with syncIndices) and the given proposals (consensus layer reward only).
   * Returns { code: 0, headSlot, attestation, sync, blocks: [{ slot, index, result, reward }], unsupported }.
   */
  async getRewards(serviceID, { indices = [], attestationEpoch, epoch, syncIndices = [], proposals = [], effectiveBalances = {} } = {}) {
    try {
      const target = await this.dutiesTarget(serviceID);
      if (target.code) return target;
      const { base, spec } = target;
      const ids = cleanIndices(indices);
      const syncIds = cleanIndices(syncIndices).slice(0, SYNC_COMMITTEE_SIZE);
      const blocks = (Array.isArray(proposals) ? proposals : [])
        .filter((p) => epochOrSlot(p?.slot) && INDEX.test(String(p?.index)))
        .slice(0, MAX_SLOTS)
        .map((p) => ({ slot: p.slot, index: String(p.index) }));

      const requests = [{ kind: "head", path: "/eth/v1/beacon/headers/head" }];
      if (epochOrSlot(attestationEpoch) && ids.length) {
        for (const chunk of chunked(ids, INDEX_CHUNK)) {
          requests.push({ kind: "attestation", path: `/eth/v1/beacon/rewards/attestations/${attestationEpoch}`, ids: chunk });
        }
      }
      if (epochOrSlot(epoch) && syncIds.length) {
        for (let slot = epoch * spec.slotsPerEpoch; slot < (epoch + 1) * spec.slotsPerEpoch; slot++) {
          requests.push({ kind: "sync", slot, path: `/eth/v1/beacon/rewards/sync_committee/${slot}`, ids: syncIds });
        }
      }
      for (const block of blocks) {
        requests.push({ kind: "header", slot: block.slot, path: `/eth/v1/beacon/headers/${block.slot}` });
        requests.push({ kind: "block", slot: block.slot, path: `/eth/v1/beacon/rewards/blocks/${block.slot}` });
      }

      const answers = await this.beaconBatch(base, requests);
      const of = (kind) => requests.map((r, i) => ({ ...r, ...answers[i] })).filter((a) => a.kind === kind);
      const headSlot = parseInt(answers[0].body?.data?.header?.message?.slot);
      const unsupported = {};

      let attestation = null;
      const attAnswers = of("attestation");
      if (attAnswers.length) {
        unsupported.attestation = allUnsupported(attAnswers);
        const ok = attAnswers.filter((a) => a.status === 200 && a.body?.data);
        if (ok.length === attAnswers.length) {
          const balances = {};
          for (const [index, balance] of Object.entries(effectiveBalances || {})) {
            if (INDEX.test(index) && Number.isSafeInteger(balance)) balances[index] = balance;
          }
          attestation = {
            epoch: attestationEpoch,
            ...attestationSummary(
              ok.map((a) => a.body),
              balances
            ),
          };
        }
      }

      let sync = null;
      const syncAnswers = of("sync");
      if (syncAnswers.length) {
        unsupported.sync = allUnsupported(syncAnswers);
        // a slot without any answer is unknown, not missed
        if (!unsupported.sync && syncAnswers.every((a) => a.status === 200 || a.status === 404)) {
          const summary = syncSummary(syncAnswers);
          sync = { epoch, total: summary.total, missedCount: summary.missedCount, missedSlots: summary.missedSlots };
        }
      }

      const results = [];
      const headers = of("header");
      const rewards = of("block");
      if (blocks.length) unsupported.block = allUnsupported(rewards.filter((r, i) => headers[i].status === 200));
      blocks.forEach((block, i) => {
        // a slot after the head has no outcome yet
        if (!Number.isFinite(headSlot) || block.slot > headSlot) return;
        const header = headers[i];
        if (header.status === 404) return results.push({ ...block, result: "missed", reward: 0 });
        if (header.status !== 200) return;
        const proposer = String(header.body?.data?.header?.message?.proposer_index);
        if (proposer !== block.index) return results.push({ ...block, result: "missed", reward: 0 });
        const total = parseInt(rewards[i].body?.data?.total);
        results.push({ ...block, result: "proposed", reward: rewards[i].status === 200 && Number.isFinite(total) ? total : null });
      });

      return {
        code: 0,
        headSlot: Number.isFinite(headSlot) ? headSlot : null,
        attestation,
        sync,
        blocks: results,
        unsupported,
      };
    } catch (err) {
      log.error("Reading the rewards of " + serviceID + " failed: ", err);
      return { code: 1, info: String(err?.message || err) };
    }
  }

  /**
   * Cluster stats of a DVT holder: Obol (Charon/Pluto, a share shows its cluster) from Prometheus, SSV
   * from the public SSV API. Returns { code: 0, kind, service, stats, empty } or { code: 1, info }.
   */
  async getClusterStats(serviceID) {
    try {
      const holders = await this.getValidatorHolders();
      const holder = holders.find((h) => h.id === serviceID);
      if (holder?.role === "distributed" || holder?.role === "share") {
        const id = holder.role === "share" ? holder.dvtVia : holder.id;
        const service = holders.find((h) => h.id === id)?.service ?? null;
        const stats = (await this.monitoring.getObolClusterInformation(id)) ?? {};
        return { code: 0, kind: "obol", service, stats, empty: !Object.keys(stats).length };
      }
      if (holder?.role === "ssv") {
        const stats = (await this.monitoring.getSSVClusterInformation(holder.id)) ?? {};
        return { code: 0, kind: "ssv", service: holder.service, stats, empty: !Object.keys(stats).length };
      }
      return { code: 1, info: "no cluster for this service" };
    } catch (err) {
      // the SSV API call throws on any non-2xx answer
      log.error("Reading the cluster stats of " + serviceID + " failed: ", err);
      return { code: 1, info: String(err?.message || err) };
    }
  }

  /**
   * Lido CSM signing keys of the node operator (from the LCOM config) with their deposit queue position.
   * Calls share one run and a 5 minute cache, since the lookup opens and closes all RPC tunnels.
   * Returns { code: 0, installed, keys: { pubkey: position } } or { code: 1, installed: true, info }.
   */
  async getCsmKeys(force = false) {
    try {
      const lcom = await this.monitoring.getServiceInfos("LCOMService");
      if (!lcom?.length) return { code: 0, installed: false, keys: {} };
      if (!force && this.csmCache && Date.now() - this.csmCache.at < CSM_CACHE_MS) return this.csmCache.result;
      const list = await this.csmSigningKeys();
      if (!list) return { code: 1, installed: true, info: "CSM keys could not be read (node syncing or RPC unavailable)" };
      const result = { code: 0, installed: true, keys: csmQueueMap(list) };
      this.csmCache = { at: Date.now(), result };
      return result;
    } catch (err) {
      log.error("Reading the Lido CSM keys failed: ", err);
      return { code: 1, installed: true, info: String(err?.message || err) };
    }
  }

  static toState(v) {
    return {
      index: v.index,
      status: v.status,
      balance: parseInt(v.balance),
      effectiveBalance: parseInt(v.validator.effective_balance),
      slashed: v.validator.slashed === true || v.validator.slashed === "true",
      withdrawalCredentials: v.validator.withdrawal_credentials,
      activationEpoch: parseInt(v.validator.activation_epoch),
      exitEpoch: parseInt(v.validator.exit_epoch),
      withdrawableEpoch: parseInt(v.validator.withdrawable_epoch),
    };
  }

  static parseJson(text) {
    try {
      return JSON.parse(text);
    } catch (e) {
      return null;
    }
  }

  // Chain timing per beacon node, cached since it never changes (falls back to mainnet values)
  async getSpec(base) {
    if (this.specByBase[base]) return this.specByBase[base];
    const res = await this.monitoring.queryBeaconApi(base, "/eth/v1/config/spec");
    const data = res.code ? {} : res.data.api_reponse?.data || {};
    const genesis = await this.monitoring.queryBeaconApi(base, "/eth/v1/beacon/genesis");
    const genesisTime = genesis?.code ? NaN : parseInt(genesis?.data?.api_reponse?.data?.genesis_time);
    const capella = parseInt(data.CAPELLA_FORK_EPOCH);
    const spec = {
      slotsPerEpoch: parseInt(data.SLOTS_PER_EPOCH) || 32,
      secondsPerSlot: parseInt(data.SECONDS_PER_SLOT) || 12,
      // 256 on mainnet, hoodi, sepolia and gnosis
      shardCommitteePeriod: parseInt(data.SHARD_COMMITTEE_PERIOD) || 256,
      capellaForkEpoch: Number.isFinite(capella) ? capella : null,
      epochsPerSyncCommitteePeriod: parseInt(data.EPOCHS_PER_SYNC_COMMITTEE_PERIOD) || 256,
      genesisTime: Number.isFinite(genesisTime) ? genesisTime : null,
    };
    if (!res.code && spec.genesisTime !== null) this.specByBase[base] = spec;
    return spec;
  }
}
