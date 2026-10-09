import { parseKeystore, checkSlashingProtection, hasDoppelgangerProtection } from "@/share/keystores";

const KEY = "a".repeat(96);
const keystore = (extra = {}) => JSON.stringify({ crypto: { kdf: {} }, pubkey: KEY, version: 4, path: "m/12381/3600/0/0/0", ...extra });
const ROOT = "0x" + "1".repeat(64);

test("keystores are recognised by their EIP-2335 shape", () => {
  expect(parseKeystore(keystore())).toEqual({ pubkey: "0x" + KEY, path: "m/12381/3600/0/0/0" });
  expect(parseKeystore(keystore({ pubkey: "0x" + KEY.toUpperCase() })).pubkey).toEqual("0x" + KEY);
  expect(parseKeystore("{ nope").error).toMatch(/JSON/);
  expect(parseKeystore(JSON.stringify({ pubkey: KEY, version: 4 })).error).toMatch(/crypto/);
  expect(parseKeystore(keystore({ version: 3 })).error).toMatch(/version 3/);
  expect(parseKeystore(keystore({ pubkey: "1234" })).error).toMatch(/public key/);
});

describe("slashing protection", () => {
  const file = (meta, data) => JSON.stringify({ metadata: meta, data });
  const meta = { interchange_format_version: "5", genesis_validators_root: ROOT };

  test("a matching file covering every key is fine", () => {
    const result = checkSlashingProtection(file(meta, [{ pubkey: "0x" + KEY }]), { genesisRoot: ROOT, pubkeys: ["0x" + KEY] });
    expect(result).toEqual({ ok: true, errors: [], missing: [] });
  });

  test("a file from another network or format is rejected", () => {
    const other = checkSlashingProtection(file({ ...meta, genesis_validators_root: "0x" + "2".repeat(64) }, []), {
      genesisRoot: ROOT,
      pubkeys: [],
    });
    expect(other.errors).toContain("it was exported on a different network");
    expect(checkSlashingProtection(file({ ...meta, interchange_format_version: "4" }, []), { genesisRoot: ROOT, pubkeys: [] }).ok).toBe(
      false
    );
    expect(checkSlashingProtection("nope", { genesisRoot: ROOT, pubkeys: [] }).ok).toBe(false);
  });

  test("keys the file does not cover are listed", () => {
    const other = "0x" + "b".repeat(96);
    const result = checkSlashingProtection(file(meta, [{ pubkey: KEY }]), { genesisRoot: ROOT, pubkeys: ["0x" + KEY, other] });
    expect(result.ok).toBe(true);
    expect(result.missing).toEqual([other]);
  });
});

test("doppelganger protection is read from each client's flag", () => {
  expect(hasDoppelgangerProtection("LighthouseValidatorService", ["--http", "--enable-doppelganger-protection"])).toBe(true);
  expect(hasDoppelgangerProtection("LighthouseValidatorService", ["--http"])).toBe(false);
  expect(hasDoppelgangerProtection("TekuValidatorService", ["--doppelganger-detection-enabled=true"])).toBe(true);
  expect(hasDoppelgangerProtection("NimbusValidatorService", ["--doppelganger-detection=false"])).toBe(false);
  expect(hasDoppelgangerProtection("LodestarValidatorService", ["--doppelgangerProtection=true"])).toBe(true);
  expect(hasDoppelgangerProtection("Web3SignerService", ["--doppelgangerProtection=true"])).toBe(false);
});
