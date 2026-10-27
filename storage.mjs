import { readFile } from "node:fs/promises";
import { join } from "node:path";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SESSION_ID = /^[0-9a-f]{128}$/;

function machineFromRow(row) {
  return {
    machineId: row.machine_id,
    claimedBy: row.claimed_by,
    registeredAt: row.registered_at,
    claimedAt: row.claimed_at,
  };
}

function sessionFromRow(row) {
  return {
    id: row.id,
    ownerSub: row.owner_sub,
    isPublic: Boolean(row.is_public),
    createdAt: row.created_at,
  };
}

async function readLegacy(path, validate, label) {
  try {
    const value = JSON.parse(await readFile(path, "utf8"));
    if (!Array.isArray(value) || value.some((record) => !validate(record))) {
      throw new Error(`Invalid legacy ${label} registry`);
    }
    return value;
  } catch (error) {
    if (error.code === "ENOENT") {
      return [];
    }
    throw error;
  }
}

export async function createStorage({ env = process.env, db: injectedDb } = {}) {
  let db = injectedDb;
  if (!db) {
    if (!env.DATABASE_URL) {
      throw new Error("DATABASE_URL is required");
    }
    let databaseUrl;
    try {
      databaseUrl = new URL(env.DATABASE_URL);
    } catch {
      throw new Error("DATABASE_URL must be an HTTPS database consumer module URL");
    }
    if (
      databaseUrl.protocol !== "https:" ||
      !databaseUrl.pathname.endsWith("/index.mjs") ||
      databaseUrl.username ||
      databaseUrl.password ||
      databaseUrl.search ||
      databaseUrl.hash
    ) {
      throw new Error(
        "DATABASE_URL must be an HTTPS database consumer module URL without credentials or query parameters",
      );
    }
    db = await import(env.DATABASE_URL);
    if (env.DB_AUTH_TOKEN) {
      db.configure({ token: env.DB_AUTH_TOKEN });
    }
  }

  const run = (s, d = []) => db.run(s, d);
  const get = (s, d = []) => db.get(s, d);
  const all = (s, d = []) => db.all(s, d);
  const transaction = (statements) => db.transaction(statements);

  await run(
    "CREATE TABLE IF NOT EXISTS relay_ids (id TEXT PRIMARY KEY, kind TEXT NOT NULL CHECK(kind IN ('machine','session')))",
  );
  await run(
    "CREATE TABLE IF NOT EXISTS machines (machine_id TEXT PRIMARY KEY, claimed_by TEXT, registered_at TEXT NOT NULL, claimed_at TEXT)",
  );
  await run(
    "CREATE TABLE IF NOT EXISTS user_sessions (id TEXT PRIMARY KEY, owner_sub TEXT NOT NULL, is_public INTEGER NOT NULL CHECK(is_public IN (0,1)), created_at TEXT NOT NULL)",
  );
  await run("CREATE INDEX IF NOT EXISTS user_sessions_owner_sub_idx ON user_sessions(owner_sub)");
  await run(
    "CREATE TABLE IF NOT EXISTS session_keys (id TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES user_sessions(id) ON DELETE CASCADE, label TEXT NOT NULL, key_hash TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL)",
  );
  await run("CREATE TABLE IF NOT EXISTS relay_migrations (name TEXT PRIMARY KEY, completed_at TEXT NOT NULL)");

  const [storedMachines, storedSessions] = await Promise.all([
    all("SELECT machine_id, claimed_by, registered_at, claimed_at FROM machines"),
    all("SELECT id, owner_sub, is_public, created_at FROM user_sessions"),
  ]);
  const migrationComplete = await get("SELECT name FROM relay_migrations WHERE name='legacy-json-v1'");
  const [legacyMachines, legacySessions] = migrationComplete
    ? [[], []]
    : await Promise.all([
        readLegacy(
          join(env.DATA_PATH || "/data", "machines.json"),
          (m) =>
            m &&
            UUID.test(m.machineId) &&
            (m.claimedBy == null ||
              (typeof m.claimedBy === "string" && m.claimedBy.trim() && m.claimedBy.length <= 512)),
          "machine",
        ),
        readLegacy(
          join(env.DATA_PATH || "/data", "sessions.json"),
          (s) =>
            s &&
            SESSION_ID.test(s.id) &&
            typeof s.ownerSub === "string" &&
            Boolean(s.ownerSub.trim()) &&
            s.ownerSub.length <= 512 &&
            typeof s.isPublic === "boolean" &&
            typeof s.createdAt === "string",
          "session",
        ),
      ]);

  const kinds = new Map();
  const reserve = (id, kind) => {
    const previous = kinds.get(id);
    if (previous && previous !== kind) {
      throw new Error("Machine/session identifier collision in database or legacy state");
    }
    kinds.set(id, kind);
  };
  for (const m of storedMachines) {
    if (!UUID.test(m.machine_id)) {
      throw new Error("Invalid machine record in database");
    }
    reserve(m.machine_id, "machine");
  }
  for (const s of storedSessions) {
    if (!SESSION_ID.test(s.id) || typeof s.owner_sub !== "string" || !s.owner_sub || ![0, 1].includes(s.is_public)) {
      throw new Error("Invalid user session record in database");
    }
    reserve(s.id, "session");
  }
  const reservations = await all("SELECT id, kind FROM relay_ids");
  for (const item of reservations) {
    if (kinds.get(item.id) !== item.kind) {
      throw new Error("Orphaned or conflicting relay ID reservation");
    }
  }

  const existingMachines = new Set(storedMachines.map((m) => m.machine_id));
  const existingSessions = new Set(storedSessions.map((s) => s.id));
  const migration = [];
  const migrationIds = new Set(kinds.keys());
  const legacySeen = new Set();
  for (const item of legacyMachines) {
    if (legacySeen.has(item.machineId)) {
      throw new Error("Duplicate legacy machine ID");
    }
    legacySeen.add(item.machineId);
    if (migrationIds.has(item.machineId)) {
      if (!existingMachines.has(item.machineId)) {
        throw new Error("Duplicate legacy machine ID");
      }
      continue;
    }
    migrationIds.add(item.machineId);
    migration.push({ kind: "machine", value: item });
  }
  for (const item of legacySessions) {
    if (legacySeen.has(item.id)) {
      throw new Error("Duplicate legacy session ID");
    }
    legacySeen.add(item.id);
    if (migrationIds.has(item.id)) {
      if (!existingSessions.has(item.id)) {
        throw new Error("Duplicate legacy session ID or machine/session collision");
      }
      continue;
    }
    migrationIds.add(item.id);
    migration.push({ kind: "session", value: item });
  }

  const migrationStatements = [];
  for (const row of storedMachines) {
    migrationStatements.push({
      s: "INSERT OR IGNORE INTO relay_ids(id,kind) VALUES(?, 'machine')",
      d: [row.machine_id],
    });
  }
  for (const row of storedSessions) {
    migrationStatements.push({ s: "INSERT OR IGNORE INTO relay_ids(id,kind) VALUES(?, 'session')", d: [row.id] });
  }
  for (const reservation of reservations) {
    migrationStatements.push({
      s: "INSERT OR IGNORE INTO relay_ids(id,kind) VALUES(?,?)",
      d: [reservation.id, reservation.kind],
    });
  }
  for (const item of migration) {
    const value = item.value;
    const id = item.kind === "machine" ? value.machineId : value.id;
    migrationStatements.push({ s: "INSERT INTO relay_ids(id,kind) VALUES(?,?)", d: [id, item.kind] });
    if (item.kind === "machine") {
      migrationStatements.push({
        s: "INSERT INTO machines(machine_id,claimed_by,registered_at,claimed_at) VALUES(?,?,?,?)",
        d: [
          value.machineId,
          value.claimedBy ?? null,
          value.registeredAt || new Date(0).toISOString(),
          value.claimedAt ?? null,
        ],
      });
    } else {
      migrationStatements.push({
        s: "INSERT INTO user_sessions(id,owner_sub,is_public,created_at) VALUES(?,?,?,?)",
        d: [value.id, value.ownerSub, value.isPublic ? 1 : 0, value.createdAt],
      });
    }
  }
  migrationStatements.push({
    s: "INSERT OR IGNORE INTO relay_migrations(name,completed_at) VALUES('legacy-json-v1',?)",
    d: [new Date().toISOString()],
  });
  if (migrationStatements.length) {
    await transaction(migrationStatements);
  }

  return {
    async ping() {
      await get("SELECT 1 AS ready");
      return true;
    },
    async getMachine(id) {
      const row = await get(
        "SELECT machine_id, claimed_by, registered_at, claimed_at FROM machines WHERE machine_id=?",
        [id],
      );
      return row ? machineFromRow(row) : null;
    },
    async listMachines() {
      return (
        await all("SELECT machine_id, claimed_by, registered_at, claimed_at FROM machines ORDER BY registered_at")
      ).map(machineFromRow);
    },
    async registerMachine(id, registeredAt = new Date().toISOString()) {
      await transaction([
        { s: "INSERT INTO relay_ids(id,kind) VALUES(?, 'machine')", d: [id] },
        {
          s: "INSERT INTO machines(machine_id,claimed_by,registered_at,claimed_at) VALUES(?,?,?,?)",
          d: [id, null, registeredAt, null],
        },
      ]);
      return this.getMachine(id);
    },
    async claimMachine(id, ownerSub, claimedAt = new Date().toISOString()) {
      await transaction([
        {
          s: "UPDATE machines SET claimed_by=COALESCE(claimed_by,?), claimed_at=COALESCE(claimed_at,?) WHERE machine_id=?",
          d: [ownerSub, claimedAt, id],
        },
      ]);
      return this.getMachine(id);
    },
    async getSession(id) {
      const row = await get("SELECT id, owner_sub, is_public, created_at FROM user_sessions WHERE id=?", [id]);
      return row ? sessionFromRow(row) : null;
    },
    async listSessions(ownerSub) {
      return (
        await all(
          "SELECT id, owner_sub, is_public, created_at FROM user_sessions WHERE owner_sub=? ORDER BY created_at DESC",
          [ownerSub],
        )
      ).map(sessionFromRow);
    },
    async createSession({ id, ownerSub, isPublic, createdAt = new Date().toISOString() }) {
      await transaction([
        { s: "INSERT INTO relay_ids(id,kind) VALUES(?, 'session')", d: [id] },
        {
          s: "INSERT INTO user_sessions(id,owner_sub,is_public,created_at) VALUES(?,?,?,?)",
          d: [id, ownerSub, isPublic ? 1 : 0, createdAt],
        },
      ]);
      return this.getSession(id);
    },
    async deleteSession(id, ownerSub) {
      await transaction([
        { s: "DELETE FROM session_keys WHERE session_id=?", d: [id] },
        { s: "DELETE FROM user_sessions WHERE id=? AND owner_sub=?", d: [id, ownerSub] },
        {
          s: "DELETE FROM relay_ids WHERE id=? AND kind='session' AND NOT EXISTS (SELECT 1 FROM user_sessions WHERE id=?)",
          d: [id, id],
        },
      ]);
    },
    async listKeys(sessionId) {
      return (
        await all("SELECT id,label,created_at FROM session_keys WHERE session_id=? ORDER BY created_at", [sessionId])
      ).map(({ id, label, created_at }) => ({ id, label, createdAt: created_at }));
    },
    async createKey({ id, sessionId, label, keyHash, createdAt }) {
      await run("INSERT INTO session_keys(id,session_id,label,key_hash,created_at) VALUES(?,?,?,?,?)", [
        id,
        sessionId,
        label,
        keyHash,
        createdAt,
      ]);
    },
    async getKey(keyHash) {
      return get("SELECT id,session_id FROM session_keys WHERE key_hash=?", [keyHash]);
    },
    async deleteKey(id, sessionId) {
      await run("DELETE FROM session_keys WHERE id=? AND session_id=?", [id, sessionId]);
    },
  };
}

export function createInMemorySqliteAdapter(database) {
  const bind = (statement, values = []) => database.prepare(statement).all(...values);
  const adapter = {
    async all(statement, values = []) {
      return bind(statement, values);
    },
    async get(statement, values = []) {
      return database.prepare(statement).get(...values);
    },
    async run(statement, values = []) {
      if (/^CREATE\s/i.test(statement) || /^DROP\s/i.test(statement)) {
        database.exec(statement);
        return {};
      }
      return database.prepare(statement).run(...values);
    },
    async transaction(statements) {
      database.exec("BEGIN IMMEDIATE");
      try {
        for (const { s, d = [], m = "run" } of statements) {
          if (m === "exec") {
            database.exec(s);
          } else if (m === "all") {
            database.prepare(s).all(...d);
          } else if (m === "get") {
            database.prepare(s).get(...d);
          } else {
            database.prepare(s).run(...d);
          }
        }
        database.exec("COMMIT");
      } catch (error) {
        database.exec("ROLLBACK");
        throw error;
      }
    },
  };
  return adapter;
}
