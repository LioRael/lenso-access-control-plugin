import assert from "node:assert/strict";
import { readFile, rm } from "node:fs/promises";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
const require = createRequire(import.meta.url),
  owner = createRequire(require.resolve("wrangler/package.json"));
const { build } = owner("esbuild"),
  { Miniflare } = owner("miniflare");
const root = fileURLToPath(new URL(".", import.meta.url)),
  output = `${root}proof.bundle.mjs`;
await build({
  entryPoints: [`${root}worker.mjs`],
  outfile: output,
  bundle: true,
  format: "esm",
  platform: "browser",
  target: "es2022",
  plugins: [
    {
      name: "wasm",
      setup(b) {
        b.onResolve({ filter: /\.wasm$/ }, (args) => ({
          path: args.path,
          external: true,
        }));
      },
    },
  ],
});
const mf = new Miniflare({
  modules: true,
  scriptPath: output,
  modulesRoot: root,
  modulesRules: [{ type: "CompiledWasm", include: ["**/*.wasm"] }],
  compatibilityDate: "2026-07-08",
  d1Databases: ["ACCESS", "EMPTY"],
});
let passed = 0;
async function run(mode, id = mode) {
  const response = await mf.dispatchFetch(
    `http://local/?mode=${mode}&id=${id}`,
  );
  const body = await response.text();
  assert.equal(response.status, 200, `${mode}: ${body}`);
  assert(!body.includes("synthetic-private-data"));
  passed++;
  return JSON.parse(body).outcome;
}
try {
  await run("setup");
  for (const mode of [
    "success",
    "conformance",
    "wrong-audience",
    "expired",
    "closed",
    "missing-schema",
    "wrong-binding",
    "throws",
    "malformed",
  ]) {
    assert.equal(
      await run(mode),
      ["missing-schema", "wrong-binding", "throws", "malformed"].includes(mode)
        ? "startup-rejected"
        : "passed",
    );
  }
  await Promise.all(
    Array.from({ length: 4 }, (_, i) => run("success", `concurrent-${i}`)),
  );
  // Different events must independently prepare and use the same durable DB.
  const db = await mf.getD1Database("ACCESS");
  const rows = await db
    .prepare(
      "SELECT scope_id,policy_revision FROM access_control_scopes WHERE scope_id LIKE ? ORDER BY scope_id",
    )
    .bind("concurrent-%")
    .all();
  assert.equal(rows.results.length, 4);
  assert(rows.results.every((r) => r.policy_revision === 2));
  assert.equal(
    (
      await db
        .prepare("SELECT count(*) AS n FROM access_control_operation")
        .first()
    ).n,
    0,
  );
  // Competing actor revocation and mutation serialize in one atomic batch.
  for (let i = 0; i < 6; i++) {
    const id = `race-${i}`;
    await run("race-setup", id);
    const [create, revoke] = await Promise.all([
      run("race-create", id),
      run("race-revoke", id),
    ]);
    assert.equal(revoke.changed, true);
    assert.equal(revoke.revision, create.allowed ? "4" : "3");
    const state = await db
      .prepare(
        "SELECT policy_revision,(SELECT count(*) FROM access_control_roles r WHERE r.scope_kind=s.scope_kind AND r.scope_id=s.scope_id AND r.role_id='viewer') AS viewer FROM access_control_scopes s WHERE scope_kind='race' AND scope_id=?",
      )
      .bind(id)
      .first();
    assert.equal(state.policy_revision, create.allowed ? 4 : 3);
    assert.equal(state.viewer, create.allowed ? 1 : 0);
    const repeats = await Promise.all(
      Array.from({ length: 4 }, () => run("race-assign", id)),
    );
    assert.equal(repeats.filter((r) => r.changed).length, 1);
    assert(
      repeats.every((r) => Number(r.revision) === state.policy_revision + 1),
    );
  }
  const wasm = await readFile(
    `${root}pkg/lenso_access_control_workers_smoke_bg.wasm`,
  );
  console.log(
    JSON.stringify(
      {
        passed,
        runtime: "workerd",
        workers_runtime: "0.1.2",
        wasm_sha256: createHash("sha256").update(wasm).digest("hex"),
      },
      null,
      2,
    ),
  );
} finally {
  await mf.dispose();
  await rm(output, { force: true });
}
