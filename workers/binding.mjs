// Private storage transport. The shared event scope fences late Wasm continuations.
export function createD1Binding(database, resources) {
  if (
    !database ||
    typeof database.prepare !== "function" ||
    typeof database.batch !== "function"
  )
    throw new Error("missing_d1_binding");
  return (input) =>
    resources.run(
      () => {
        const statements = JSON.parse(input);
        if (
          !Array.isArray(statements) ||
          statements.length === 0 ||
          statements.length > 128 ||
          statements.some(
            (s) =>
              typeof s.sql !== "string" ||
              !Array.isArray(s.params) ||
              s.params.length > 100,
          )
        )
          throw new Error("invalid_batch");
        // The base database binding always targets primary. Never use a replica session.
        return database.batch(
          statements.map(({ sql, params }) =>
            database.prepare(sql).bind(...params),
          ),
        );
      },
      (result) => {
        if (
          !Array.isArray(result) ||
          result.some((r) => !r.success || !Array.isArray(r.results))
        )
          throw new Error("invalid_receipt");
        return JSON.stringify(
          result.map(({ success, results }) => ({ success, results })),
        );
      },
    );
}
