import * as generated from "./pkg/lenso_access_control_workers_smoke.js";
import wasmModule from "./pkg/lenso_access_control_workers_smoke_bg.wasm";
import {
  createWorkersHttpHost,
  createEventScope,
} from "@lenso/workers-runtime";
import { createD1Binding } from "./binding.mjs";
export default createWorkersHttpHost({
  bindings: {
    ...generated,
    async handle_http(_input, scope) {
      try {
        const outcome = scope.mode.startsWith("race-")
          ? JSON.parse(await generated.race(scope.batch, scope.mode, scope.id))
          : scope.mode === "setup"
            ? (await generated.migrate(scope.batch), "setup")
            : await generated.exercise(
                scope.batch,
                scope.mode,
                scope.id,
                scope.close,
              );
        return JSON.stringify({
          status: 200,
          headers: [],
          body: Array.from(
            new TextEncoder().encode(JSON.stringify({ outcome })),
          ),
          shutdown: "clean",
        });
      } catch (error) {
        console.error(error);
        throw error;
      }
    },
  },
  wasmModule,
  limits: { eventLimitMs: 30000 },
  createScope(request, env) {
    const url = new URL(request.url),
      mode = url.searchParams.get("mode") || "success",
      id = url.searchParams.get("id") || "default";
    return createEventScope((resources) => ({
      mode,
      id,
      close: () => resources.abort(),
      batch:
        mode === "throws"
          ? () => {
              throw new Error("synthetic-private-data");
            }
          : mode === "malformed"
            ? async () => JSON.stringify([{ success: false, results: [] }])
            : createD1Binding(
                mode === "missing-schema" ? env.EMPTY : env.ACCESS,
                resources,
              ),
    }));
  },
});
