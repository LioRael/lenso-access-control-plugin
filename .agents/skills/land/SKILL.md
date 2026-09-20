# Land Access Control changes

This is an optional agent entry point. The common contract is
[`CONTRIBUTING.md`](../../../CONTRIBUTING.md). Delta users may run this through
the Delta Land action; other agents and plain Git users must perform the same
steps with Git and GitHub APIs. `/land` is not a universal shell command or
permission.

1. Read `AGENTS.md`, `CONTRIBUTING.md`, status, diff, and remotes. Fetch
   `origin/main` and record its full base SHA.
2. Obtain meaningful review of the final diff (Delta Review, or an Issue
   review naming the immutable SHA), and absorb fixes before candidate CI.
3. Run focused checks. Push the final commit once to a unique
   `delta/verify/lenso-access-control-plugin/<attempt>` ref.
4. Accept only the `CI` run caused by that push with the exact repository,
   workflow, ref, head SHA, attempt, and successful required `quality` and
   `workers` jobs.
5. Refresh `origin/main`; if it advanced, integrate and repeat review and
   candidate CI. Otherwise push the exact verified SHA normally to `main`.
   Read back remote `main`, prove the candidate is an ancestor, and remove the
   task-owned candidate ref. Never force-push or rewrite a verified commit.

Release workflow dispatch is a separate, read-only dry-run using an immutable
landed SHA and the matching candidate run evidence. It does not publish.
