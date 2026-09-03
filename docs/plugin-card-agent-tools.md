# Access Control Agent Tools Plugin card

## Owner and deletion boundary

`lenso-access-control-agent-tools-plugin` is a private, stateless adapter.
Removing it removes the Console Agent's Access Control Tools without removing
roles, bindings, policy revisions, or RBAC decisions.

## Roles

- Provides `lenso.agent.tool-provider@2` in the `tool-providers` root slot.
- Requires exactly one `lenso.access-control-directory@1` Provider for role
  inspection.
- Requires exactly one `lenso.access-control-admin@1` Provider for
  post-bootstrap mutation.
- Exposes three parallel-safe reads and five exclusive mutations. It does not
  expose `bootstrap_scope`.

## Authority boundary

The adapter decodes exact Capability request schemas and forwards the original
Invocation Context. The Access Control provider remains the final authority:
it verifies the operation-audienced sealed ActorAssertion and current scoped
administration permission in the same transaction as each mutation. Directory
reads remain separately admitted by exact Plugin Instance configuration.

The adapter owns no configuration, state, lifecycle resources, role policy, or
database access. It does not decide whether an Organization, Project, or other
opaque scope exists, and it cannot make an RBAC allow sufficient for a target
Plugin's final resource authorization.
