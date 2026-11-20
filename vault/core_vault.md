# Personal & Technical Second Brain Knowledge Vault

## Note 1: Architecture Invariants
- id: note-arch-001
- tags: architecture, systems, reliability
- content: Core architectural invariant: All stateful storage nodes must maintain write-ahead logs (WAL) before updating in-memory pages. Failover must be arbitrated by external consensus (etcd/Consul) with strict lease TTLs <= 10s.

## Note 2: Security & Threat Boundaries
- id: note-sec-002
- tags: security, threat-modeling, mcp
- content: MCP tools are untrusted input boundaries. Tool descriptions can be poisoned to induce prompt injections or secret exfiltration. Strict schema validation with additionalProperties=false and strict path traversal sandboxing must be enforced.

## Note 3: Incident Response Playbooks
- id: note-ops-003
- tags: sre, runbooks, incidents
- content: SRE Incident Playbook: When cascading retries threaten database thread pools, immediately activate circuit breakers, apply exponential backoff with full jitter, and execute rolling rollbacks to the last verified semver tag.
