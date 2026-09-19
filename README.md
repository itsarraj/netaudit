# netaudit

Which of your listening ports are reachable from the network, not just
localhost. Not "what's on port 3000" (`whatport`, elsewhere in this
workspace, answers that) — this flips the question to an audit: scan
*every* listening socket and flag the ones bound to `0.0.0.0`/`::`
instead of `127.0.0.1`/`::1`, the exact mistake that leaves a dev
Postgres or Redis reachable from the network.

## Usage

```bash
netaudit               # exposed sockets only (the ones worth looking at)
netaudit --all         # + loopback-bound (safe) ones, full picture
netaudit --json
```

Exit code `1` if anything on a well-known database/admin-API port
(Postgres, MySQL, Redis, MongoDB, the unauthenticated Docker API, ...) is
bound to every interface — CI/cron-friendly, so this can gate a deploy or
page someone.

## How it classifies

Reads `/proc/net/tcp`/`/proc/net/tcp6` directly (same technique
`whatport` uses, reimplemented independently here rather than shared —
see `tools/README.md`'s convention on why each tool stays a standalone
crate). Every listening socket's bound address is one of: `Any`
(`0.0.0.0`/`::`, reachable from anywhere), `Loopback` (this machine
only), or `Specific` (bound to one interface IP — not "every interface,"
but still reachable from whatever network that interface is actually on,
so still reported, just without the extra severity). A port additionally
matching a known database/cache/admin-API port gets flagged by name.

## Status: built and verified against this real machine, including a live-caught bug

- **17 unit tests** (`cargo test --lib`): IPv4 address classification —
  `0.0.0.0` is `Any`, `127.x.x.x` (the whole loopback range, not just
  `127.0.0.1`) is `Loopback`, everything else `Specific`; risky-port
  recognition vs. ordinary web ports correctly *not* flagged; malformed
  hex is a clean error, not a panic. **IPv6 classification tests use the
  exact raw hex values this workspace confirmed live** (see below) rather
  than derived/assumed encodings.
- **The IPv6 byte layout was verified empirically before being coded,
  not assumed from documentation**: bound a real Python socket to `::1`
  and separately to `::` on this actual machine, read the real
  `/proc/net/tcp6` output both times, and only then wrote the decoder —
  confirming the kernel's per-4-byte-word little-endian encoding
  (`::1` → `00000000000000000000000001000000`, `::` → all zeros) against
  ground truth instead of getting subtly wrong byte-order code that
  passed self-consistent-but-wrong tests.
- **A real bug caught and fixed via live testing, not a unit test**:
  piping real output into `head` (`netaudit --all | head -5`, an entirely
  normal way to use this) **panicked** — `println!` aborts the process
  the instant the reader goes away, an obvious thing to hit for a tool
  whose output people will pipe into `head`/`less`/`grep`. Fixed by
  writing through a `BrokenPipe`-tolerant wrapper instead of bare
  `println!`; reverified with the same `| head` pipeline afterward,
  clean exit, no panic.
- **Live-verified against this real machine's real listening sockets**:
  found real exposed services (SSH on `0.0.0.0`/`::` — expected for a
  real box — plus a couple of others), and separately bound a **real fake
  Postgres to `0.0.0.0:5432`** to confirm the actual point of this tool:
  reported as `EXPOSED ... port 5432 ... [PostgreSQL]`, correctly
  resolved to the real PID and process name, and — the part that actually
  matters for CI/cron use — the process **exit code flipped to `1`**.

**Not done / deliberately deferred**: UDP sockets (`/proc/net/udp` —
this only reads TCP, matching `whatport`'s same scope call, since "what's
listening" for the exposed-database-mistake case is overwhelmingly TCP);
full RFC 5952 IPv6 address compression in `Specific` address display
(shown as plain colon-separated hex groups instead — correct information,
just not the canonically shortened form); and firewall-awareness (a port
bound to `0.0.0.0` might still be blocked by `iptables`/`nftables`/a cloud
security group — this reports what the *socket* is bound to, not whether
traffic can actually reach it, a real and meaningful gap between "looks
exposed" and "is reachable").
