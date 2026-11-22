# opnsense-awg-kmod

FreeBSD kernel implementation of AmneziaWG, maintained for use with OPNsense.

This tree is derived from the FreeBSD AmneziaWG kernel work by Vitaly Grebenschikov and tracks the protocol changes present in AmneziaWG Linux kernel module version `3.1.20260906`.

The installed kernel module and interface namespace are intentionally separate from the in-tree WireGuard implementation:

- module: `if_awg.ko`
- module name: `if_awg`
- interface cloner: `awg`
- interfaces: `awg0`, `awg1`, ...

Internal `wg_*` source symbols are retained where they are implementation details.

## Implemented AmneziaWG 3.1 features

- H1-H4 ranges and S1-S4 packet padding
- I1-I5 junk packet programs
- `HeaderProtectionKey` with ChaCha20 header protection
- `ContentPaddingAddition`
- configurable timing ranges:
  - `RekeyAfterTime`
  - `RekeyTimeout`
  - `RejectAfterTime`
  - `KeepaliveTimeout`
  - `MaxHandshakeAttempts`
- ranged `PersistentKeepalive`
- `RandomTrailers`
- `DisableCookies`

The FreeBSD userspace ABI uses nvlist fields and is paired with the `opnsense-awg-tools` repository.

## Compatibility and limitations

- The FreeBSD port intentionally permits H1-H4 values 1-4, provided the configured header ranges remain unambiguous. This differs from upstream validation policy.
- An all-zero `HeaderProtectionKey` **disables** header protection in this FreeBSD implementation. The Linux AWG 3.1 implementation treats a configured all-zero 32-byte key as an **enabled** key; do not use an all-zero HP key for cross-platform interoperability.
- This build does not define `AWG2_CLIENT_COMPAT`; legacy AWG2 compatibility is not guaranteed.
- `SIOCSWG` performs extensive preflight validation, but runtime failures during the commit phase can still leave a partially applied configuration. Do not assume full transactional atomicity of a multi-field update.
- Kernel-module unload and callback teardown require validation against the exact FreeBSD kernel version and execution environment. Successful traffic tests alone do not prove all unload races safe.


## Target

The current source tracks AmneziaWG protocol version `3.1.20260906` and targets FreeBSD 15.x / OPNsense 27.x.

Kernel modules must be built against the exact FreeBSD kernel sources/ABI used by the target OPNsense release.

## Build

On a matching FreeBSD source/kernel environment:

```sh
make
```

The result is `if_awg.ko`.

## Validation status

The current implementation has been validated with a matching AmneziaWG 3.1 Linux peer for configuration round-trips, handshake, bidirectional transport, header protection, content padding, randomized trailers, keepalives and rekey operation. It has also been exercised over a network path where an older AmneziaWG 2.x configuration was filtered.

The `3.1.20260906` upstream audit does not require an additional FreeBSD packet-path change: I1-I5 and dummy junk packets already bypass the RandomTrailers path, while handshake and cookie packets retain the expected trailer behavior. Relevant `3.1.20260827`/`3.1.20260828` protocol fixes were already present in this FreeBSD implementation; Linux kernel compatibility-only changes do not apply.

This does not remove the normal requirement to rebuild and smoke-test the module for every new OPNsense/FreeBSD kernel ABI.

## Upstream

See [UPSTREAM.md](UPSTREAM.md) for source lineage and the update workflow.

## License

GPL-2.0. See [COPYING](COPYING).
