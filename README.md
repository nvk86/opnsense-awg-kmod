# opnsense-awg-kmod

FreeBSD kernel implementation of AmneziaWG, maintained for use with OPNsense.

This tree is derived from the FreeBSD AmneziaWG kernel work by Vitaly Grebenschikov and ports the protocol changes present in AmneziaWG Linux kernel module version `3.1.20260812` to FreeBSD.

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

## Target

The current source tracks AmneziaWG protocol version `3.1.20260812` and targets FreeBSD 15.x / OPNsense 27.x.

Kernel modules must be built against the exact FreeBSD kernel sources/ABI used by the target OPNsense release.

## Build

On a matching FreeBSD source/kernel environment:

```sh
make
```

The result is `if_awg.ko`.

## Validation status

The current implementation has been validated with a matching AmneziaWG 3.1 Linux peer for configuration round-trips, handshake, bidirectional transport, header protection, content padding, randomized trailers, keepalives and rekey operation. It has also been exercised over a network path where an older AmneziaWG 2.x configuration was filtered.

This does not remove the normal requirement to rebuild and smoke-test the module for every new OPNsense/FreeBSD kernel ABI.

## Upstream

See [UPSTREAM.md](UPSTREAM.md) for source lineage and the update workflow.

## License

GPL-2.0. See [COPYING](COPYING).
