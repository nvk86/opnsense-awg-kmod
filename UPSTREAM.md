# Upstream tracking

This repository combines two upstream lines:

1. FreeBSD kernel implementation base:
   `https://github.com/vgrebenschikov/wireguard-amnezia-kmod`
2. AmneziaWG protocol reference:
   `https://github.com/amnezia-vpn/amneziawg-linux-kernel-module`

Current protocol reference version: `3.1.20260906`.

## 3.1.20260812 -> 3.1.20260906 audit

The Linux upstream contains seven commits after `v3.1.20260812`. Their applicability to the FreeBSD port is:

- `3958cece` — header-protection lock initialization/write locking: already implemented with a FreeBSD `rwlock`, initialized in `awg_header_protection_init()` and write-locked in `awg_header_protection_set_key()`.
- `0bcc6dfa` — Linux kernel 7.1.5+ socket compatibility: not applicable to FreeBSD.
- `40c812eb` — Linux netlink `strscpy` compatibility: not applicable to the FreeBSD nvlist ABI.
- `b72bb7a6` — Linux 7.2 workqueue flag compatibility: not applicable to FreeBSD gtaskqueue.
- `7fc01457` — use `UDPWindow` for `ContentPaddingAddition`: already implemented in the FreeBSD transport padding path.
- `3c38e168` — `DisableCookies` disables the underload/cookie mechanism: already implemented in the FreeBSD handshake receive path.
- `4569c4c6` — do not append `RandomTrailers` to I1-I5 and dummy junk packets: already satisfied by the FreeBSD send architecture. I1-I5 and dummy junk packets use `wg_peer_send_buf()` directly; handshake/cookie packets use the padding/trailer helpers.

Therefore the `3.1.20260906` tracking update is semantically equivalent without a new FreeBSD packet-path patch.

For a new AmneziaWG Linux release:

1. diff the new Linux release against the protocol reference version recorded above;
2. identify protocol, UAPI, timing, packet-layout and cryptographic changes;
3. port only the applicable changes to the FreeBSD implementation;
4. build with warnings treated as errors against the target FreeBSD/OPNsense kernel tree;
5. validate userspace ABI with the matching `opnsense-awg-tools` version;
6. perform Linux <-> FreeBSD interoperability tests before tagging a release.

Repository tags should follow the upstream protocol version, for example `v3.1.20260906`. FreeBSD-only package revisions can use package revisions without changing the upstream protocol version.
