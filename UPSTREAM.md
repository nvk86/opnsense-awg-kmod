# Upstream tracking

This repository combines two upstream lines:

1. FreeBSD kernel implementation base:
   `https://github.com/vgrebenschikov/wireguard-amnezia-kmod`
2. AmneziaWG protocol reference:
   `https://github.com/amnezia-vpn/amneziawg-linux-kernel-module`

Current protocol reference version: `3.1.20260812`.

For a new AmneziaWG Linux release:

1. diff the new Linux release against `3.1.20260812`;
2. identify protocol, UAPI, timing, packet-layout and cryptographic changes;
3. port only the applicable changes to the FreeBSD implementation;
4. build with warnings treated as errors against the target FreeBSD/OPNsense kernel tree;
5. validate userspace ABI with the matching `opnsense-awg-tools` version;
6. perform Linux <-> FreeBSD interoperability tests before tagging a release.

Repository tags should follow the upstream protocol version, for example `v3.1.20260812`. FreeBSD-only package revisions can use package revisions without changing the upstream protocol version.
