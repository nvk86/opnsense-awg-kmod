#!/usr/bin/env python3

from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "if_wg.c"

source = SOURCE.read_text()

def extract_function(name, next_name):
    pattern = rf"static int\s+{name}\s*\([^;{{}}]*\)\s*\{{"
    matches = list(re.finditer(pattern, source))

    if len(matches) != 1:
        raise AssertionError(
            f"Expected one definition of {name}, found {len(matches)}"
        )

    start = matches[0].start()
    end = source.find(f"\nstatic int\n{next_name}(", start)

    if end == -1:
        raise AssertionError(f"Cannot locate {next_name}")

    return source[start:end]


def check(condition, message):
    if not condition:
        raise AssertionError(message)
    print(f"PASS: {message}")


validate = extract_function("wg_peer_validate", "wg_peer_add")
setter = extract_function("wgc_set", "wgc_get")

check(
    'nvlist_exists_binary(nvl, "public-key")' in validate,
    "public-key presence validated",
)

check(
    "size != WG_KEY_SIZE" in validate,
    "public-key length validated",
)

check(
    "noise_local_keys(" not in validate,
    "preflight does not skip current self-key",
)

check(
    'nvlist_exists_bool(nvl, "remove")' in validate,
    "remove-peer shortcut preserved",
)

check(
    validate.index('nvlist_exists_bool(nvl, "remove")')
    < validate.index('nvlist_exists_binary(nvl, "endpoint")'),
    "remove-peer semantics preserved before endpoint validation",
)

check(
    "wg_peer_validate(sc, nvl_peers[i])" in setter,
    "wgc_set invokes peer preflight",
)

check(
    setter.index("wg_peer_validate(sc, nvl_peers[i])")
    < setter.index("wg_peer_destroy_all(sc)"),
    "peer validation precedes replace-peers",
)

check(
    setter.index("wg_peer_validate(sc, nvl_peers[i])")
    < setter.index("wg_peer_add(sc, nvl_peers[i])"),
    "peer validation precedes peer application",
)

print("\nALL PEER PREFLIGHT SOURCE CHECKS PASSED")
