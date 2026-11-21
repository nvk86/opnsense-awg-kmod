#!/usr/bin/env python3
"""
Model peer-count transitions in wgc_set()/wg_peer_add().

This is a standalone semantic model, not a kernel execution test.
No FreeBSD interfaces, sockets, or modules are accessed.
"""

from dataclasses import dataclass

MAX_REMOTE_PER_LOCAL = 1 << 20


@dataclass(frozen=True)
class Op:
    key: str
    remove: bool = False


def simulate(
    existing,
    operations,
    *,
    limit=MAX_REMOTE_PER_LOCAL,
    replace_peers=False,
    new_self_key=None,
):
    """
    Reproduce peer membership transitions in ioctl order.

    Return (errno, resulting_peers, peak_count).

    ENOSPC is represented by the string "ENOSPC".
    """

    peers = set() if replace_peers else set(existing)

    if len(peers) > limit:
        raise ValueError("Invalid initial peer count")

    # A new local identity removes a conflicting existing peer.
    if new_self_key is not None:
        peers.discard(new_self_key)

    peak = len(peers)

    for op in operations:
        # wg_peer_add() ignores the interface's own public key.
        if new_self_key is not None and op.key == new_self_key:
            continue

        if op.remove:
            peers.discard(op.key)
            continue

        if op.key not in peers:
            if len(peers) >= limit:
                return "ENOSPC", peers, peak
            peers.add(op.key)

        peak = max(peak, len(peers))

    return None, peers, peak


def check(name, expected, **kwargs):
    actual = simulate(**kwargs)

    assert actual == expected, (
        f"{name}: expected {expected!r}, got {actual!r}"
    )

    print(f"PASS: {name}")


def main():
    check(
        "existing peer update",
        (None, {"A", "B", "C"}, 3),
        existing={"A", "B", "C"},
        operations=[Op("A")],
        limit=3,
    )

    check(
        "addition at full capacity",
        ("ENOSPC", {"A", "B", "C"}, 3),
        existing={"A", "B", "C"},
        operations=[Op("D")],
        limit=3,
    )

    check(
        "remove before add",
        (None, {"A", "B", "D"}, 3),
        existing={"A", "B", "C"},
        operations=[Op("C", True), Op("D")],
        limit=3,
    )

    check(
        "add before remove still fails",
        ("ENOSPC", {"A", "B", "C"}, 3),
        existing={"A", "B", "C"},
        operations=[Op("D"), Op("C", True)],
        limit=3,
    )

    check(
        "replace peers clears capacity",
        (None, {"D", "E"}, 2),
        existing={"A", "B", "C"},
        operations=[Op("D"), Op("E")],
        replace_peers=True,
        limit=3,
    )

    check(
        "duplicate additions",
        (None, {"A", "B"}, 2),
        existing={"A"},
        operations=[Op("B"), Op("B"), Op("B")],
        limit=2,
    )

    check(
        "add remove add",
        (None, {"A", "B"}, 2),
        existing={"A"},
        operations=[Op("B"), Op("B", True), Op("B")],
        limit=2,
    )

    check(
        "remove nonexistent peer",
        (None, {"A"}, 1),
        existing={"A"},
        operations=[Op("Z", True)],
        limit=1,
    )

    check(
        "new self key removes conflicting peer",
        (None, {"A", "C"}, 2),
        existing={"A", "B"},
        operations=[Op("C")],
        new_self_key="B",
        limit=2,
    )

    check(
        "new self key is ignored in peer list",
        (None, {"A"}, 1),
        existing={"A"},
        operations=[Op("B"), Op("B", True)],
        new_self_key="B",
        limit=1,
    )

    check(
        "self key ignored before removal",
        (None, {"A"}, 1),
        existing={"A"},
        operations=[Op("B", True), Op("B")],
        new_self_key="B",
        limit=1,
    )

    check(
        "capacity exceeded after intermediate additions",
        ("ENOSPC", {"A", "B", "C"}, 3),
        existing={"A"},
        operations=[
            Op("B"),
            Op("C"),
            Op("D"),
            Op("B", True),
        ],
        limit=3,
    )

    check(
        "actual kernel limit boundary",
        (None, {"A"}, 1),
        existing=set(),
        operations=[Op("A")],
        limit=MAX_REMOTE_PER_LOCAL,
    )

    assert MAX_REMOTE_PER_LOCAL == 1048576
    print("\nALL 13 PEER CAPACITY MODEL TESTS PASSED")


if __name__ == "__main__":
    main()
