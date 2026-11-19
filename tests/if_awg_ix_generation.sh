#!/usr/libexec/atf-sh

atf_test_case awg_ix_generation

awg_ix_generation_head()
{
    atf_set descr "Verify generated AWG I1-I5 UDP packets"
    atf_set require.user root
    atf_set require.progs "awg python3 tcpdump jail jexec"
}

awg_ix_generation_body()
{
    JAIL="awg-ix-atf-$$"
    CAPTURE_PID=""

    cleanup()
    {
        if [ -n "$CAPTURE_PID" ]; then
            kill -INT "$CAPTURE_PID" 2>/dev/null || true
            wait "$CAPTURE_PID" 2>/dev/null || true
        fi
        jail -r "$JAIL" >/dev/null 2>&1 || true
    }

    trap cleanup EXIT
    trap 'exit 1' HUP INT TERM

    jail -c name="$JAIL" persist vnet=new path=/ ||
        atf_fail "Cannot create VNET jail"

    jexec "$JAIL" ifconfig lo0 inet 127.0.0.1/8 up ||
        atf_fail "Cannot configure loopback"

    IFACE=$(jexec "$JAIL" ifconfig awg create) ||
        atf_fail "Cannot create AWG interface"

    awg genkey > private
    awg genkey > peer-private
    awg pubkey < peer-private > peer-public

    jexec "$JAIL" awg set "$IFACE" \
        private-key "$(pwd)/private" \
        listen-port 51820 \
        i1 '<b 0xdeadbeef><r 1><c><t>' \
        i2 '<b 0x01020304><r 1448>' \
        i3 '<b 0xaabbcc><t>' \
        i4 '<b 0x11223344><rc 16>' \
        i5 '<b 0x55><rd 31>' ||
        atf_fail "Cannot configure I1-I5"

    PEER=$(cat peer-public)

    jexec "$JAIL" awg set "$IFACE" \
        peer "$PEER" \
        endpoint 127.0.0.1:51821 \
        allowed-ips 10.255.255.2/32 ||
        atf_fail "Cannot configure peer"

    jexec "$JAIL" ifconfig "$IFACE" inet 10.255.255.1/24 up ||
        atf_fail "Cannot bring up AWG interface"

    jexec "$JAIL" tcpdump -ni lo0 -s 0 -U \
        -w "$(pwd)/capture.pcap" \
        'udp and dst port 51821' \
        > tcpdump.log 2>&1 &

    CAPTURE_PID=$!

    # Wait until tcpdump has attached its capture filter.
    READY=0
    ATTEMPT=0

    while [ "$ATTEMPT" -lt 50 ]; do
        if grep -q 'listening on lo0' tcpdump.log; then
            READY=1
            break
        fi

        if ! kill -0 "$CAPTURE_PID" 2>/dev/null; then
            break
        fi

        sleep 0.1
        ATTEMPT=$((ATTEMPT + 1))
    done

    if [ "$READY" -ne 1 ]; then
        cat tcpdump.log
        atf_fail "tcpdump did not become ready"
    fi

    jexec "$JAIL" ping -c 1 -t 2 10.255.255.2 >/dev/null 2>&1 || true
    sleep 2

    kill -INT "$CAPTURE_PID" 2>/dev/null || true
    wait "$CAPTURE_PID" 2>/dev/null || true
    CAPTURE_PID=""

    python3 "$(atf_get_srcdir)/awg_ix_pcap.py" capture.pcap ||
        atf_fail "AWG I1-I5 PCAP verification failed"
}

atf_init_test_cases()
{
    atf_add_test_case awg_ix_generation
}
