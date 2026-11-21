#!/usr/bin/env python3
"""Compile and execute the actual if_wg.c capacity validator with mock kernel APIs."""
from pathlib import Path
import subprocess
import tempfile
import shutil
import sys

source = Path('if_wg.c').read_text()

def extract(signature):
    assert source.count(signature) == 1, f'expected exactly one {signature}'
    begin = source.index(signature)
    start = source.index('{', begin)
    depth = 0
    for i in range(start, len(source)):
        if source[i] == '{': depth += 1
        if source[i] == '}':
            depth -= 1
            if depth == 0:
                return source[begin:i + 1]
    raise RuntimeError('unbalanced braces')

hash_fn = extract('static uint64_t\nwg_capacity_hash(')
entry_marker = 'struct wg_capacity_entry {'
assert source.count(entry_marker) == 1, 'expected one capacity entry struct'
entry_start = source.index(entry_marker)
entry_end = source.index('};', entry_start) + len('};')
entry_def = source[entry_start:entry_end]
validator = extract('static int\nwg_peer_capacity_validate(')
assert 'WG_CAPACITY_MAX_REMOTE' in source

prelude = r'''
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#define WG_KEY_SIZE 32
#define SIPHASH_KEY_LENGTH 16
#define WG_CAPACITY_MAX_REMOTE (1U << 20)
#define M_TEMP 1
#define M_NOWAIT 2
#define M_ZERO 4
#define SX_XLOCKED 1
#define sx_assert(a,b) ((void)0)
#define explicit_bzero(p,n) memset((p),0,(n))
#define timingsafe_bcmp(a,b,n) memcmp((a),(b),(n))
typedef struct { int dummy; } SIPHASH_CTX;
/* Forced collisions exercise linear probing; cryptographic hash itself is not tested. */
static uint64_t SipHashX(SIPHASH_CTX *ctx, int a, int b,
    const uint8_t *key, const void *data, size_t len)
{ (void)ctx; (void)a; (void)b; (void)key; (void)data; (void)len; return 0; }
/* FreeBSD libc already declares and provides arc4random_buf(). */
static bool allocation_fail;
static int allocations, frees, outstanding;
static void *mock_mallocarray(size_t n, size_t sz, int type, int flags)
{
    (void)type; (void)flags;
    if (allocation_fail || (sz && n > SIZE_MAX / sz)) return NULL;
    void *p = calloc(n, sz);
    if (p) { allocations++; outstanding++; }
    return p;
}
static void mock_free(void *p, int type)
{ (void)type; if (p) { frees++; outstanding--; } free(p); }
#define mallocarray mock_mallocarray
#define free mock_free
struct noise_local { int unused; };
struct noise_remote { int unused; };
struct wg_softc { int sc_lock; size_t sc_peers_num; struct noise_local *sc_local; };
typedef struct nvlist {
    bool has_peers, has_replace, replace, has_private, has_public, has_remove, remove;
    uint8_t private_key[32], public_key[32];
    size_t private_len, public_len, count;
    const struct nvlist **peers;
} nvlist_t;
static bool nvlist_exists_nvlist_array(const nvlist_t *n, const char *s)
{ (void)s; return n->has_peers; }
static const nvlist_t *const *nvlist_get_nvlist_array(const nvlist_t *n,
    const char *s, size_t *count)
{ (void)s; *count=n->count; return n->peers; }
static bool nvlist_exists_bool(const nvlist_t *n, const char *s)
{ return strcmp(s,"remove")==0 ? n->has_remove : n->has_replace; }
static bool nvlist_get_bool(const nvlist_t *n, const char *s)
{ return strcmp(s,"remove")==0 ? n->remove : n->replace; }
static bool nvlist_exists_binary(const nvlist_t *n, const char *s)
{ return strcmp(s,"private-key")==0 ? n->has_private : n->has_public; }
static const void *nvlist_get_binary(const nvlist_t *n, const char *s, size_t *len)
{ if (!strcmp(s,"private-key")) { *len=n->private_len; return n->private_key; }
  *len=n->public_len; return n->public_key; }
static bool has_identity;
static uint8_t local_public[32], local_private[32];
static bool existing[64];
static int noise_local_keys(struct noise_local *l, uint8_t *pub, uint8_t *priv)
{ (void)l; if (!has_identity) return ENXIO;
  if (pub) memcpy(pub,local_public,32); if (priv) memcpy(priv,local_private,32); return 0; }
static bool curve25519_generate_public(uint8_t *pub, const void *priv)
{ memcpy(pub,priv,32); return true; }
static struct noise_remote remote_stub;
static struct noise_remote *noise_remote_lookup(struct noise_local *l, const uint8_t *key)
{
    (void)l;
    for (int i = 0; i < 64; i++) {
        if (existing[i] && key[0] == i &&
            !memcmp(key + 1, (uint8_t[31]){0}, 31)) {
            return &remote_stub;
        }
    }
    return NULL;
}
static void noise_remote_put(struct noise_remote *r) { (void)r; }
'''

main = r'''
static uint32_t rng=0x12ab34cd;
static uint32_t rnd(void) { rng ^= rng<<13; rng ^= rng>>17; rng ^= rng<<5; return rng; }
static void keyset(uint8_t *p, unsigned v) { memset(p,0,32); p[0]=(uint8_t)v; }
static void check(bool condition, const char *message)
{ if (!condition) { fprintf(stderr,"FAIL: %s\n",message); exit(1); } }
/* Independent reference model: ordered membership transitions, no hash table. */
static int reference(const nvlist_t *req, size_t initial)
{
    bool state[64]; memcpy(state,existing,sizeof(state));
    size_t used=req->replace ? 0 : initial;
    if (req->replace) memset(state,0,sizeof(state));
    bool identity=has_identity;
    unsigned self=local_public[0];
    bool changed=false;
    if (req->has_private) {
        changed=!has_identity || memcmp(local_private,req->private_key,32)!=0;
        if (changed) {
            identity=true; self=req->private_key[0];
            if (!req->replace && state[self]) { state[self]=false; used--; }
        }
    }
    for (size_t j=0;j<req->count;j++) {
        const nvlist_t *p=req->peers[j];
        if (p->public_len!=32) return EINVAL;
        unsigned id=p->public_key[0];
        if (identity && id==self) continue;
        if (p->remove) {
            if (state[id]) { state[id]=false; used--; }
        } else if (!state[id]) {
            if (used >= WG_CAPACITY_MAX_REMOTE) return ENOSPC;
            state[id]=true; used++;
        }
    }
    return 0;
}
int main(void)
{
    struct noise_local local={0};
    struct wg_softc sc={.sc_local=&local};
    nvlist_t req={.has_peers=true}, ops[256];
    const nvlist_t *ptrs[256];
    req.peers=ptrs;
    for (int trial=0;trial<4000;trial++) {
        memset(existing,0,sizeof(existing));
        has_identity=(rnd()%2)==0;
        keyset(local_public,rnd()%64);
        keyset(local_private,rnd()%64);
        size_t used=0;
        for (int i=0;i<64;i++) if ((rnd()%4)==0) { existing[i]=true; used++; }
        sc.sc_peers_num=used;
        req.has_replace=true; req.replace=(rnd()%4)==0;
        req.has_private=(rnd()%3)==0;
        req.private_len=32;
        keyset(req.private_key,rnd()%64);
        req.count=rnd()%256;
        for (size_t j=0;j<req.count;j++) {
            ops[j]=(nvlist_t){.has_public=true,.public_len=32,
                .has_remove=true,.remove=(rnd()%2)==0};
            keyset(ops[j].public_key,rnd()%64);
            ptrs[j]=&ops[j];
        }
        int expected=reference(&req,used);
        int actual=wg_peer_capacity_validate(&sc,&req);
        if (actual!=expected) {
            fprintf(stderr,"trial=%d actual=%d expected=%d count=%zu replace=%d\n",
                trial,actual,expected,req.count,req.replace);
            return 1;
        }
        check(outstanding==0,"memory leak in random trial");
    }
    puts("PASS: 4000 randomized sequences, forced hash collisions");
    memset(existing,0,sizeof(existing));
    has_identity=false;
    sc.sc_peers_num=WG_CAPACITY_MAX_REMOTE;
    req.has_private=false; req.replace=false; req.count=1;
    ops[0]=(nvlist_t){.has_public=true,.public_len=32};
    keyset(ops[0].public_key,42); ptrs[0]=&ops[0];
    check(wg_peer_capacity_validate(&sc,&req)==ENOSPC,"full capacity");
    check(outstanding==0,"memory leak on ENOSPC");
    puts("PASS: real capacity boundary and cleanup");
    allocation_fail=true;
    check(wg_peer_capacity_validate(&sc,&req)==ENOMEM,"allocation failure");
    check(outstanding==0,"memory leak on ENOMEM");
    allocation_fail=false;
    puts("PASS: allocation failure");
    ops[0].public_len=31;
    check(wg_peer_capacity_validate(&sc,&req)==EINVAL,"invalid public key length");
    check(outstanding==0,"memory leak on EINVAL");
    puts("PASS: invalid input and cleanup");
    printf("PASS: allocations=%d frees=%d outstanding=%d\n",allocations,frees,outstanding);
    return 0;
}
'''

compiler = shutil.which('cc') or shutil.which('clang')
if not compiler:
    sys.exit('STOP: C compiler not found')
with tempfile.TemporaryDirectory(prefix='awg-capacity-test-') as directory:
    c = Path(directory) / 'capacity.c'
    exe = Path(directory) / 'capacity'
    c.write_text(prelude + '\n' + entry_def + '\n' + hash_fn + '\n' + validator + '\n' + main)
    subprocess.run([compiler, '-std=c17', '-O1', '-Wall', '-Wextra', '-Werror',
                    '-o', str(exe), str(c)], check=True)
    subprocess.run([str(exe)], check=True)
