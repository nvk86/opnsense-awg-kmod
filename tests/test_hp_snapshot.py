#!/usr/bin/env python3
"""Userspace regression harness compiling the current kernel HP implementation."""
from pathlib import Path
import subprocess, tempfile, sys
root = Path(__file__).resolve().parent.parent
source = (root/'header_protection.c').read_text()
header = (root/'header_protection.h').read_text()
for token in ('awg_header_protection_snapshot(', 'awg_header_protection_crypt_snapshot('):
    if token not in source or token not in header:
        sys.exit(f'FAIL: missing snapshot API: {token}')
source = source.replace('#include <sys/param.h>', '').replace('#include <sys/endian.h>', '').replace('#include <sys/systm.h>', '').replace('#include "header_protection.h"', '')
header = header.replace('#include <sys/types.h>', '').replace('#include <sys/rwlock.h>', '')
header = header.replace('struct rwlock hp_lock;', 'pthread_rwlock_t hp_lock;')
prelude = r'''
#define _DEFAULT_SOURCE 1
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <sys/param.h>
#include <sys/endian.h>
#define rw_init(p,n) do { if(pthread_rwlock_init((p),NULL)) abort(); } while(0)
#define rw_destroy(p) do { if(pthread_rwlock_destroy((p))) abort(); } while(0)
#define rw_rlock(p) do { if(pthread_rwlock_rdlock((p))) abort(); } while(0)
#define rw_runlock(p) do { if(pthread_rwlock_unlock((p))) abort(); } while(0)
#define rw_wlock(p) do { if(pthread_rwlock_wrlock((p))) abort(); } while(0)
#define rw_wunlock(p) do { if(pthread_rwlock_unlock((p))) abort(); } while(0)
'''
tests = r'''
static int failures;
#define CHECK(cond, msg) do { if(!(cond)){ fprintf(stderr,"FAIL: %s\n",msg); failures++; } } while(0)
static void fill(uint8_t *k, uint8_t v) { memset(k,v,32); }
static bool eq(const uint8_t *a,const uint8_t *b,size_t n) { return memcmp(a,b,n)==0; }
struct worker_ctx { struct awg_header_protection *hp; uint8_t a[32],b[32]; int iterations; int bad; };
static void *writer(void *p) {
 struct worker_ctx *c=p;
 for(int i=0;i<c->iterations;i++) awg_header_protection_set_key(c->hp,(i&1)?c->a:c->b);
 return NULL;
}
static void *reader(void *p) {
 struct worker_ctx *c=p;
 for(int i=0;i<c->iterations;i++) {
  struct awg_hp_snapshot s;
  awg_header_protection_snapshot(c->hp,&s);
  if(!s.enabled || (!eq(s.key,c->a,32) && !eq(s.key,c->b,32))) c->bad++;
  explicit_bzero(&s,sizeof(s));
 }
 return NULL;
}
int main(void) {
 struct awg_header_protection hp;
 struct awg_hp_snapshot snap;
 uint8_t zero[32]={0},a[32],b[32],nonce[12]={0},x[128]={0},y[128]={0},z[128]={0};
 fill(a,0x11); fill(b,0x22);
 awg_header_protection_init(&hp);
 awg_header_protection_snapshot(&hp,&snap);
 CHECK(!snap.enabled,"initially disabled");
 awg_header_protection_crypt_snapshot(&snap,nonce,x,sizeof(x));
 CHECK(eq(x,y,sizeof(x)),"disabled crypt is no-op");
 explicit_bzero(&snap,sizeof(snap));
 awg_header_protection_set_key(&hp,a);
 awg_header_protection_snapshot(&hp,&snap);
 CHECK(snap.enabled && eq(snap.key,a,32),"snapshot A");
 awg_header_protection_crypt_snapshot(&snap,nonce,x,sizeof(x));
 awg_header_protection_set_key(&hp,b);
 awg_header_protection_crypt_snapshot(&snap,nonce,y,sizeof(y));
 CHECK(eq(x,y,sizeof(x)),"snapshot remains A after rotation to B");
 awg_header_protection_crypt_snapshot(&snap,nonce,y,sizeof(y));
 CHECK(eq(y,z,sizeof(y)),"ChaCha XOR roundtrip");
 explicit_bzero(&snap,sizeof(snap));
 awg_header_protection_snapshot(&hp,&snap);
 CHECK(snap.enabled && eq(snap.key,b,32),"new snapshot B");
 awg_header_protection_crypt_snapshot(&snap,nonce,z,sizeof(z));
 CHECK(!eq(x,z,sizeof(x)),"different keys yield different keystream");
 explicit_bzero(&snap,sizeof(snap));
 awg_header_protection_set_key(&hp,zero);
 awg_header_protection_snapshot(&hp,&snap);
 CHECK(!snap.enabled && eq(snap.key,zero,32),"all-zero key disables HP");
 explicit_bzero(&snap,sizeof(snap));
 awg_header_protection_set_key(&hp,a);
 struct worker_ctx c={.hp=&hp,.iterations=100000};
 memcpy(c.a,a,32);memcpy(c.b,b,32);
 pthread_t w,r1,r2;
 if(pthread_create(&w,NULL,writer,&c) || pthread_create(&r1,NULL,reader,&c) || pthread_create(&r2,NULL,reader,&c)) abort();
 pthread_join(w,NULL);pthread_join(r1,NULL);pthread_join(r2,NULL);
 CHECK(c.bad==0,"concurrent snapshots contain no torn/mixed keys");
 awg_header_protection_destroy(&hp);
 if(failures) return 1;
 puts("PASS: disabled/zero key, snapshot rotation, XOR roundtrip, concurrent coherent snapshots");
 return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='awg-hp-test-') as tmp:
    t = Path(tmp)
    (t/'hp_test.c').write_text(prelude+'\n'+header+'\n'+source+'\n'+tests)
    cmd=['cc','-std=gnu17','-O2','-Wall','-Wextra','-Werror','-pthread',str(t/'hp_test.c'),'-o',str(t/'hp_test')]
    print('=== COMPILE LOCAL HP SOURCE ===',flush=True)
    subprocess.run(cmd,check=True)
    print('=== RUN TESTS ===',flush=True)
    subprocess.run([str(t/'hp_test')],check=True)
print('No kernel modules, interfaces, or source files changed.')
