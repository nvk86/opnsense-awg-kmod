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
tests = '\nstatic int fail(const char *msg) { fprintf(stderr,"FAIL: %s\\n",msg); return 1; }\nstatic int fromhex(const char *h, uint8_t *out, size_t n) {\n for(size_t i=0;i<n;i++){ unsigned x; if(sscanf(h+2*i,"%2x",&x)!=1)return 1;out[i]=x; } return 0;\n}\nstatic int run(const char *name,const uint8_t *key,const uint8_t *nonce,\n const uint8_t *plain,const uint8_t *expected,size_t n) {\n struct awg_header_protection hp;\n struct awg_hp_snapshot snap;\n uint8_t *buf=calloc(n+64,1);\n if(!buf)return fail("calloc");\n memcpy(buf+64,plain,n);\n awg_header_protection_init(&hp);\n awg_header_protection_set_key(&hp,key);\n awg_header_protection_snapshot(&hp,&snap);\n if(!snap.enabled || memcmp(snap.key,key,32))return fail("snapshot key");\n /* Counter 1 is the second 64-byte block; AWG primitive starts at counter 0. */\n awg_header_protection_crypt_snapshot(&snap,nonce,buf,n+64);\n int mismatch=memcmp(buf+64,expected,n);\n explicit_bzero(&snap,sizeof(snap));\n awg_header_protection_destroy(&hp);\n explicit_bzero(buf,n+64); free(buf);\n if(mismatch)return fail(name);\n printf("PASS: %s\\n",name);\n return 0;\n}\nint main(void) {\n if(!awg_header_protection_selftest())return fail("ChaCha20 kernel self-test");\n puts("PASS: ChaCha20 kernel self-test");\n uint8_t key[32],nonce[12],expected[114],plain[114],zeros[64]={0};\n for(int i=0;i<32;i++)key[i]=i;\n if(fromhex("000000090000004a00000000",nonce,12))return fail("nonce1");\n if(fromhex(\n "10f1e7e4d13b5915500fdd1fa32071c4"\n "c7d1f4c733c068030422aa9ac3d46c4e"\n "d2826446079faa0914c2d705d98b02a2"\n "b5129cd1de164eb9cbd083e8a2503c4e",expected,64))return fail("hex1");\n if(run("RFC 8439 section 2.3.2 block counter=1",key,nonce,zeros,expected,64))return 1;\n if(fromhex("000000000000004a00000000",nonce,12))return fail("nonce2");\n const char *message="Ladies and Gentlemen of the class of \'99: If I could offer you only one tip for the future, sunscreen would be it.";\n if(strlen(message)!=114)return fail("plaintext length");\n memcpy(plain,message,114);\n if(fromhex(\n "6e2e359a2568f98041ba0728dd0d6981"\n "e97e7aec1d4360c20a27afccfd9fae0b"\n "f91b65c5524733ab8f593dabcd62b357"\n "1639d624e65152ab8f530c359f0861d8"\n "07ca0dbf500d6a6156a38e088a22b65e"\n "52bc514d16ccf806818ce91ab7793736"\n "5af90bbf74a35be6b40b8eedf2785e42"\n "874d",expected,114))return fail("hex2");\n if(run("RFC 8439 section 2.4.2 encryption counter=1",key,nonce,plain,expected,114))return 1;\n struct awg_header_protection hp;\n struct awg_hp_snapshot snap;\n uint8_t mask[4]={0},header[16]={0},zero16[16]={0},newkey[32];\n memset(newkey,0x5a,32);\n awg_header_protection_init(&hp);\n awg_header_protection_set_key(&hp,key);\n awg_header_protection_snapshot(&hp,&snap);\n awg_header_protection_crypt_snapshot(&snap,nonce,mask,4);\n awg_header_protection_set_key(&hp,newkey);\n awg_header_protection_crypt_snapshot(&snap,nonce,header,16);\n if(memcmp(mask,header,4))return fail("AWG mask vs header prefix");\n awg_header_protection_crypt_snapshot(&snap,nonce,header,16);\n if(memcmp(header,zero16,16))return fail("AWG roundtrip");\n explicit_bzero(&snap,sizeof(snap));\n awg_header_protection_destroy(&hp);\n puts("PASS: AWG counter=0 mask/full-header consistency after key rotation");\n return 0;\n}\n'

with tempfile.TemporaryDirectory(prefix='awg-rfc8439-') as tmp:
    t=Path(tmp)
    (t/'hp_rfc8439.c').write_text(prelude+'\n'+header+'\n'+source+'\n'+tests)
    print('=== COMPILE LOCAL HP SOURCE ===',flush=True)
    subprocess.run(['cc','-std=gnu17','-O2','-Wall','-Wextra','-Werror','-pthread',
                    str(t/'hp_rfc8439.c'),'-o',str(t/'hp_rfc8439')],check=True)
    print('=== RFC 8439 + AWG TESTS ===',flush=True)
    subprocess.run([str(t/'hp_rfc8439')],check=True)

    print('=== NEGATIVE SELF-TEST ===', flush=True)

    marker = '0x76, 0xb8, 0xe0, 0xad'
    corrupted = '0x77, 0xb8, 0xe0, 0xad'

    if source.count(marker) != 1:
        raise SystemExit('FAIL: unexpected self-test vector')

    bad_source = source.replace(marker, corrupted, 1)
    bad_main = """
int main(void) {
    return awg_header_protection_selftest() ? 1 : 0;
}
"""

    bad_c = t / 'hp_selftest_negative.c'
    bad_exe = t / 'hp_selftest_negative'

    bad_c.write_text(
        prelude + '\n' + header + '\n' +
        bad_source + '\n' + bad_main
    )

    subprocess.run([
        'cc', '-std=gnu17', '-O2',
        '-Wall', '-Wextra', '-Werror', '-pthread',
        str(bad_c), '-o', str(bad_exe)
    ], check=True)

    subprocess.run([str(bad_exe)], check=True)
    print('PASS: corrupted vector detected', flush=True)

print('No kernel modules, interfaces, routes, or source files changed.')
