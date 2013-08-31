#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

/* Your C functions if any go here */
#include <sodium.h>

MODULE = Sodium		PACKAGE = Sodium

# how do I do a TYPEMAP

# /* core.h */
int sodium_init()


# /* crypto_auth.h */
size_t  crypto_auth_bytes()

size_t  crypto_auth_keybytes()

const char *crypto_auth_primitive()

int crypto_auth(unsigned char *out, const unsigned char *in, unsigned long long inlen, const unsigned char *k)

int crypto_auth_verify(const unsigned char *h, const unsigned char *in, unsigned long long inlen, const unsigned char *k)

# /* crypto_auth_hmacsha256.h */
size_t crypto_auth_hmacsha256_bytes()

size_t crypto_auth_hmacsha256_keybytes()

const char * crypto_auth_hmacsha256_primitive()

int crypto_auth_hmacsha256(unsigned char * a,const unsigned char * b,unsigned long long c,const unsigned char * d)

int crypto_auth_hmacsha256_verify(const unsigned char * a,const unsigned char * b,unsigned long long c,const unsigned char * d)


# /* crypto_auth_hmacsha512256.h */
size_t crypto_auth_hmacsha512256_bytes()

size_t crypto_auth_hmacsha512256_keybytes()

const char * crypto_auth_hmacsha512256_primitive()

int crypto_auth_hmacsha512256(unsigned char * a,const unsigned char * b,unsigned long long c,const unsigned char * d)

int crypto_auth_hmacsha512256_verify(const unsigned char * a,const unsigned char * b,unsigned long long c,const unsigned char * d)


# /* crypto_box.h */
size_t  crypto_box_publickeybytes()

size_t  crypto_box_secretkeybytes()

size_t  crypto_box_beforenmbytes()

size_t  crypto_box_noncebytes()

size_t  crypto_box_zerobytes()

size_t  crypto_box_boxzerobytes()

size_t  crypto_box_macbytes()

const char *crypto_box_primitive()

int crypto_box_keypair(unsigned char *pk, unsigned char *sk)

int crypto_box_beforenm(unsigned char *k, const unsigned char *pk, const unsigned char *sk)

int crypto_box_afternm(unsigned char *c, const unsigned char *m, unsigned long long mlen, const unsigned char *n, const unsigned char *k)

int crypto_box_open_afternm(unsigned char *m, const unsigned char *c, unsigned long long clen, const unsigned char *n, const unsigned char *k)

int crypto_box(unsigned char *c, const unsigned char *m, unsigned long long mlen, const unsigned char *n, const unsigned char *pk, const unsigned char *sk);

int crypto_box_open(unsigned char *m, const unsigned char *c, unsigned long long clen, const unsigned char *n, const unsigned char *pk, const unsigned char *sk)


# /* crypto_box_curve25519xsalsa20poly1305.h */
size_t crypto_box_curve25519xsalsa20poly1305_publickeybytes()

size_t crypto_box_curve25519xsalsa20poly1305_secretkeybytes()

size_t crypto_box_curve25519xsalsa20poly1305_beforenmbytes()

size_t crypto_box_curve25519xsalsa20poly1305_noncebytes()

size_t crypto_box_curve25519xsalsa20poly1305_zerobytes()

size_t crypto_box_curve25519xsalsa20poly1305_boxzerobytes()

size_t crypto_box_curve25519xsalsa20poly1305_macbytes()

const char * crypto_box_curve25519xsalsa20poly1305_primitive()

int crypto_box_curve25519xsalsa20poly1305(unsigned char *a,const unsigned char *b,unsigned long long c,const unsigned char * d,const unsigned char * e,const unsigned char * f)

int crypto_box_curve25519xsalsa20poly1305_open(unsigned char * a,const unsigned char * b,unsigned long long c,const unsigned char * d,const unsigned char * e,const unsigned char * f)

int crypto_box_curve25519xsalsa20poly1305_keypair(unsigned char * a,unsigned char * b)

int crypto_box_curve25519xsalsa20poly1305_beforenm(unsigned char * a,const unsigned char * b,const unsigned char * c)

int crypto_box_curve25519xsalsa20poly1305_afternm(unsigned char * a,const unsigned char * b,unsigned long long c,const unsigned char * d,const unsigned char * e)

int crypto_box_curve25519xsalsa20poly1305_open_afternm(unsigned char * a,const unsigned char * b,unsigned long long c,const unsigned char * d,const unsigned char * e)


# /* crypto_core_hsalsa20.h */
size_t crypto_core_hsalsa20_outputbytes()

size_t crypto_core_hsalsa20_inputbytes()

size_t crypto_core_hsalsa20_keybytes()

size_t crypto_core_hsalsa20_constbytes()

const char * crypto_core_hsalsa20_primitive()

int crypto_core_hsalsa20(unsigned char * a,const unsigned char * b,const unsigned char * c,const unsigned char * d)


# /* crypto_core_salsa20.h */
size_t crypto_core_salsa20_outputbytes()

size_t crypto_core_salsa20_inputbytes()

size_t crypto_core_salsa20_keybytes()

size_t crypto_core_salsa20_constbytes()

const char * crypto_core_salsa20_primitive()

int crypto_core_salsa20(unsigned char * a,const unsigned char * b,const unsigned char * c,const unsigned char * d)


# /* crypto_core_salsa2012.h */
size_t crypto_core_salsa2012_outputbytes()

size_t crypto_core_salsa2012_inputbytes()

size_t crypto_core_salsa2012_keybytes()

size_t crypto_core_salsa2012_constbytes()

const char * crypto_core_salsa2012_primitive()

int crypto_core_salsa2012(unsigned char *a,const unsigned char *b,const unsigned char *c,const unsigned char *d)


# /* crypto_core_salsa208.h */
size_t crypto_core_salsa208_outputbytes()

size_t crypto_core_salsa208_inputbytes()

size_t crypto_core_salsa208_keybytes()

size_t crypto_core_salsa208_constbytes()

const char * crypto_core_salsa208_primitive()

int crypto_core_salsa208(unsigned char *a,const unsigned char *b,const unsigned char *c,const unsigned char *d)


# /* crypto_generichash.h */
size_t  crypto_generichash_bytes()

size_t  crypto_generichash_bytes_min()

size_t  crypto_generichash_bytes_max()

size_t  crypto_generichash_keybytes()

size_t  crypto_generichash_keybytes_min()

size_t  crypto_generichash_keybytes_max()

size_t  crypto_generichash_blockbytes()

const char *crypto_generichash_primitive()

int crypto_generichash(unsigned char *out, size_t outlen, const unsigned char *in, unsigned long long inlen, const unsigned char *key, size_t keylen)

# TODO  int crypto_generichash_init(crypto_generichash_state *state, const unsigned char *key, const size_t keylen, const size_t outlen)

# TODO  int crypto_generichash_update(crypto_generichash_state *state, const unsigned char *in, unsigned long long inlen)

# TODO  int crypto_generichash_final(crypto_generichash_state *state, unsigned char *out, const size_t outlen)


# /* crypto_generichash_blake2b.h */
size_t crypto_generichash_blake2b_bytes_min()

size_t crypto_generichash_blake2b_bytes_max()

size_t crypto_generichash_blake2b_keybytes_min()

size_t crypto_generichash_blake2b_keybytes_max()

size_t crypto_generichash_blake2b_blockbytes()

const char * crypto_generichash_blake2b_blockbytes_primitive()

int crypto_generichash_blake2b(unsigned char *out, size_t outlen, const unsigned char *in, unsigned long long inlen, const unsigned char *key, size_t keylen)

# TODO  int crypto_generichash_blake2b_init(crypto_generichash_blake2b_state *state, const unsigned char *key, const size_t keylen, const size_t outlen)

# TODO int crypto_generichash_blake2b_update(crypto_generichash_blake2b_state *state, const unsigned char *in, unsigned long long inlen)

# TODO  int crypto_generichash_blake2b_final(crypto_generichash_blake2b_state *state, unsigned char *out, const size_t outlen)


# /* crypto_hash.h */
int crypto_hash(unsigned char *out, const unsigned char *in, unsigned long long inlen)


# /* crypto_hash_sha256.h */
size_t crypto_hash_sha256_bytes()

const char * crypto_hash_sha256_primitive()

int crypto_hash_sha256(unsigned char * a,const unsigned char * b,unsigned long long c)


# /* crypto_hash_sha512.h */
size_t crypto_hash_sha512_bytes()

const char * crypto_hash_sha512_primitive()

int crypto_hash_sha512(unsigned char * a,const unsigned char * b,unsigned long long c)


# /* crypto_hashblocks_sha256.h */
size_t crypto_hashblocks_sha256_statebytes()

size_t crypto_hashblocks_sha256_blockbytes()

const char * crypto_hashblocks_sha256_primitive()

int crypto_hashblocks_sha256(unsigned char * a,const unsigned char * b,unsigned long long c)


# /* crypto_hashblocks_sha512.h */
size_t crypto_hashblocks_sha512_statebytes()

size_t crypto_hashblocks_sha512_blockbytes()

const char * crypto_hashblocks_sha512_primitive()

int crypto_hashblocks_sha512(unsigned char * a,const unsigned char * b,unsigned long long c)


# /* crypto_int32.h */

# /* crypto_int64.h */

# /* crypto_onetimeauth.h */
size_t  crypto_onetimeauth_bytes()

size_t  crypto_onetimeauth_keybytes()

const char *crypto_onetimeauth_primitive()

int crypto_onetimeauth(unsigned char *out, const unsigned char *in, unsigned long long inlen, const unsigned char *k)

int crypto_onetimeauth_verify(const unsigned char *h, const unsigned char *in, unsigned long long inlen, const unsigned char *k)


# /* crypto_onetimeauth_poly1305.h */
size_t crypto_onetimeauth_poly1305_bytes()

size_t crypto_onetimeauth_poly1305_keybytes()

const char * crypto_onetimeauth_poly1305_primitive()

const char *crypto_onetimeauth_poly1305_ref_implementation_name()

# TODO int crypto_onetimeauth_poly1305_set_implementation(crypto_onetimeauth_poly1305_implementation *impl)

# TODO  crypto_onetimeauth_poly1305_implementation * crypto_onetimeauth_pick_best_implementation()

int crypto_onetimeauth_poly1305(unsigned char *out, const unsigned char *in, unsigned long long inlen, const unsigned char *k)

int crypto_onetimeauth_poly1305_verify(const unsigned char *h, const unsigned char *in, unsigned long long inlen, const unsigned char *k)


# /* crypto_onetimeauth_poly1305_53.h */

# LATER char * crypto_onetimeauth_poly1305_53_implementation_name()

# LATER int crypto_onetimeauth_poly1305_53(unsigned char *out, const unsigned char *in, unsigned long long inlen, const unsigned char *k)

# LATER int crypto_onetimeauth_poly1305_53_verify(const unsigned char *h, const unsigned char *in, unsigned long long inlen, const unsigned char *k)


# /* crypto_onetimeauth_poly1305_donna.h */

# LATER const char *crypto_onetimeauth_poly1305_donna_implementation_name()

# LATER int crypto_onetimeauth_poly1305_donna(unsigned char *out, const unsigned char *in, unsigned long long inlen, const unsigned char *k)

# LATER int crypto_onetimeauth_poly1305_donna_verify(const unsigned char *h, const unsigned char *in, unsigned long long inlen, const unsigned char *k)


# /* crypto_scalarmult.h */
size_t  crypto_scalarmult_bytes()

size_t  crypto_scalarmult_scalarbytes()

const char *crypto_scalarmult_primitive()

int crypto_scalarmult_base(unsigned char *q, const unsigned char *n)

int crypto_scalarmult(unsigned char *q, const unsigned char *n, const unsigned char *p)


# /* crypto_scalarmult_curve25519.h */
int crypto_scalarmult_curve25519(unsigned char * a,const unsigned char * b,const unsigned char * c)

int crypto_scalarmult_curve25519_base(unsigned char *a,const unsigned char *b)


# /* crypto_secretbox.h */
size_t  crypto_secretbox_keybytes()

size_t  crypto_secretbox_noncebytes()

size_t  crypto_secretbox_zerobytes()

size_t  crypto_secretbox_boxzerobytes()

const char *crypto_secretbox_primitive()

int crypto_secretbox(unsigned char *c, const unsigned char *m, unsigned long long mlen, const unsigned char *n, const unsigned char *k)

int crypto_secretbox_open(unsigned char *m, const unsigned char *c, unsigned long long clen, const unsigned char *n, const unsigned char *k)


# /* crypto_secretbox_xsalsa20poly1305.h */
size_t crypto_secretbox_xsalsa20poly1305_keybytes()

size_t crypto_secretbox_xsalsa20poly1305_noncebytes()

size_t crypto_secretbox_xsalsa20poly1305_zerobytes()

size_t crypto_secretbox_xsalsa20poly1305_boxzerobytes()

const char * crypto_secretbox_xsalsa20poly1305_primitive()

int crypto_secretbox_xsalsa20poly1305(unsigned char *a,const unsigned char *b,unsigned long long c,const unsigned char *d,const unsigned char *e)

int crypto_secretbox_xsalsa20poly1305_open(unsigned char *a,const unsigned char *b,unsigned long long c,const unsigned char *d,const unsigned char *e)


# /* crypto_shorthash.h */
size_t  crypto_shorthash_bytes()

size_t  crypto_shorthash_keybytes()

const char *crypto_shorthash_primitive()

int crypto_shorthash(unsigned char *out, const unsigned char *in, unsigned long long inlen, const unsigned char *k)

# /* crypto_shorthash_siphash24.h */
size_t crypto_shorthash_siphash24_bytes()

const char * crypto_shorthash_siphash24_primitive()

int crypto_shorthash_siphash24(unsigned char * a,const unsigned char *b,unsigned long long c,const unsigned char *d)


# /* crypto_sign.h */
size_t  crypto_sign_bytes()

size_t  crypto_sign_seedbytes()

# LATER size_t  crypto_sign_publiciiikeybytes()

size_t  crypto_sign_secretkeybytes()

const char *crypto_sign_primitive()

int crypto_sign_seed_keypair(unsigned char *pk, unsigned char *sk, const unsigned char *seed)

int crypto_sign_keypair(unsigned char *pk, unsigned char *sk)

int crypto_sign(unsigned char *sm, unsigned long long *smlen, const unsigned char *m, unsigned long long mlen, const unsigned char *sk)

int crypto_sign_open(unsigned char *m, unsigned long long *mlen, const unsigned char *sm, unsigned long long smlen, const unsigned char *pk)


# /* crypto_sign_ed25519.h */
size_t crypto_sign_ed25519_bytes()

size_t crypto_sign_ed25519_seedbytes()

size_t crypto_sign_ed25519_publickeybytes()

size_t crypto_sign_ed25519_secretkeybytes()

const char * crypto_sign_ed25519_primitive()

int crypto_sign_ed25519(unsigned char *a,unsigned long long *b,const unsigned char *c,unsigned long long d,const unsigned char *e)

int crypto_sign_ed25519_open(unsigned char *a,unsigned long long *b,const unsigned char *c,unsigned long long d,const unsigned char *e)

int crypto_sign_ed25519_keypair(unsigned char *a,unsigned char *b)

int crypto_sign_ed25519_seed_keypair(unsigned char *a,unsigned char *b,const unsigned char *c)


# /* crypto_sign_edwards25519sha512batch.h */
size_t crypto_sign_edwards25519sha512batch_bytes()

size_t crypto_sign_edwards25519sha512batch_publickeybytes()

size_t crypto_sign_edwards25519sha512batch_secretkeybytes()

const char * crypto_sign_edwards25519sha512batch_primitive()

int crypto_sign_edwards25519sha512batch(unsigned char *a,unsigned long long *b,const unsigned char *c,unsigned long long d,const unsigned char *e)

int crypto_sign_edwards25519sha512batch_open(unsigned char *a,unsigned long long *b,const unsigned char *c,unsigned long long d,const unsigned char *e)

int crypto_sign_edwards25519sha512batch_keypair(unsigned char *a,unsigned char *b)


# /* crypto_stream.h */
size_t  crypto_stream_keybytes()

size_t  crypto_stream_noncebytes()

const char *crypto_stream_primitive()

int crypto_stream(unsigned char *c, unsigned long long clen, const unsigned char *n, const unsigned char *k)

int crypto_stream_xor(unsigned char *c, const unsigned char *m, unsigned long long mlen, const unsigned char *n, const unsigned char *k)


# /* crypto_stream_aes128ctr.h */
size_t crypto_stream_aes128ctr_keybytes()

size_t crypto_stream_aes128ctr_noncebytes()

size_t crypto_stream_aes128ctr_beforenmbytes()

const char * crypto_stream_aes128ctr_primitive()

int crypto_stream_aes128ctr(unsigned char *a,unsigned long long b,const unsigned char *c,const unsigned char *d)

int crypto_stream_aes128ctr_xor(unsigned char *a,const unsigned char *b,unsigned long long c,const unsigned char *d,const unsigned char *e)

int crypto_stream_aes128ctr_beforenm(unsigned char *a,const unsigned char *b)

int crypto_stream_aes128ctr_afternm(unsigned char *a,unsigned long long b,const unsigned char *c,const unsigned char *d)

int crypto_stream_aes128ctr_xor_afternm(unsigned char *e,const unsigned char *a,unsigned long long b,const unsigned char *c,const unsigned char *d)


# /* crypto_stream_aes256estream.h */
size_t crypto_stream_aes256estream_keybytes()

size_t crypto_stream_aes256estream_noncebytes()

size_t crypto_stream_aes256estream_beforenmbytes()

const char * crypto_stream_aes256estream_primitive()

int crypto_stream_aes256estream(unsigned char *a,unsigned long long b,const unsigned char *c,const unsigned char *d)

int crypto_stream_aes256estream_xor(unsigned char *a,const unsigned char *b,unsigned long long c,const unsigned char *d,const unsigned char *e)

int crypto_stream_aes256estream_beforenm(unsigned char *a,const unsigned char *b)

int crypto_stream_aes256estream_afternm(unsigned char *a,unsigned long long b,const unsigned char * c,const unsigned char * d)

int crypto_stream_aes256estream_xor_afternm(unsigned char *a,const unsigned char *b,unsigned long long c,const unsigned char *d,const unsigned char *e)


# /* crypto_stream_salsa20.h */
int crypto_stream_salsa20(unsigned char *a,unsigned long long b,const unsigned char *c,const unsigned char *d)

int crypto_stream_salsa20_xor(unsigned char *a,const unsigned char *b,unsigned long long c,const unsigned char *d,const unsigned char *e)


# /* crypto_stream_salsa2012.h */
size_t crypto_stream_salsa2012_keybytes()

size_t crypto_stream_salsa2012_noncebytes()

const char * crypto_stream_salsa2012_primitive()

int crypto_stream_salsa2012(unsigned char *a,unsigned long long b,const unsigned char *c,const unsigned char *d)

int crypto_stream_salsa2012_xor(unsigned char *e,const unsigned char *a,unsigned long long b,const unsigned char *c,const unsigned char *d)


# /* crypto_stream_salsa208.h */
size_t crypto_stream_salsa208_keybytes()

size_t crypto_stream_salsa208_noncebytes()

const char * crypto_stream_salsa208_primitive()

int crypto_stream_salsa208(unsigned char *a,unsigned long long b,const unsigned char *c,const unsigned char *d)

int crypto_stream_salsa208_xor(unsigned char *e,const unsigned char *a,unsigned long long b,const unsigned char *c,const unsigned char *d)


# /* crypto_stream_xsalsa20.h */
size_t crypto_stream_xsalsa20_keybytes()

size_t crypto_stream_xsalsa20_noncebytes()

const char * crypto_stream_xsalsa20_primitive()

int crypto_stream_xsalsa20(unsigned char *a,unsigned long long b,const unsigned char *c,const unsigned char *d)

int crypto_stream_xsalsa20_xor(unsigned char *e,const unsigned char *a,unsigned long long b,const unsigned char *c,const unsigned char *d)


# /* crypto_uint16.h */

# /* crypto_uint32.h */

# /* crypto_uint64.h */

# /* crypto_uint8.h */

# /* crypto_verify_16.h */
size_t crypto_verify_16_bytes()

int crypto_verify_16(const unsigned char *x, const unsigned char *y)



# /* crypto_verify_32.h */
size_t crypto_verify_32_bytes()

int crypto_verify_32(const unsigned char *x, const unsigned char *y)



# /* export.h */



# /* randombytes.h */
# TODO  int         randombytes_set_implementation(randombytes_implementation *impl)

void randombytes(unsigned char *buf, unsigned long long size)

const char *randombytes_implementation_name()

uint32_t    randombytes_random()

void randombytes_stir()

uint32_t    randombytes_uniform(const uint32_t upper_bound)

void randombytes_buf(void * const buf, const size_t size)

int         randombytes_close()


# /* randombytes_salsa20_random.h */

const char *randombytes_salsa20_implementation_name()

uint32_t    randombytes_salsa20_random()

void        randombytes_salsa20_random_stir()

uint32_t    randombytes_salsa20_random_uniform(const uint32_t upper_bound)

void        randombytes_salsa20_random_buf(void * const buf, const size_t size)

int         randombytes_salsa20_random_close()


# /* randombytes_sysrandom.h */
const char *randombytes_sysrandom_implementation_name()

uint32_t    randombytes_sysrandom()

void        randombytes_sysrandom_stir()

uint32_t    randombytes_sysrandom_uniform(const uint32_t upper_bound)

void        randombytes_sysrandom_buf(void * const buf, const size_t size)

int         randombytes_sysrandom_close()


# /* utils.h */
void sodium_memzero(void * const pnt, const size_t len)

int sodium_memcmp(const void * const b1_, const void * const b2_, size_t size)

char *sodium_bin2hex(char * const hex, const size_t hexlen, const unsigned char *bin, const size_t binlen)


# /* version.h */
const char *sodium_version_string()

int         sodium_library_version_major()

int         sodium_library_version_minor()



