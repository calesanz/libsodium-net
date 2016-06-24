using System;
using System.Runtime.InteropServices;

namespace LibSodium
{
	static class SodiumLibrary
	{
		// extern int sodium_init () __attribute__((visibility("default"))) __attribute__((warn_unused_result));
		[DllImport ("__Internal")]
	 	public  static extern int sodium_init ();

		// extern int crypto_aead_aes256gcm_is_available () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
		public  static extern int crypto_aead_aes256gcm_is_available ();

		// extern size_t crypto_aead_aes256gcm_keybytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
		public  static extern long crypto_aead_aes256gcm_keybytes ();

		// extern size_t crypto_aead_aes256gcm_nsecbytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_aead_aes256gcm_nsecbytes ();

		// extern size_t crypto_aead_aes256gcm_npubbytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_aead_aes256gcm_npubbytes ();

		// extern size_t crypto_aead_aes256gcm_abytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_aead_aes256gcm_abytes ();

		// extern size_t crypto_aead_aes256gcm_statebytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_aead_aes256gcm_statebytes ();

		// extern int crypto_aead_aes256gcm_encrypt (unsigned char *c, unsigned long long *clen_p, const unsigned char *m, unsigned long long mlen, const unsigned char *ad, unsigned long long adlen, const unsigned char *nsec, const unsigned char *npub, const unsigned char *k) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern int crypto_aead_aes256gcm_encrypt (byte[] c, ulong clen_p, byte[] m, ulong mlen, byte[] ad, ulong adlen, byte[] nsec, byte[] npub, byte[] k);

		// extern int crypto_aead_aes256gcm_decrypt (unsigned char *m, unsigned long long *mlen_p, unsigned char *nsec, const unsigned char *c, unsigned long long clen, const unsigned char *ad, unsigned long long adlen, const unsigned char *npub, const unsigned char *k) __attribute__((visibility("default"))) __attribute__((warn_unused_result));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_aead_aes256gcm_decrypt (byte[] m, ulong mlen_p, byte[] nsec, byte[] c, ulong clen, byte[] ad, ulong adlen, byte[] npub, byte[] k);

		// extern int crypto_aead_aes256gcm_encrypt_detached (unsigned char *c, unsigned char *mac, unsigned long long *maclen_p, const unsigned char *m, unsigned long long mlen, const unsigned char *ad, unsigned long long adlen, const unsigned char *nsec, const unsigned char *npub, const unsigned char *k) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_aead_aes256gcm_encrypt_detached (byte[] c, byte[] mac, ulong maclen_p, byte[] m, ulong mlen, byte[] ad, ulong adlen, byte[] nsec, byte[] npub, byte[] k);

		// extern int crypto_aead_aes256gcm_decrypt_detached (unsigned char *m, unsigned char *nsec, const unsigned char *c, unsigned long long clen, const unsigned char *mac, const unsigned char *ad, unsigned long long adlen, const unsigned char *npub, const unsigned char *k) __attribute__((visibility("default"))) __attribute__((warn_unused_result));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_aead_aes256gcm_decrypt_detached (byte[] m, byte[] nsec, byte[] c, ulong clen, byte[] mac, byte[] ad, ulong adlen, byte[] npub, byte[] k);

		// extern int crypto_aead_aes256gcm_beforenm (crypto_aead_aes256gcm_state *ctx_, const unsigned char *k) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_aead_aes256gcm_beforenm (byte[][] ctx_, byte[] k);

		// extern int crypto_aead_aes256gcm_encrypt_afternm (unsigned char *c, unsigned long long *clen_p, const unsigned char *m, unsigned long long mlen, const unsigned char *ad, unsigned long long adlen, const unsigned char *nsec, const unsigned char *npub, const crypto_aead_aes256gcm_state *ctx_) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_aead_aes256gcm_encrypt_afternm (byte[] c, long  clen_p, byte[] m, ulong mlen, byte[] ad, ulong adlen, byte[] nsec, byte[] npub, byte[][] ctx_);

		// extern int crypto_aead_aes256gcm_decrypt_afternm (unsigned char *m, unsigned long long *mlen_p, unsigned char *nsec, const unsigned char *c, unsigned long long clen, const unsigned char *ad, unsigned long long adlen, const unsigned char *npub, const crypto_aead_aes256gcm_state *ctx_) __attribute__((visibility("default"))) __attribute__((warn_unused_result));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_aead_aes256gcm_decrypt_afternm (byte[] m, long  mlen_p, byte[] nsec, byte[] c, ulong clen, byte[] ad, ulong adlen, byte[] npub, byte[][] ctx_);

		// extern int crypto_aead_aes256gcm_encrypt_detached_afternm (unsigned char *c, unsigned char *mac, unsigned long long *maclen_p, const unsigned char *m, unsigned long long mlen, const unsigned char *ad, unsigned long long adlen, const unsigned char *nsec, const unsigned char *npub, const crypto_aead_aes256gcm_state *ctx_) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_aead_aes256gcm_encrypt_detached_afternm (byte[] c, byte[] mac, long  maclen_p, byte[] m, ulong mlen, byte[] ad, ulong adlen, byte[] nsec, byte[] npub, byte[][] ctx_);

		// extern int crypto_aead_aes256gcm_decrypt_detached_afternm (unsigned char *m, unsigned char *nsec, const unsigned char *c, unsigned long long clen, const unsigned char *mac, const unsigned char *ad, unsigned long long adlen, const unsigned char *npub, const crypto_aead_aes256gcm_state *ctx_) __attribute__((visibility("default"))) __attribute__((warn_unused_result));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_aead_aes256gcm_decrypt_detached_afternm (byte[] m, byte[] nsec, byte[] c, ulong clen, byte[] mac, byte[] ad, ulong adlen, byte[] npub, byte[][] ctx_);

		// extern size_t crypto_aead_chacha20poly1305_ietf_keybytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_aead_chacha20poly1305_ietf_keybytes ();

		// extern size_t crypto_aead_chacha20poly1305_ietf_nsecbytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_aead_chacha20poly1305_ietf_nsecbytes ();

		// extern size_t crypto_aead_chacha20poly1305_ietf_npubbytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_aead_chacha20poly1305_ietf_npubbytes ();

		// extern size_t crypto_aead_chacha20poly1305_ietf_abytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_aead_chacha20poly1305_ietf_abytes ();

		// extern int crypto_aead_chacha20poly1305_ietf_encrypt (unsigned char *c, unsigned long long *clen_p, const unsigned char *m, unsigned long long mlen, const unsigned char *ad, unsigned long long adlen, const unsigned char *nsec, const unsigned char *npub, const unsigned char *k) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_aead_chacha20poly1305_ietf_encrypt (byte[] c, long  clen_p, byte[] m, ulong mlen, byte[] ad, ulong adlen, byte[] nsec, byte[] npub, byte[] k);

		// extern int crypto_aead_chacha20poly1305_ietf_decrypt (unsigned char *m, unsigned long long *mlen_p, unsigned char *nsec, const unsigned char *c, unsigned long long clen, const unsigned char *ad, unsigned long long adlen, const unsigned char *npub, const unsigned char *k) __attribute__((visibility("default"))) __attribute__((warn_unused_result));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_aead_chacha20poly1305_ietf_decrypt (byte[] m, long  mlen_p, byte[] nsec, byte[] c, ulong clen, byte[] ad, ulong adlen, byte[] npub, byte[] k);

		// extern int crypto_aead_chacha20poly1305_ietf_encrypt_detached (unsigned char *c, unsigned char *mac, unsigned long long *maclen_p, const unsigned char *m, unsigned long long mlen, const unsigned char *ad, unsigned long long adlen, const unsigned char *nsec, const unsigned char *npub, const unsigned char *k) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_aead_chacha20poly1305_ietf_encrypt_detached (byte[] c, byte[] mac, long  maclen_p, byte[] m, ulong mlen, byte[] ad, ulong adlen, byte[] nsec, byte[] npub, byte[] k);

		// extern int crypto_aead_chacha20poly1305_ietf_decrypt_detached (unsigned char *m, unsigned char *nsec, const unsigned char *c, unsigned long long clen, const unsigned char *mac, const unsigned char *ad, unsigned long long adlen, const unsigned char *npub, const unsigned char *k) __attribute__((visibility("default"))) __attribute__((warn_unused_result));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_aead_chacha20poly1305_ietf_decrypt_detached (byte[] m, byte[] nsec, byte[] c, ulong clen, byte[] mac, byte[] ad, ulong adlen, byte[] npub, byte[] k);

		// extern size_t crypto_aead_chacha20poly1305_keybytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_aead_chacha20poly1305_keybytes ();

		// extern size_t crypto_aead_chacha20poly1305_nsecbytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_aead_chacha20poly1305_nsecbytes ();

		// extern size_t crypto_aead_chacha20poly1305_npubbytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_aead_chacha20poly1305_npubbytes ();

		// extern size_t crypto_aead_chacha20poly1305_abytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_aead_chacha20poly1305_abytes ();

		// extern int crypto_aead_chacha20poly1305_encrypt (unsigned char *c, unsigned long long *clen_p, const unsigned char *m, unsigned long long mlen, const unsigned char *ad, unsigned long long adlen, const unsigned char *nsec, const unsigned char *npub, const unsigned char *k) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_aead_chacha20poly1305_encrypt (byte[] c, long  clen_p, byte[] m, ulong mlen, byte[] ad, ulong adlen, byte[] nsec, byte[] npub, byte[] k);

		// extern int crypto_aead_chacha20poly1305_decrypt (unsigned char *m, unsigned long long *mlen_p, unsigned char *nsec, const unsigned char *c, unsigned long long clen, const unsigned char *ad, unsigned long long adlen, const unsigned char *npub, const unsigned char *k) __attribute__((visibility("default"))) __attribute__((warn_unused_result));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_aead_chacha20poly1305_decrypt (byte[] m, long  mlen_p, byte[] nsec, byte[] c, ulong clen, byte[] ad, ulong adlen, byte[] npub, byte[] k);

		// extern int crypto_aead_chacha20poly1305_encrypt_detached (unsigned char *c, unsigned char *mac, unsigned long long *maclen_p, const unsigned char *m, unsigned long long mlen, const unsigned char *ad, unsigned long long adlen, const unsigned char *nsec, const unsigned char *npub, const unsigned char *k) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_aead_chacha20poly1305_encrypt_detached (byte[] c, byte[] mac, long  maclen_p, byte[] m, ulong mlen, byte[] ad, ulong adlen, byte[] nsec, byte[] npub, byte[] k);

		// extern int crypto_aead_chacha20poly1305_decrypt_detached (unsigned char *m, unsigned char *nsec, const unsigned char *c, unsigned long long clen, const unsigned char *mac, const unsigned char *ad, unsigned long long adlen, const unsigned char *npub, const unsigned char *k) __attribute__((visibility("default"))) __attribute__((warn_unused_result));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_aead_chacha20poly1305_decrypt_detached (byte[] m, byte[] nsec, byte[] c, ulong clen, byte[] mac, byte[] ad, ulong adlen, byte[] npub, byte[] k);

		// extern size_t crypto_hash_sha512_statebytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_hash_sha512_statebytes ();

		// extern size_t crypto_hash_sha512_bytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_hash_sha512_bytes ();

		// extern int crypto_hash_sha512 (unsigned char *out, const unsigned char *in, unsigned long long inlen) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_hash_sha512 (byte[] @out, byte[] @in, ulong inlen);

		// extern int crypto_hash_sha512_init (crypto_hash_sha512_state *state) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_hash_sha512_init (IntPtr state);

		// extern int crypto_hash_sha512_update (crypto_hash_sha512_state *state, const unsigned char *in, unsigned long long inlen) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_hash_sha512_update (IntPtr state, byte[] @in, ulong inlen);

		// extern int crypto_hash_sha512_final (crypto_hash_sha512_state *state, unsigned char *out) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_hash_sha512_final (IntPtr state, byte[] @out);

		// extern size_t crypto_auth_hmacsha512_bytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_auth_hmacsha512_bytes ();

		// extern size_t crypto_auth_hmacsha512_keybytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_auth_hmacsha512_keybytes ();

		// extern int crypto_auth_hmacsha512 (unsigned char *out, const unsigned char *in, unsigned long long inlen, const unsigned char *k) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_auth_hmacsha512 (byte[] @out, byte[] @in, ulong inlen, byte[] k);

		// extern int crypto_auth_hmacsha512_verify (const unsigned char *h, const unsigned char *in, unsigned long long inlen, const unsigned char *k) __attribute__((visibility("default"))) __attribute__((warn_unused_result));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_auth_hmacsha512_verify (byte[] h, byte[] @in, ulong inlen, byte[] k);

		// extern size_t crypto_auth_hmacsha512_statebytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_auth_hmacsha512_statebytes ();

		// extern int crypto_auth_hmacsha512_init (crypto_auth_hmacsha512_state *state, const unsigned char *key, size_t keylen) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_auth_hmacsha512_init (IntPtr state, byte[] key, long keylen);

		// extern int crypto_auth_hmacsha512_update (crypto_auth_hmacsha512_state *state, const unsigned char *in, unsigned long long inlen) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_auth_hmacsha512_update (IntPtr state, byte[] @in, ulong inlen);

		// extern int crypto_auth_hmacsha512_final (crypto_auth_hmacsha512_state *state, unsigned char *out) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_auth_hmacsha512_final (IntPtr state, byte[] @out);

		// extern size_t crypto_auth_hmacsha512256_bytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_auth_hmacsha512256_bytes ();

		// extern size_t crypto_auth_hmacsha512256_keybytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_auth_hmacsha512256_keybytes ();

		// extern int crypto_auth_hmacsha512256 (unsigned char *out, const unsigned char *in, unsigned long long inlen, const unsigned char *k) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_auth_hmacsha512256 (byte[] @out, byte[] @in, ulong inlen, byte[] k);

		// extern int crypto_auth_hmacsha512256_verify (const unsigned char *h, const unsigned char *in, unsigned long long inlen, const unsigned char *k) __attribute__((visibility("default"))) __attribute__((warn_unused_result));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_auth_hmacsha512256_verify (byte[] h, byte[] @in, ulong inlen, byte[] k);

		// extern size_t crypto_auth_hmacsha512256_statebytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_auth_hmacsha512256_statebytes ();

		// extern int crypto_auth_hmacsha512256_init (crypto_auth_hmacsha512256_state *state, const unsigned char *key, size_t keylen) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_auth_hmacsha512256_init (IntPtr state, byte[] key, long keylen);

		// extern int crypto_auth_hmacsha512256_update (crypto_auth_hmacsha512256_state *state, const unsigned char *in, unsigned long long inlen) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_auth_hmacsha512256_update (IntPtr state, byte[] @in, ulong inlen);

		// extern int crypto_auth_hmacsha512256_final (crypto_auth_hmacsha512256_state *state, unsigned char *out) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_auth_hmacsha512256_final (IntPtr state, byte[] @out);

		// extern size_t crypto_auth_bytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_auth_bytes ();

		// extern size_t crypto_auth_keybytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_auth_keybytes ();

		// extern const char * crypto_auth_primitive () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  sbyte[] crypto_auth_primitive ();

		// extern int crypto_auth (unsigned char *out, const unsigned char *in, unsigned long long inlen, const unsigned char *k) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_auth (byte[] @out, byte[] @in, ulong inlen, byte[] k);

		// extern int crypto_auth_verify (const unsigned char *h, const unsigned char *in, unsigned long long inlen, const unsigned char *k) __attribute__((visibility("default"))) __attribute__((warn_unused_result));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_auth_verify (byte[] h, byte[] @in, ulong inlen, byte[] k);

		// extern size_t crypto_hash_sha256_statebytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_hash_sha256_statebytes ();

		// extern size_t crypto_hash_sha256_bytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_hash_sha256_bytes ();

		// extern int crypto_hash_sha256 (unsigned char *out, const unsigned char *in, unsigned long long inlen) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_hash_sha256 (byte[] @out, byte[] @in, ulong inlen);

		// extern int crypto_hash_sha256_init (crypto_hash_sha256_state *state) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_hash_sha256_init (IntPtr state);

		// extern int crypto_hash_sha256_update (crypto_hash_sha256_state *state, const unsigned char *in, unsigned long long inlen) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_hash_sha256_update (IntPtr state, byte[] @in, ulong inlen);

		// extern int crypto_hash_sha256_final (crypto_hash_sha256_state *state, unsigned char *out) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_hash_sha256_final (IntPtr state, byte[] @out);

		// extern size_t crypto_auth_hmacsha256_bytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_auth_hmacsha256_bytes ();

		// extern size_t crypto_auth_hmacsha256_keybytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_auth_hmacsha256_keybytes ();

		// extern int crypto_auth_hmacsha256 (unsigned char *out, const unsigned char *in, unsigned long long inlen, const unsigned char *k) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_auth_hmacsha256 (byte[] @out, byte[] @in, ulong inlen, byte[] k);

		// extern int crypto_auth_hmacsha256_verify (const unsigned char *h, const unsigned char *in, unsigned long long inlen, const unsigned char *k) __attribute__((visibility("default"))) __attribute__((warn_unused_result));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_auth_hmacsha256_verify (byte[] h, byte[] @in, ulong inlen, byte[] k);

		// extern size_t crypto_auth_hmacsha256_statebytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_auth_hmacsha256_statebytes ();

		// extern int crypto_auth_hmacsha256_init (crypto_auth_hmacsha256_state *state, const unsigned char *key, size_t keylen) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_auth_hmacsha256_init (IntPtr state, byte[] key, long keylen);

		// extern int crypto_auth_hmacsha256_update (crypto_auth_hmacsha256_state *state, const unsigned char *in, unsigned long long inlen) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_auth_hmacsha256_update (IntPtr state, byte[] @in, ulong inlen);

		// extern int crypto_auth_hmacsha256_final (crypto_auth_hmacsha256_state *state, unsigned char *out) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_auth_hmacsha256_final (IntPtr state, byte[] @out);

		// extern size_t crypto_box_curve25519xsalsa20poly1305_seedbytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_box_curve25519xsalsa20poly1305_seedbytes ();

		// extern size_t crypto_box_curve25519xsalsa20poly1305_publickeybytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_box_curve25519xsalsa20poly1305_publickeybytes ();

		// extern size_t crypto_box_curve25519xsalsa20poly1305_secretkeybytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_box_curve25519xsalsa20poly1305_secretkeybytes ();

		// extern size_t crypto_box_curve25519xsalsa20poly1305_beforenmbytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_box_curve25519xsalsa20poly1305_beforenmbytes ();

		// extern size_t crypto_box_curve25519xsalsa20poly1305_noncebytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_box_curve25519xsalsa20poly1305_noncebytes ();

		// extern size_t crypto_box_curve25519xsalsa20poly1305_macbytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_box_curve25519xsalsa20poly1305_macbytes ();

		// extern size_t crypto_box_curve25519xsalsa20poly1305_boxzerobytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_box_curve25519xsalsa20poly1305_boxzerobytes ();

		// extern size_t crypto_box_curve25519xsalsa20poly1305_zerobytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_box_curve25519xsalsa20poly1305_zerobytes ();

		// extern int crypto_box_curve25519xsalsa20poly1305 (unsigned char *c, const unsigned char *m, unsigned long long mlen, const unsigned char *n, const unsigned char *pk, const unsigned char *sk) __attribute__((visibility("default"))) __attribute__((warn_unused_result));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_box_curve25519xsalsa20poly1305 (byte[] c, byte[] m, ulong mlen, byte[] n, byte[] pk, byte[] sk);

		// extern int crypto_box_curve25519xsalsa20poly1305_open (unsigned char *m, const unsigned char *c, unsigned long long clen, const unsigned char *n, const unsigned char *pk, const unsigned char *sk) __attribute__((visibility("default"))) __attribute__((warn_unused_result));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_box_curve25519xsalsa20poly1305_open (byte[] m, byte[] c, ulong clen, byte[] n, byte[] pk, byte[] sk);

		// extern int crypto_box_curve25519xsalsa20poly1305_seed_keypair (unsigned char *pk, unsigned char *sk, const unsigned char *seed) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_box_curve25519xsalsa20poly1305_seed_keypair (byte[] pk, byte[] sk, byte[] seed);

		// extern int crypto_box_curve25519xsalsa20poly1305_keypair (unsigned char *pk, unsigned char *sk) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_box_curve25519xsalsa20poly1305_keypair (byte[] pk, byte[] sk);

		// extern int crypto_box_curve25519xsalsa20poly1305_beforenm (unsigned char *k, const unsigned char *pk, const unsigned char *sk) __attribute__((visibility("default"))) __attribute__((warn_unused_result));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_box_curve25519xsalsa20poly1305_beforenm (byte[] k, byte[] pk, byte[] sk);

		// extern int crypto_box_curve25519xsalsa20poly1305_afternm (unsigned char *c, const unsigned char *m, unsigned long long mlen, const unsigned char *n, const unsigned char *k) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_box_curve25519xsalsa20poly1305_afternm (byte[] c, byte[] m, ulong mlen, byte[] n, byte[] k);

		// extern int crypto_box_curve25519xsalsa20poly1305_open_afternm (unsigned char *m, const unsigned char *c, unsigned long long clen, const unsigned char *n, const unsigned char *k) __attribute__((visibility("default"))) __attribute__((warn_unused_result));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_box_curve25519xsalsa20poly1305_open_afternm (byte[] m, byte[] c, ulong clen, byte[] n, byte[] k);

		// extern size_t crypto_box_seedbytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_box_seedbytes ();

		// extern size_t crypto_box_publickeybytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_box_publickeybytes ();

		// extern size_t crypto_box_secretkeybytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_box_secretkeybytes ();

		// extern size_t crypto_box_noncebytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_box_noncebytes ();

		// extern size_t crypto_box_macbytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_box_macbytes ();

		// extern const char * crypto_box_primitive () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  sbyte[] crypto_box_primitive ();

		// extern int crypto_box_seed_keypair (unsigned char *pk, unsigned char *sk, const unsigned char *seed) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_box_seed_keypair (byte[] pk, byte[] sk, byte[] seed);

		// extern int crypto_box_keypair (unsigned char *pk, unsigned char *sk) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_box_keypair (byte[] pk, byte[] sk);

		// extern int crypto_box_easy (unsigned char *c, const unsigned char *m, unsigned long long mlen, const unsigned char *n, const unsigned char *pk, const unsigned char *sk) __attribute__((visibility("default"))) __attribute__((warn_unused_result));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_box_easy (byte[] c, byte[] m, ulong mlen, byte[] n, byte[] pk, byte[] sk);

		// extern int crypto_box_open_easy (unsigned char *m, const unsigned char *c, unsigned long long clen, const unsigned char *n, const unsigned char *pk, const unsigned char *sk) __attribute__((visibility("default"))) __attribute__((warn_unused_result));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_box_open_easy (byte[] m, byte[] c, ulong clen, byte[] n, byte[] pk, byte[] sk);

		// extern int crypto_box_detached (unsigned char *c, unsigned char *mac, const unsigned char *m, unsigned long long mlen, const unsigned char *n, const unsigned char *pk, const unsigned char *sk) __attribute__((visibility("default"))) __attribute__((warn_unused_result));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_box_detached (byte[] c, byte[] mac, byte[] m, ulong mlen, byte[] n, byte[] pk, byte[] sk);

		// extern int crypto_box_open_detached (unsigned char *m, const unsigned char *c, const unsigned char *mac, unsigned long long clen, const unsigned char *n, const unsigned char *pk, const unsigned char *sk) __attribute__((visibility("default"))) __attribute__((warn_unused_result));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_box_open_detached (byte[] m, byte[] c, byte[] mac, ulong clen, byte[] n, byte[] pk, byte[] sk);

		// extern size_t crypto_box_beforenmbytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_box_beforenmbytes ();

		// extern int crypto_box_beforenm (unsigned char *k, const unsigned char *pk, const unsigned char *sk) __attribute__((visibility("default"))) __attribute__((warn_unused_result));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_box_beforenm (byte[] k, byte[] pk, byte[] sk);

		// extern int crypto_box_easy_afternm (unsigned char *c, const unsigned char *m, unsigned long long mlen, const unsigned char *n, const unsigned char *k) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_box_easy_afternm (byte[] c, byte[] m, ulong mlen, byte[] n, byte[] k);

		// extern int crypto_box_open_easy_afternm (unsigned char *m, const unsigned char *c, unsigned long long clen, const unsigned char *n, const unsigned char *k) __attribute__((visibility("default"))) __attribute__((warn_unused_result));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_box_open_easy_afternm (byte[] m, byte[] c, ulong clen, byte[] n, byte[] k);

		// extern int crypto_box_detached_afternm (unsigned char *c, unsigned char *mac, const unsigned char *m, unsigned long long mlen, const unsigned char *n, const unsigned char *k) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_box_detached_afternm (byte[] c, byte[] mac, byte[] m, ulong mlen, byte[] n, byte[] k);

		// extern int crypto_box_open_detached_afternm (unsigned char *m, const unsigned char *c, const unsigned char *mac, unsigned long long clen, const unsigned char *n, const unsigned char *k) __attribute__((visibility("default"))) __attribute__((warn_unused_result));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_box_open_detached_afternm (byte[] m, byte[] c, byte[] mac, ulong clen, byte[] n, byte[] k);

		// extern size_t crypto_box_sealbytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_box_sealbytes ();

		// extern int crypto_box_seal (unsigned char *c, const unsigned char *m, unsigned long long mlen, const unsigned char *pk) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_box_seal (byte[] c, byte[] m, ulong mlen, byte[] pk);

		// extern int crypto_box_seal_open (unsigned char *m, const unsigned char *c, unsigned long long clen, const unsigned char *pk, const unsigned char *sk) __attribute__((visibility("default"))) __attribute__((warn_unused_result));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_box_seal_open (byte[] m, byte[] c, ulong clen, byte[] pk, byte[] sk);

		// extern size_t crypto_box_zerobytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_box_zerobytes ();

		// extern size_t crypto_box_boxzerobytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_box_boxzerobytes ();

		// extern int crypto_box (unsigned char *c, const unsigned char *m, unsigned long long mlen, const unsigned char *n, const unsigned char *pk, const unsigned char *sk) __attribute__((visibility("default"))) __attribute__((warn_unused_result));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_box (byte[] c, byte[] m, ulong mlen, byte[] n, byte[] pk, byte[] sk);

		// extern int crypto_box_open (unsigned char *m, const unsigned char *c, unsigned long long clen, const unsigned char *n, const unsigned char *pk, const unsigned char *sk) __attribute__((visibility("default"))) __attribute__((warn_unused_result));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_box_open (byte[] m, byte[] c, ulong clen, byte[] n, byte[] pk, byte[] sk);

		// extern int crypto_box_afternm (unsigned char *c, const unsigned char *m, unsigned long long mlen, const unsigned char *n, const unsigned char *k) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_box_afternm (byte[] c, byte[] m, ulong mlen, byte[] n, byte[] k);

		// extern int crypto_box_open_afternm (unsigned char *m, const unsigned char *c, unsigned long long clen, const unsigned char *n, const unsigned char *k) __attribute__((visibility("default"))) __attribute__((warn_unused_result));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_box_open_afternm (byte[] m, byte[] c, ulong clen, byte[] n, byte[] k);

		// extern size_t crypto_core_hsalsa20_outputbytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_core_hsalsa20_outputbytes ();

		// extern size_t crypto_core_hsalsa20_inputbytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_core_hsalsa20_inputbytes ();

		// extern size_t crypto_core_hsalsa20_keybytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_core_hsalsa20_keybytes ();

		// extern size_t crypto_core_hsalsa20_constbytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_core_hsalsa20_constbytes ();

		// extern int crypto_core_hsalsa20 (unsigned char *out, const unsigned char *in, const unsigned char *k, const unsigned char *c) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_core_hsalsa20 (byte[] @out, byte[] @in, byte[] k, byte[] c);

		// extern size_t crypto_core_hchacha20_outputbytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_core_hchacha20_outputbytes ();

		// extern size_t crypto_core_hchacha20_inputbytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_core_hchacha20_inputbytes ();

		// extern size_t crypto_core_hchacha20_keybytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_core_hchacha20_keybytes ();

		// extern size_t crypto_core_hchacha20_constbytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_core_hchacha20_constbytes ();

		// extern int crypto_core_hchacha20 (unsigned char *out, const unsigned char *in, const unsigned char *k, const unsigned char *c) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_core_hchacha20 (byte[] @out, byte[] @in, byte[] k, byte[] c);

		// extern size_t crypto_core_salsa20_outputbytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_core_salsa20_outputbytes ();

		// extern size_t crypto_core_salsa20_inputbytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_core_salsa20_inputbytes ();

		// extern size_t crypto_core_salsa20_keybytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_core_salsa20_keybytes ();

		// extern size_t crypto_core_salsa20_constbytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_core_salsa20_constbytes ();

		// extern int crypto_core_salsa20 (unsigned char *out, const unsigned char *in, const unsigned char *k, const unsigned char *c) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_core_salsa20 (byte[] @out, byte[] @in, byte[] k, byte[] c);

		// extern size_t crypto_core_salsa2012_outputbytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_core_salsa2012_outputbytes ();

		// extern size_t crypto_core_salsa2012_inputbytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_core_salsa2012_inputbytes ();

		// extern size_t crypto_core_salsa2012_keybytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_core_salsa2012_keybytes ();

		// extern size_t crypto_core_salsa2012_constbytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_core_salsa2012_constbytes ();

		// extern int crypto_core_salsa2012 (unsigned char *out, const unsigned char *in, const unsigned char *k, const unsigned char *c) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_core_salsa2012 (byte[] @out, byte[] @in, byte[] k, byte[] c);

		// extern size_t crypto_core_salsa208_outputbytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_core_salsa208_outputbytes ();

		// extern size_t crypto_core_salsa208_inputbytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_core_salsa208_inputbytes ();

		// extern size_t crypto_core_salsa208_keybytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_core_salsa208_keybytes ();

		// extern size_t crypto_core_salsa208_constbytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_core_salsa208_constbytes ();

		// extern int crypto_core_salsa208 (unsigned char *out, const unsigned char *in, const unsigned char *k, const unsigned char *c) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_core_salsa208 (byte[] @out, byte[] @in, byte[] k, byte[] c);

		// extern size_t crypto_generichash_blake2b_bytes_min () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_generichash_blake2b_bytes_min ();

		// extern size_t crypto_generichash_blake2b_bytes_max () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_generichash_blake2b_bytes_max ();

		// extern size_t crypto_generichash_blake2b_bytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_generichash_blake2b_bytes ();

		// extern size_t crypto_generichash_blake2b_keybytes_min () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_generichash_blake2b_keybytes_min ();

		// extern size_t crypto_generichash_blake2b_keybytes_max () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_generichash_blake2b_keybytes_max ();

		// extern size_t crypto_generichash_blake2b_keybytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_generichash_blake2b_keybytes ();

		// extern size_t crypto_generichash_blake2b_saltbytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_generichash_blake2b_saltbytes ();

		// extern size_t crypto_generichash_blake2b_personalbytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_generichash_blake2b_personalbytes ();

		// extern size_t crypto_generichash_blake2b_statebytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_generichash_blake2b_statebytes ();

		// extern int crypto_generichash_blake2b (unsigned char *out, size_t outlen, const unsigned char *in, unsigned long long inlen, const unsigned char *key, size_t keylen) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_generichash_blake2b (byte[] @out, long outlen, byte[] @in, ulong inlen, byte[] key, long keylen);

		// extern int crypto_generichash_blake2b_salt_personal (unsigned char *out, size_t outlen, const unsigned char *in, unsigned long long inlen, const unsigned char *key, size_t keylen, const unsigned char *salt, const unsigned char *personal) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_generichash_blake2b_salt_personal (byte[] @out, long outlen, byte[] @in, ulong inlen, byte[] key, long keylen, byte[] salt, byte[] personal);

		// extern int crypto_generichash_blake2b_init (crypto_generichash_blake2b_state *state, const unsigned char *key, const size_t keylen, const size_t outlen) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_generichash_blake2b_init (IntPtr state, byte[] key, long keylen, long outlen);

		// extern int crypto_generichash_blake2b_init_salt_personal (crypto_generichash_blake2b_state *state, const unsigned char *key, const size_t keylen, const size_t outlen, const unsigned char *salt, const unsigned char *personal) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_generichash_blake2b_init_salt_personal (IntPtr state, byte[] key, long keylen, long outlen, byte[] salt, byte[] personal);

		// extern int crypto_generichash_blake2b_update (crypto_generichash_blake2b_state *state, const unsigned char *in, unsigned long long inlen) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_generichash_blake2b_update (IntPtr state, byte[] @in, ulong inlen);

		// extern int crypto_generichash_blake2b_final (crypto_generichash_blake2b_state *state, unsigned char *out, const size_t outlen) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_generichash_blake2b_final (IntPtr state, byte[] @out, long outlen);

		// extern int _crypto_generichash_blake2b_pick_best_implementation ();
		[DllImport ("__Internal")]
	
		public  static extern int _crypto_generichash_blake2b_pick_best_implementation ();

		// extern size_t crypto_generichash_bytes_min () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_generichash_bytes_min ();

		// extern size_t crypto_generichash_bytes_max () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_generichash_bytes_max ();

		// extern size_t crypto_generichash_bytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_generichash_bytes ();

		// extern size_t crypto_generichash_keybytes_min () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_generichash_keybytes_min ();

		// extern size_t crypto_generichash_keybytes_max () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_generichash_keybytes_max ();

		// extern size_t crypto_generichash_keybytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_generichash_keybytes ();

		// extern const char * crypto_generichash_primitive () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  sbyte[] crypto_generichash_primitive ();

		// extern size_t crypto_generichash_statebytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_generichash_statebytes ();

		// extern int crypto_generichash (unsigned char *out, size_t outlen, const unsigned char *in, unsigned long long inlen, const unsigned char *key, size_t keylen) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_generichash (byte[] @out, long outlen, byte[] @in, ulong inlen, byte[] key, long keylen);

		// extern int crypto_generichash_init (crypto_generichash_state *state, const unsigned char *key, const size_t keylen, const size_t outlen) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_generichash_init (IntPtr state, byte[] key, long keylen, long outlen);

		// extern int crypto_generichash_update (crypto_generichash_state *state, const unsigned char *in, unsigned long long inlen) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_generichash_update (IntPtr state, byte[] @in, ulong inlen);

		// extern int crypto_generichash_final (crypto_generichash_state *state, unsigned char *out, const size_t outlen) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_generichash_final (IntPtr state, byte[] @out, long outlen);

		// extern size_t crypto_hash_bytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_hash_bytes ();

		// extern int crypto_hash (unsigned char *out, const unsigned char *in, unsigned long long inlen) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_hash (byte[] @out, byte[] @in, ulong inlen);

		// extern const char * crypto_hash_primitive () __attribute__((visibility("default"))) __attribute__((warn_unused_result));
		[DllImport ("__Internal")]
	
		public  static extern  sbyte[] crypto_hash_primitive ();

		// extern size_t crypto_onetimeauth_poly1305_bytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_onetimeauth_poly1305_bytes ();

		// extern size_t crypto_onetimeauth_poly1305_keybytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_onetimeauth_poly1305_keybytes ();

		// extern int crypto_onetimeauth_poly1305 (unsigned char *out, const unsigned char *in, unsigned long long inlen, const unsigned char *k) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_onetimeauth_poly1305 (byte[] @out, byte[] @in, ulong inlen, byte[] k);

		// extern int crypto_onetimeauth_poly1305_verify (const unsigned char *h, const unsigned char *in, unsigned long long inlen, const unsigned char *k) __attribute__((visibility("default"))) __attribute__((warn_unused_result));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_onetimeauth_poly1305_verify (byte[] h, byte[] @in, ulong inlen, byte[] k);

		// extern int crypto_onetimeauth_poly1305_init (crypto_onetimeauth_poly1305_state *state, const unsigned char *key) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_onetimeauth_poly1305_init (IntPtr state, byte[] key);

		// extern int crypto_onetimeauth_poly1305_update (crypto_onetimeauth_poly1305_state *state, const unsigned char *in, unsigned long long inlen) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_onetimeauth_poly1305_update (IntPtr state, byte[] @in, ulong inlen);

		// extern int crypto_onetimeauth_poly1305_final (crypto_onetimeauth_poly1305_state *state, unsigned char *out) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_onetimeauth_poly1305_final (IntPtr state, byte[] @out);

		// extern int _crypto_onetimeauth_poly1305_pick_best_implementation ();
		[DllImport ("__Internal")]
	
		public  static extern int _crypto_onetimeauth_poly1305_pick_best_implementation ();

		// extern size_t crypto_onetimeauth_statebytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_onetimeauth_statebytes ();

		// extern size_t crypto_onetimeauth_bytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_onetimeauth_bytes ();

		// extern size_t crypto_onetimeauth_keybytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_onetimeauth_keybytes ();

		// extern const char * crypto_onetimeauth_primitive () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  sbyte[] crypto_onetimeauth_primitive ();

		// extern int crypto_onetimeauth (unsigned char *out, const unsigned char *in, unsigned long long inlen, const unsigned char *k) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_onetimeauth (byte[] @out, byte[] @in, ulong inlen, byte[] k);

		// extern int crypto_onetimeauth_verify (const unsigned char *h, const unsigned char *in, unsigned long long inlen, const unsigned char *k) __attribute__((visibility("default"))) __attribute__((warn_unused_result));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_onetimeauth_verify (byte[] h, byte[] @in, ulong inlen, byte[] k);

		// extern int crypto_onetimeauth_init (crypto_onetimeauth_state *state, const unsigned char *key) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_onetimeauth_init (IntPtr state, byte[] key);

		// extern int crypto_onetimeauth_update (crypto_onetimeauth_state *state, const unsigned char *in, unsigned long long inlen) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_onetimeauth_update (IntPtr state, byte[] @in, ulong inlen);

		// extern int crypto_onetimeauth_final (crypto_onetimeauth_state *state, unsigned char *out) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_onetimeauth_final (IntPtr state, byte[] @out);

		// extern int crypto_pwhash_argon2i_alg_argon2i13 () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern int crypto_pwhash_argon2i_alg_argon2i13 ();

		// extern size_t crypto_pwhash_argon2i_saltbytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_pwhash_argon2i_saltbytes ();

		// extern size_t crypto_pwhash_argon2i_strbytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_pwhash_argon2i_strbytes ();

		// extern const char * crypto_pwhash_argon2i_strprefix () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  sbyte[] crypto_pwhash_argon2i_strprefix ();

		// extern size_t crypto_pwhash_argon2i_opslimit_interactive () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_pwhash_argon2i_opslimit_interactive ();

		// extern size_t crypto_pwhash_argon2i_memlimit_interactive () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_pwhash_argon2i_memlimit_interactive ();

		// extern size_t crypto_pwhash_argon2i_opslimit_moderate () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_pwhash_argon2i_opslimit_moderate ();

		// extern size_t crypto_pwhash_argon2i_memlimit_moderate () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_pwhash_argon2i_memlimit_moderate ();

		// extern size_t crypto_pwhash_argon2i_opslimit_sensitive () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_pwhash_argon2i_opslimit_sensitive ();

		// extern size_t crypto_pwhash_argon2i_memlimit_sensitive () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_pwhash_argon2i_memlimit_sensitive ();

		// extern int crypto_pwhash_argon2i (unsigned char *const out, unsigned long long outlen, const char *const passwd, unsigned long long passwdlen, const unsigned char *const salt, unsigned long long opslimit, size_t memlimit, int alg) __attribute__((visibility("default"))) __attribute__((warn_unused_result));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_pwhash_argon2i (byte[] @out, ulong outlen, sbyte[] passwd, ulong passwdlen, byte[] salt, ulong opslimit, long memlimit, int alg);

		// extern int crypto_pwhash_argon2i_str (char *out, const char *const passwd, unsigned long long passwdlen, unsigned long long opslimit, size_t memlimit) __attribute__((visibility("default"))) __attribute__((warn_unused_result));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_pwhash_argon2i_str (sbyte[] @out, sbyte[] passwd, ulong passwdlen, ulong opslimit, long memlimit);

		// extern int crypto_pwhash_argon2i_str_verify (const char *str, const char *const passwd, unsigned long long passwdlen) __attribute__((visibility("default"))) __attribute__((warn_unused_result));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_pwhash_argon2i_str_verify (sbyte[] str, sbyte[] passwd, ulong passwdlen);

		// extern int _crypto_pwhash_argon2i_pick_best_implementation ();
		[DllImport ("__Internal")]
	
		public  static extern int _crypto_pwhash_argon2i_pick_best_implementation ();

		// extern int crypto_pwhash_alg_argon2i13 () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern int crypto_pwhash_alg_argon2i13 ();

		// extern int crypto_pwhash_alg_default () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern int crypto_pwhash_alg_default ();

		// extern size_t crypto_pwhash_saltbytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_pwhash_saltbytes ();

		// extern size_t crypto_pwhash_strbytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_pwhash_strbytes ();

		// extern const char * crypto_pwhash_strprefix () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  sbyte[] crypto_pwhash_strprefix ();

		// extern size_t crypto_pwhash_opslimit_interactive () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_pwhash_opslimit_interactive ();

		// extern size_t crypto_pwhash_memlimit_interactive () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_pwhash_memlimit_interactive ();

		// extern size_t crypto_pwhash_opslimit_moderate () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_pwhash_opslimit_moderate ();

		// extern size_t crypto_pwhash_memlimit_moderate () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_pwhash_memlimit_moderate ();

		// extern size_t crypto_pwhash_opslimit_sensitive () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_pwhash_opslimit_sensitive ();

		// extern size_t crypto_pwhash_memlimit_sensitive () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_pwhash_memlimit_sensitive ();

		// extern int crypto_pwhash (unsigned char *const out, unsigned long long outlen, const char *const passwd, unsigned long long passwdlen, const unsigned char *const salt, unsigned long long opslimit, size_t memlimit, int alg) __attribute__((visibility("default"))) __attribute__((warn_unused_result));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_pwhash (byte[] @out, ulong outlen, sbyte[] passwd, ulong passwdlen, byte[] salt, ulong opslimit, long memlimit, int alg);

		// extern int crypto_pwhash_str (char *out, const char *const passwd, unsigned long long passwdlen, unsigned long long opslimit, size_t memlimit) __attribute__((visibility("default"))) __attribute__((warn_unused_result));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_pwhash_str (sbyte[] @out, sbyte[] passwd, ulong passwdlen, ulong opslimit, long memlimit);

		// extern int crypto_pwhash_str_verify (const char *str, const char *const passwd, unsigned long long passwdlen) __attribute__((visibility("default"))) __attribute__((warn_unused_result));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_pwhash_str_verify (sbyte[] str, sbyte[] passwd, ulong passwdlen);

		// extern const char * crypto_pwhash_primitive () __attribute__((visibility("default"))) __attribute__((warn_unused_result));
		[DllImport ("__Internal")]
	
		public  static extern  sbyte[] crypto_pwhash_primitive ();

		// extern size_t crypto_pwhash_scryptsalsa208sha256_saltbytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_pwhash_scryptsalsa208sha256_saltbytes ();

		// extern size_t crypto_pwhash_scryptsalsa208sha256_strbytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_pwhash_scryptsalsa208sha256_strbytes ();

		// extern const char * crypto_pwhash_scryptsalsa208sha256_strprefix () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  sbyte[] crypto_pwhash_scryptsalsa208sha256_strprefix ();

		// extern size_t crypto_pwhash_scryptsalsa208sha256_opslimit_interactive () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_pwhash_scryptsalsa208sha256_opslimit_interactive ();

		// extern size_t crypto_pwhash_scryptsalsa208sha256_memlimit_interactive () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_pwhash_scryptsalsa208sha256_memlimit_interactive ();

		// extern size_t crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive ();

		// extern size_t crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive ();

		// extern int crypto_pwhash_scryptsalsa208sha256 (unsigned char *const out, unsigned long long outlen, const char *const passwd, unsigned long long passwdlen, const unsigned char *const salt, unsigned long long opslimit, size_t memlimit) __attribute__((visibility("default"))) __attribute__((warn_unused_result));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_pwhash_scryptsalsa208sha256 (byte[] @out, ulong outlen, sbyte[] passwd, ulong passwdlen, byte[] salt, ulong opslimit, long memlimit);

		// extern int crypto_pwhash_scryptsalsa208sha256_str (char *out, const char *const passwd, unsigned long long passwdlen, unsigned long long opslimit, size_t memlimit) __attribute__((visibility("default"))) __attribute__((warn_unused_result));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_pwhash_scryptsalsa208sha256_str (sbyte[] @out, sbyte[] passwd, ulong passwdlen, ulong opslimit, long memlimit);

		// extern int crypto_pwhash_scryptsalsa208sha256_str_verify (const char *str, const char *const passwd, unsigned long long passwdlen) __attribute__((visibility("default"))) __attribute__((warn_unused_result));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_pwhash_scryptsalsa208sha256_str_verify (sbyte[] str, sbyte[] passwd, ulong passwdlen);

		// extern int crypto_pwhash_scryptsalsa208sha256_ll (const uint8_t *passwd, size_t passwdlen, const uint8_t *salt, size_t saltlen, uint64_t N, uint32_t r, uint32_t p, uint8_t *buf, size_t buflen) __attribute__((visibility("default"))) __attribute__((warn_unused_result));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_pwhash_scryptsalsa208sha256_ll (byte[] passwd, long passwdlen, byte[] salt, long saltlen, ulong N, uint r, uint p, byte[] buf, long buflen);

		// extern size_t crypto_scalarmult_curve25519_bytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_scalarmult_curve25519_bytes ();

		// extern size_t crypto_scalarmult_curve25519_scalarbytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_scalarmult_curve25519_scalarbytes ();

		// extern int crypto_scalarmult_curve25519 (unsigned char *q, const unsigned char *n, const unsigned char *p) __attribute__((visibility("default"))) __attribute__((warn_unused_result));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_scalarmult_curve25519 (byte[] q, byte[] n, byte[] p);

		// extern int crypto_scalarmult_curve25519_base (unsigned char *q, const unsigned char *n) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_scalarmult_curve25519_base (byte[] q, byte[] n);

		// extern int _crypto_scalarmult_curve25519_pick_best_implementation ();
		[DllImport ("__Internal")]
	
		public  static extern int _crypto_scalarmult_curve25519_pick_best_implementation ();

		// extern size_t crypto_scalarmult_bytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_scalarmult_bytes ();

		// extern size_t crypto_scalarmult_scalarbytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_scalarmult_scalarbytes ();

		// extern const char * crypto_scalarmult_primitive () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  sbyte[] crypto_scalarmult_primitive ();

		// extern int crypto_scalarmult_base (unsigned char *q, const unsigned char *n) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_scalarmult_base (byte[] q, byte[] n);

		// extern int crypto_scalarmult (unsigned char *q, const unsigned char *n, const unsigned char *p) __attribute__((visibility("default"))) __attribute__((warn_unused_result));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_scalarmult (byte[] q, byte[] n, byte[] p);

		// extern size_t crypto_secretbox_xsalsa20poly1305_keybytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_secretbox_xsalsa20poly1305_keybytes ();

		// extern size_t crypto_secretbox_xsalsa20poly1305_noncebytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_secretbox_xsalsa20poly1305_noncebytes ();

		// extern size_t crypto_secretbox_xsalsa20poly1305_macbytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_secretbox_xsalsa20poly1305_macbytes ();

		// extern size_t crypto_secretbox_xsalsa20poly1305_boxzerobytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_secretbox_xsalsa20poly1305_boxzerobytes ();

		// extern size_t crypto_secretbox_xsalsa20poly1305_zerobytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_secretbox_xsalsa20poly1305_zerobytes ();

		// extern int crypto_secretbox_xsalsa20poly1305 (unsigned char *c, const unsigned char *m, unsigned long long mlen, const unsigned char *n, const unsigned char *k) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_secretbox_xsalsa20poly1305 (byte[] c, byte[] m, ulong mlen, byte[] n, byte[] k);

		// extern int crypto_secretbox_xsalsa20poly1305_open (unsigned char *m, const unsigned char *c, unsigned long long clen, const unsigned char *n, const unsigned char *k) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_secretbox_xsalsa20poly1305_open (byte[] m, byte[] c, ulong clen, byte[] n, byte[] k);

		// extern size_t crypto_secretbox_keybytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_secretbox_keybytes ();

		// extern size_t crypto_secretbox_noncebytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_secretbox_noncebytes ();

		// extern size_t crypto_secretbox_macbytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_secretbox_macbytes ();

		// extern const char * crypto_secretbox_primitive () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  sbyte[] crypto_secretbox_primitive ();

		// extern int crypto_secretbox_easy (unsigned char *c, const unsigned char *m, unsigned long long mlen, const unsigned char *n, const unsigned char *k) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_secretbox_easy (byte[] c, byte[] m, ulong mlen, byte[] n, byte[] k);

		// extern int crypto_secretbox_open_easy (unsigned char *m, const unsigned char *c, unsigned long long clen, const unsigned char *n, const unsigned char *k) __attribute__((visibility("default"))) __attribute__((warn_unused_result));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_secretbox_open_easy (byte[] m, byte[] c, ulong clen, byte[] n, byte[] k);

		// extern int crypto_secretbox_detached (unsigned char *c, unsigned char *mac, const unsigned char *m, unsigned long long mlen, const unsigned char *n, const unsigned char *k) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_secretbox_detached (byte[] c, byte[] mac, byte[] m, ulong mlen, byte[] n, byte[] k);

		// extern int crypto_secretbox_open_detached (unsigned char *m, const unsigned char *c, const unsigned char *mac, unsigned long long clen, const unsigned char *n, const unsigned char *k) __attribute__((visibility("default"))) __attribute__((warn_unused_result));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_secretbox_open_detached (byte[] m, byte[] c, byte[] mac, ulong clen, byte[] n, byte[] k);

		// extern size_t crypto_secretbox_zerobytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_secretbox_zerobytes ();

		// extern size_t crypto_secretbox_boxzerobytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_secretbox_boxzerobytes ();

		// extern int crypto_secretbox (unsigned char *c, const unsigned char *m, unsigned long long mlen, const unsigned char *n, const unsigned char *k) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_secretbox (byte[] c, byte[] m, ulong mlen, byte[] n, byte[] k);

		// extern int crypto_secretbox_open (unsigned char *m, const unsigned char *c, unsigned long long clen, const unsigned char *n, const unsigned char *k) __attribute__((visibility("default"))) __attribute__((warn_unused_result));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_secretbox_open (byte[] m, byte[] c, ulong clen, byte[] n, byte[] k);

		// extern size_t crypto_shorthash_siphash24_bytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_shorthash_siphash24_bytes ();

		// extern size_t crypto_shorthash_siphash24_keybytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_shorthash_siphash24_keybytes ();

		// extern int crypto_shorthash_siphash24 (unsigned char *out, const unsigned char *in, unsigned long long inlen, const unsigned char *k) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_shorthash_siphash24 (byte[] @out, byte[] @in, ulong inlen, byte[] k);

		// extern size_t crypto_shorthash_bytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_shorthash_bytes ();

		// extern size_t crypto_shorthash_keybytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_shorthash_keybytes ();

		// extern const char * crypto_shorthash_primitive () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  sbyte[] crypto_shorthash_primitive ();

		// extern int crypto_shorthash (unsigned char *out, const unsigned char *in, unsigned long long inlen, const unsigned char *k) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_shorthash (byte[] @out, byte[] @in, ulong inlen, byte[] k);

		// extern size_t crypto_sign_ed25519_bytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_sign_ed25519_bytes ();

		// extern size_t crypto_sign_ed25519_seedbytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_sign_ed25519_seedbytes ();

		// extern size_t crypto_sign_ed25519_publickeybytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_sign_ed25519_publickeybytes ();

		// extern size_t crypto_sign_ed25519_secretkeybytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_sign_ed25519_secretkeybytes ();

		// extern int crypto_sign_ed25519 (unsigned char *sm, unsigned long long *smlen_p, const unsigned char *m, unsigned long long mlen, const unsigned char *sk) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_sign_ed25519 (byte[] sm, long  smlen_p, byte[] m, ulong mlen, byte[] sk);

		// extern int crypto_sign_ed25519_open (unsigned char *m, unsigned long long *mlen_p, const unsigned char *sm, unsigned long long smlen, const unsigned char *pk) __attribute__((visibility("default"))) __attribute__((warn_unused_result));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_sign_ed25519_open (byte[] m, long  mlen_p, byte[] sm, ulong smlen, byte[] pk);

		// extern int crypto_sign_ed25519_detached (unsigned char *sig, unsigned long long *siglen_p, const unsigned char *m, unsigned long long mlen, const unsigned char *sk) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_sign_ed25519_detached (byte[] sig, long  siglen_p, byte[] m, ulong mlen, byte[] sk);

		// extern int crypto_sign_ed25519_verify_detached (const unsigned char *sig, const unsigned char *m, unsigned long long mlen, const unsigned char *pk) __attribute__((visibility("default"))) __attribute__((warn_unused_result));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_sign_ed25519_verify_detached (byte[] sig, byte[] m, ulong mlen, byte[] pk);

		// extern int crypto_sign_ed25519_keypair (unsigned char *pk, unsigned char *sk) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_sign_ed25519_keypair (byte[] pk, byte[] sk);

		// extern int crypto_sign_ed25519_seed_keypair (unsigned char *pk, unsigned char *sk, const unsigned char *seed) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_sign_ed25519_seed_keypair (byte[] pk, byte[] sk, byte[] seed);

		// extern int crypto_sign_ed25519_pk_to_curve25519 (unsigned char *curve25519_pk, const unsigned char *ed25519_pk) __attribute__((visibility("default"))) __attribute__((warn_unused_result));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_sign_ed25519_pk_to_curve25519 (byte[] curve25519_pk, byte[] ed25519_pk);

		// extern int crypto_sign_ed25519_sk_to_curve25519 (unsigned char *curve25519_sk, const unsigned char *ed25519_sk) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_sign_ed25519_sk_to_curve25519 (byte[] curve25519_sk, byte[] ed25519_sk);

		// extern int crypto_sign_ed25519_sk_to_seed (unsigned char *seed, const unsigned char *sk) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_sign_ed25519_sk_to_seed (byte[] seed, byte[] sk);

		// extern int crypto_sign_ed25519_sk_to_pk (unsigned char *pk, const unsigned char *sk) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_sign_ed25519_sk_to_pk (byte[] pk, byte[] sk);

		// extern size_t crypto_sign_bytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_sign_bytes ();

		// extern size_t crypto_sign_seedbytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_sign_seedbytes ();

		// extern size_t crypto_sign_publickeybytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_sign_publickeybytes ();

		// extern size_t crypto_sign_secretkeybytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_sign_secretkeybytes ();

		// extern const char * crypto_sign_primitive () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  sbyte[] crypto_sign_primitive ();

		// extern int crypto_sign_seed_keypair (unsigned char *pk, unsigned char *sk, const unsigned char *seed) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_sign_seed_keypair (byte[] pk, byte[] sk, byte[] seed);

		// extern int crypto_sign_keypair (unsigned char *pk, unsigned char *sk) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_sign_keypair (byte[] pk, byte[] sk);

		// extern int crypto_sign (unsigned char *sm, unsigned long long *smlen_p, const unsigned char *m, unsigned long long mlen, const unsigned char *sk) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_sign (byte[] sm, long  smlen_p, byte[] m, ulong mlen, byte[] sk);

		// extern int crypto_sign_open (unsigned char *m, unsigned long long *mlen_p, const unsigned char *sm, unsigned long long smlen, const unsigned char *pk) __attribute__((visibility("default"))) __attribute__((warn_unused_result));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_sign_open (byte[] m, long  mlen_p, byte[] sm, ulong smlen, byte[] pk);

		// extern int crypto_sign_detached (unsigned char *sig, unsigned long long *siglen_p, const unsigned char *m, unsigned long long mlen, const unsigned char *sk) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_sign_detached (byte[] sig, long  siglen_p, byte[] m, ulong mlen, byte[] sk);

		// extern int crypto_sign_verify_detached (const unsigned char *sig, const unsigned char *m, unsigned long long mlen, const unsigned char *pk) __attribute__((visibility("default"))) __attribute__((warn_unused_result));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_sign_verify_detached (byte[] sig, byte[] m, ulong mlen, byte[] pk);

		// extern size_t crypto_stream_xsalsa20_keybytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_stream_xsalsa20_keybytes ();

		// extern size_t crypto_stream_xsalsa20_noncebytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_stream_xsalsa20_noncebytes ();

		// extern int crypto_stream_xsalsa20 (unsigned char *c, unsigned long long clen, const unsigned char *n, const unsigned char *k) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_stream_xsalsa20 (byte[] c, ulong clen, byte[] n, byte[] k);

		// extern int crypto_stream_xsalsa20_xor (unsigned char *c, const unsigned char *m, unsigned long long mlen, const unsigned char *n, const unsigned char *k) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_stream_xsalsa20_xor (byte[] c, byte[] m, ulong mlen, byte[] n, byte[] k);

		// extern int crypto_stream_xsalsa20_xor_ic (unsigned char *c, const unsigned char *m, unsigned long long mlen, const unsigned char *n, uint64_t ic, const unsigned char *k) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_stream_xsalsa20_xor_ic (byte[] c, byte[] m, ulong mlen, byte[] n, ulong ic, byte[] k);

		// extern size_t crypto_stream_keybytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_stream_keybytes ();

		// extern size_t crypto_stream_noncebytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_stream_noncebytes ();

		// extern const char * crypto_stream_primitive () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  sbyte[] crypto_stream_primitive ();

		// extern int crypto_stream (unsigned char *c, unsigned long long clen, const unsigned char *n, const unsigned char *k) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_stream (byte[] c, ulong clen, byte[] n, byte[] k);

		// extern int crypto_stream_xor (unsigned char *c, const unsigned char *m, unsigned long long mlen, const unsigned char *n, const unsigned char *k) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_stream_xor (byte[] c, byte[] m, ulong mlen, byte[] n, byte[] k);

		// extern size_t crypto_stream_aes128ctr_keybytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_stream_aes128ctr_keybytes ();

		// extern size_t crypto_stream_aes128ctr_noncebytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_stream_aes128ctr_noncebytes ();

		// extern size_t crypto_stream_aes128ctr_beforenmbytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_stream_aes128ctr_beforenmbytes ();

		// extern int crypto_stream_aes128ctr (unsigned char *out, unsigned long long outlen, const unsigned char *n, const unsigned char *k) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_stream_aes128ctr (byte[] @out, ulong outlen, byte[] n, byte[] k);

		// extern int crypto_stream_aes128ctr_xor (unsigned char *out, const unsigned char *in, unsigned long long inlen, const unsigned char *n, const unsigned char *k) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_stream_aes128ctr_xor (byte[] @out, byte[] @in, ulong inlen, byte[] n, byte[] k);

		// extern int crypto_stream_aes128ctr_beforenm (unsigned char *c, const unsigned char *k) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_stream_aes128ctr_beforenm (byte[] c, byte[] k);

		// extern int crypto_stream_aes128ctr_afternm (unsigned char *out, unsigned long long len, const unsigned char *nonce, const unsigned char *c) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_stream_aes128ctr_afternm (byte[] @out, ulong len, byte[] nonce, byte[] c);

		// extern int crypto_stream_aes128ctr_xor_afternm (unsigned char *out, const unsigned char *in, unsigned long long len, const unsigned char *nonce, const unsigned char *c) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_stream_aes128ctr_xor_afternm (byte[] @out, byte[] @in, ulong len, byte[] nonce, byte[] c);

		// extern size_t crypto_stream_chacha20_keybytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_stream_chacha20_keybytes ();

		// extern size_t crypto_stream_chacha20_noncebytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_stream_chacha20_noncebytes ();

		// extern int crypto_stream_chacha20 (unsigned char *c, unsigned long long clen, const unsigned char *n, const unsigned char *k) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_stream_chacha20 (byte[] c, ulong clen, byte[] n, byte[] k);

		// extern int crypto_stream_chacha20_xor (unsigned char *c, const unsigned char *m, unsigned long long mlen, const unsigned char *n, const unsigned char *k) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_stream_chacha20_xor (byte[] c, byte[] m, ulong mlen, byte[] n, byte[] k);

		// extern int crypto_stream_chacha20_xor_ic (unsigned char *c, const unsigned char *m, unsigned long long mlen, const unsigned char *n, uint64_t ic, const unsigned char *k) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_stream_chacha20_xor_ic (byte[] c, byte[] m, ulong mlen, byte[] n, ulong ic, byte[] k);

		// extern size_t crypto_stream_chacha20_ietf_noncebytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_stream_chacha20_ietf_noncebytes ();

		// extern int crypto_stream_chacha20_ietf (unsigned char *c, unsigned long long clen, const unsigned char *n, const unsigned char *k) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_stream_chacha20_ietf (byte[] c, ulong clen, byte[] n, byte[] k);

		// extern int crypto_stream_chacha20_ietf_xor (unsigned char *c, const unsigned char *m, unsigned long long mlen, const unsigned char *n, const unsigned char *k) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_stream_chacha20_ietf_xor (byte[] c, byte[] m, ulong mlen, byte[] n, byte[] k);

		// extern int crypto_stream_chacha20_ietf_xor_ic (unsigned char *c, const unsigned char *m, unsigned long long mlen, const unsigned char *n, uint32_t ic, const unsigned char *k) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_stream_chacha20_ietf_xor_ic (byte[] c, byte[] m, ulong mlen, byte[] n, uint ic, byte[] k);

		// extern int _crypto_stream_chacha20_pick_best_implementation ();
		[DllImport ("__Internal")]
	
		public  static extern int _crypto_stream_chacha20_pick_best_implementation ();

		// extern size_t crypto_stream_salsa20_keybytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_stream_salsa20_keybytes ();

		// extern size_t crypto_stream_salsa20_noncebytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_stream_salsa20_noncebytes ();

		// extern int crypto_stream_salsa20 (unsigned char *c, unsigned long long clen, const unsigned char *n, const unsigned char *k) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_stream_salsa20 (byte[] c, ulong clen, byte[] n, byte[] k);

		// extern int crypto_stream_salsa20_xor (unsigned char *c, const unsigned char *m, unsigned long long mlen, const unsigned char *n, const unsigned char *k) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_stream_salsa20_xor (byte[] c, byte[] m, ulong mlen, byte[] n, byte[] k);

		// extern int crypto_stream_salsa20_xor_ic (unsigned char *c, const unsigned char *m, unsigned long long mlen, const unsigned char *n, uint64_t ic, const unsigned char *k) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_stream_salsa20_xor_ic (byte[] c, byte[] m, ulong mlen, byte[] n, ulong ic, byte[] k);

		// extern size_t crypto_stream_salsa2012_keybytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_stream_salsa2012_keybytes ();

		// extern size_t crypto_stream_salsa2012_noncebytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_stream_salsa2012_noncebytes ();

		// extern int crypto_stream_salsa2012 (unsigned char *c, unsigned long long clen, const unsigned char *n, const unsigned char *k) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_stream_salsa2012 (byte[] c, ulong clen, byte[] n, byte[] k);

		// extern int crypto_stream_salsa2012_xor (unsigned char *c, const unsigned char *m, unsigned long long mlen, const unsigned char *n, const unsigned char *k) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_stream_salsa2012_xor (byte[] c, byte[] m, ulong mlen, byte[] n, byte[] k);

		// extern size_t crypto_stream_salsa208_keybytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_stream_salsa208_keybytes ();

		// extern size_t crypto_stream_salsa208_noncebytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_stream_salsa208_noncebytes ();

		// extern int crypto_stream_salsa208 (unsigned char *c, unsigned long long clen, const unsigned char *n, const unsigned char *k) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_stream_salsa208 (byte[] c, ulong clen, byte[] n, byte[] k);

		// extern int crypto_stream_salsa208_xor (unsigned char *c, const unsigned char *m, unsigned long long mlen, const unsigned char *n, const unsigned char *k) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_stream_salsa208_xor (byte[] c, byte[] m, ulong mlen, byte[] n, byte[] k);

		// extern size_t crypto_verify_16_bytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_verify_16_bytes ();

		// extern int crypto_verify_16 (const unsigned char *x, const unsigned char *y) __attribute__((visibility("default"))) __attribute__((warn_unused_result));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_verify_16 (byte[] x, byte[] y);

		// extern size_t crypto_verify_32_bytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_verify_32_bytes ();

		// extern int crypto_verify_32 (const unsigned char *x, const unsigned char *y) __attribute__((visibility("default"))) __attribute__((warn_unused_result));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_verify_32 (byte[] x, byte[] y);

		// extern size_t crypto_verify_64_bytes () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern long crypto_verify_64_bytes ();

		// extern int crypto_verify_64 (const unsigned char *x, const unsigned char *y) __attribute__((visibility("default"))) __attribute__((warn_unused_result));
		[DllImport ("__Internal")]
	
		public  static extern  int crypto_verify_64 (byte[] x, byte[] y);

		// extern void randombytes_buf (void *const buf, const size_t size) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  void randombytes_buf (byte[] buf, long size);

		// extern uint32_t randombytes_random () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern uint randombytes_random ();

		// extern uint32_t randombytes_uniform (const uint32_t upper_bound) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern uint randombytes_uniform (uint upper_bound);

		// extern void randombytes_stir () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern void randombytes_stir ();

		// extern int randombytes_close () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern int randombytes_close ();

		// extern int randombytes_set_implementation (randombytes_implementation *impl) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int randombytes_set_implementation (IntPtr impl);

		// extern const char * randombytes_implementation_name () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  sbyte[] randombytes_implementation_name ();

		// extern void randombytes (unsigned char *const buf, const unsigned long long buf_len) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  void randombytes (byte[] buf, ulong buf_len);

		// extern int sodium_runtime_has_neon () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern int sodium_runtime_has_neon ();

		// extern int sodium_runtime_has_sse2 () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern int sodium_runtime_has_sse2 ();

		// extern int sodium_runtime_has_sse3 () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern int sodium_runtime_has_sse3 ();

		// extern int sodium_runtime_has_ssse3 () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern int sodium_runtime_has_ssse3 ();

		// extern int sodium_runtime_has_sse41 () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern int sodium_runtime_has_sse41 ();

		// extern int sodium_runtime_has_avx () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern int sodium_runtime_has_avx ();

		// extern int sodium_runtime_has_avx2 () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern int sodium_runtime_has_avx2 ();

		// extern int sodium_runtime_has_pclmul () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern int sodium_runtime_has_pclmul ();

		// extern int sodium_runtime_has_aesni () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern int sodium_runtime_has_aesni ();

		// extern int _sodium_runtime_get_cpu_features ();
		[DllImport ("__Internal")]
	
		public  static extern int _sodium_runtime_get_cpu_features ();

		// extern void sodium_memzero (void *const pnt, const size_t len) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  void sodium_memzero (byte[] pnt, long len);

		// extern int sodium_memcmp (const void *const b1_, const void *const b2_, size_t len) __attribute__((visibility("default"))) __attribute__((warn_unused_result));
		[DllImport ("__Internal")]
	
		public  static extern  int sodium_memcmp (byte[] b1_, byte[] b2_, long len);

		// extern int sodium_compare (const unsigned char *b1_, const unsigned char *b2_, size_t len) __attribute__((visibility("default"))) __attribute__((warn_unused_result));
		[DllImport ("__Internal")]
	
		public  static extern  int sodium_compare (byte[] b1_, byte[] b2_, long len);

		// extern int sodium_is_zero (const unsigned char *n, const size_t nlen) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int sodium_is_zero (byte[] n, long nlen);

		// extern void sodium_increment (unsigned char *n, const size_t nlen) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  void sodium_increment (byte[] n, long nlen);

		// extern void sodium_add (unsigned char *a, const unsigned char *b, const size_t len) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  void sodium_add (byte[] a, byte[] b, long len);

		// extern char * sodium_bin2hex (char *const hex, const size_t hex_maxlen, const unsigned char *const bin, const size_t bin_len) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  sbyte[] sodium_bin2hex (sbyte[] hex, long hex_maxlen, byte[] bin, long bin_len);

		// extern int sodium_hex2bin (unsigned char *const bin, const size_t bin_maxlen, const char *const hex, const size_t hex_len, const char *const ignore, size_t *const bin_len, const char **const hex_end) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int sodium_hex2bin (byte[] bin, long bin_maxlen, sbyte[] hex, long hex_len, sbyte[] ignore, long bin_len, sbyte[] hex_end);

		// extern int sodium_mlock (void *const addr, const size_t len) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int sodium_mlock (byte[] addr, long len);

		// extern int sodium_munlock (void *const addr, const size_t len) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int sodium_munlock (byte[] addr, long len);

		// extern void * sodium_malloc (const size_t size) __attribute__((visibility("default"))) __attribute__((malloc));
		[DllImport ("__Internal")]
	
		public  static extern  byte[] sodium_malloc (long size);

		// extern void * sodium_allocarray (size_t count, size_t size) __attribute__((visibility("default"))) __attribute__((malloc));
		[DllImport ("__Internal")]
	
		public  static extern  IntPtr sodium_allocarray (long count, long size);

		// extern void sodium_free (void *ptr) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  void sodium_free (byte[] ptr);

		// extern int sodium_mprotect_noaccess (void *ptr) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int sodium_mprotect_noaccess (byte[] ptr);

		// extern int sodium_mprotect_readonly (void *ptr) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int sodium_mprotect_readonly (byte[] ptr);

		// extern int sodium_mprotect_readwrite (void *ptr) __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  int sodium_mprotect_readwrite (byte[] ptr);

		// extern int _sodium_alloc_init ();
		[DllImport ("__Internal")]
	
		public  static extern int _sodium_alloc_init ();

		// extern const char * sodium_version_string () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern  sbyte[] sodium_version_string ();

		// extern int sodium_library_version_major () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern int sodium_library_version_major ();

		// extern int sodium_library_version_minor () __attribute__((visibility("default")));
		[DllImport ("__Internal")]
	
		public  static extern int sodium_library_version_minor ();
	}

	[StructLayout (LayoutKind.Sequential)]
	public struct crypto_hash_sha512_state
	{
		public ulong[] state;

		public ulong[] count;

		public byte[] buf;
	}

	[StructLayout (LayoutKind.Sequential)]
	public struct crypto_auth_hmacsha512256_state
	{
		public crypto_hash_sha512_state ictx;

		public crypto_hash_sha512_state octx;
	}



	[StructLayout (LayoutKind.Sequential)]
	public struct crypto_hash_sha256_state
	{
		public uint[] state;

		public ulong count;

		public byte[] buf;
	}

	[StructLayout (LayoutKind.Sequential)]
	public struct crypto_auth_hmacsha256_state
	{
		public crypto_hash_sha256_state ictx;

		public crypto_hash_sha256_state octx;
	}

	[StructLayout (LayoutKind.Sequential)]
	public struct crypto_generichash_state
	{
		public ulong[] h;

		public ulong[] t;

		public ulong[] f;

		public byte[] buf;

		public long buflen;

		public byte last_node;
	}

	[StructLayout (LayoutKind.Sequential)]
	public struct crypto_onetimeauth_state
	{
		public byte[] opaque;
	}

	[StructLayout (LayoutKind.Sequential)]
	public struct randombytes_implementation
	{
		public  Func<sbyte> implementation_name;

		public  Func<uint> random;

		public  Action stir;

		public  Func<uint, uint> uniform;

		public  Action<long> buf;

		public  Func<int> close;
	}
}
