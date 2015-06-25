/*
  This file is part of msr.

  msr is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.
  
  msr is distributed in the hope that it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
  or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
  License for more details.

  You should have received a copy of the GNU General Public License
  along with Foobar. If not, see <http://www.gnu.org/licenses/>.
*/

#include "crypto.h"

void compute_checksum_seckey(SecretKey sk, uint8_t *checksum) {
  // checksum = BLAKE2( ALG || KEY_ID || SECRET_KEY )
  crypto_generichash_state st;
  crypto_generichash_init(&st, NULL, 0, CHK_WIDTH);
  crypto_generichash_update(&st, sk->sig_alg, SIG_ALG_WIDTH);
  crypto_generichash_update(&st, sk->key_id, KEY_ID_WIDTH);
  crypto_generichash_update(&st, sk->secret_key, SEC_KEY_WIDTH);
  crypto_generichash_final(&st, checksum, CHK_WIDTH);
}

Error generate_key_pair(SecretKey *sk, PublicKey *pk) {
  *sk = catch_smalloc(sizeof(struct secret_key_s),
                     "Unable to securely allocate secrety key memory.");
  *pk = catch_smalloc(sizeof(struct public_key_s),
                     "Unable to securely allocate public key memory.");
  // Initialise structures randomly, for hysterical raisons
  randombytes_buf((*sk),sizeof(struct secret_key_s));
  randombytes_buf((*pk),sizeof(struct public_key_s));
  // -- Public key init ---
  memcpy((*pk)->sig_alg, SIG_ALG, SIG_ALG_WIDTH);
  randombytes_buf((*pk)->key_id, KEY_ID_WIDTH);
  // --- Secret key init ---
  memcpy((*sk)->sig_alg, SIG_ALG, SIG_ALG_WIDTH);
  memcpy((*sk)->kdf_alg, KDF_ALG, KDF_ALG_WIDTH);
  memcpy((*sk)->chk_alg, CHK_ALG, CHK_ALG_WIDTH);
  (*sk)->kdf_memlimit = crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE;
  (*sk)->kdf_opslimit = crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE;
  memcpy((*sk)->key_id, (*pk)->key_id, KEY_ID_WIDTH);
  // Generate keypair
  crypto_sign_keypair((*pk)->public_key, (*sk)->secret_key);
  // Checksum on secret key to wrap-up generation
  compute_checksum_seckey((*sk),(*sk)->checksum);
  return SUCCESS;
}

Error is_valid_sigmsg(SignedMsg sm) {
  if (sm == NULL) return E_NULL;
  if (sodium_memcmp(sm->sig_alg, SIG_ALG, SIG_ALG_WIDTH) != 0)
    return E_ALG_CHOICE;
  return SUCCESS;
}

Error is_valid_pubkey(PublicKey pk) {
  if (pk == NULL) return E_NULL;
  // Same as before
  if (sodium_memcmp(pk->sig_alg, SIG_ALG, SIG_ALG_WIDTH) != 0)
    return E_ALG_CHOICE;
  return SUCCESS;
}

Error is_correct_options(SecretKey sk) {
  if (sk == NULL) return E_NULL;
  // For a secret key to be valid, it *must* use the same algorithms
  if ( (sodium_memcmp(sk->sig_alg, SIG_ALG, SIG_ALG_WIDTH) != 0)
       || (sodium_memcmp(sk->kdf_alg, KDF_ALG, KDF_ALG_WIDTH) != 0)
       || (sodium_memcmp(sk->chk_alg, CHK_ALG, CHK_ALG_WIDTH) != 0) )
    return E_ALG_CHOICE;
  // If so, sucess
  return SUCCESS;
}

Error is_correct_checksum(SecretKey sk) {
  Error e;
  uint8_t checksum[CHK_WIDTH];
  compute_checksum_seckey(sk,checksum);
  if (sodium_memcmp(sk->checksum, checksum, CHK_WIDTH) == 0)
    e =  SUCCESS;
  else e = E_CHECKSUM;
  sodium_memzero(checksum,CHK_WIDTH);
  return e;
}

void xor_keynum_sk(SecretKey sk, const uint8_t outp[ENCRYPTED_KEY_WIDTH]) {
  // Xor correctly aligned to blocks
  size_t k;
  for (k=0;k<KEY_ID_WIDTH;k++) sk->key_id[k] ^= outp[k];
  for (k=0;k<SEC_KEY_WIDTH;k++) sk->secret_key[k] ^= outp[k+KEY_ID_WIDTH];
  for (k=0;k<CHK_WIDTH;k++) sk->checksum[k] ^= outp[k+KEY_ID_WIDTH+SEC_KEY_WIDTH];
}

Error alter_seckey(char encrypt, SecretKey sk, const uint8_t * const passwd,
                   unsigned long long pwlen) {
  Error e;
  // Cannot decrypt invalid secret keys, or reencrypt encrypted and so on
  if ( (e = is_correct_options(sk)) != SUCCESS ) return e;
  e = is_correct_checksum(sk);
  if ( (encrypt != 0) && (e != SUCCESS) ) return E_ALREADY_ENCRYPTED;
  if ( (encrypt == 0) && (e == SUCCESS) ) return E_ALREADY_DECRYPTED;
  // Actual processing
  uint8_t *outp = catch_smalloc(ENCRYPTED_KEY_WIDTH,
                               "Unable to allocate secure internal storage for KDF.");
  sodium_memzero(outp,ENCRYPTED_KEY_WIDTH);
  // Run the KDF
  if (crypto_pwhash_scryptsalsa208sha256(outp, ENCRYPTED_KEY_WIDTH,
                                         (char*)passwd, pwlen,
                                         sk->kdf_salt,sk->kdf_opslimit,
                                         sk->kdf_memlimit) != 0 )
    return E_KDF_FAIL;
  // XOR into blocks appropriately
  xor_keynum_sk(sk,outp);
  if (!encrypt) {
    // If decrypting, check for correct password
    if ( is_correct_checksum(sk) == SUCCESS ) return SUCCESS;
    else {
      // Password was bad, undo what we did
      xor_keynum_sk(sk,outp);
      e = E_BAD_PASS;
    }
    // Otherwise done
  } else e = SUCCESS;
  // Wipe kdf output
  sodium_free(outp);
  return e;
}

Error verify_message(PublicKey pk, SignedMsg sm) {
  Error e;
  // Check validity of public key and signed message algo choice
  if ( (e = is_valid_pubkey(pk)) != SUCCESS ) return e;
  if ( (e = is_valid_sigmsg(sm)) != SUCCESS ) return e;
  // Ensure that the key id is correct
  if ( sodium_memcmp(pk->key_id,sm->key_id,KEY_ID_WIDTH) != 0)
    return E_WRONG_PUBKEY;
  // Verify if
  if ( crypto_sign_verify_detached(sm->sig,
                                   sm->msg, sm->msglen,
                                   pk->public_key) != 0 )
    return E_VERIFY;
  return SUCCESS;
}

Error sign_message(SecretKey sk, SignedMsg sm) {
  Error e;
  // Ensure that SK uses correct algo choices and has ok checksum
  if ( (e = is_correct_options(sk)) != SUCCESS ) return e;
  if ( is_correct_checksum(sk) != SUCCESS ) return e;
  // Sign it
  if ( crypto_sign_detached(sm->sig, NULL, sm->msg, sm->msglen, sk->secret_key) != 0 )
    return E_SIGN;
  return SUCCESS;
}
