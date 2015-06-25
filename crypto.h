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

#pragma once
#pragma pack(1) // VERY IMPORTANT

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sodium.h>

#include "utils.h"

// --- Algorithm choices ---
#define SIG_ALG "Ed"
#define KDF_ALG "Sc"
#define CHK_ALG "B2"

// --- Widths for various fields in the structs ---
#define SIG_ALG_WIDTH 2
#define KDF_ALG_WIDTH 2
#define CHK_ALG_WIDTH 2
#define KEY_ID_WIDTH 8
#define SIG_WIDTH (size_t)crypto_sign_BYTES
#define CHK_WIDTH (size_t)crypto_generichash_BYTES
#define SEC_KEY_WIDTH (size_t)crypto_sign_SECRETKEYBYTES
#define PUB_KEY_WIDTH (size_t)crypto_sign_PUBLICKEYBYTES
#define KDF_SALT_WIDTH (size_t)crypto_pwhash_scryptsalsa208sha256_SALTBYTES
#define ENCRYPTED_KEY_WIDTH (KEY_ID_WIDTH + SEC_KEY_WIDTH + CHK_WIDTH)

#define PUB_KEY_STORE_WIDTH sizeof(struct public_key_s)
#define SEC_KEY_STORE_WIDTH sizeof(struct secret_key_s)
#define SIGNED_MSG_WIDTH (SIG_ALG_WIDTH+KEY_ID_WIDTH+SIG_WIDTH)

// --- Structs for secret key, public key and messages ---
typedef struct secret_key_s {
  uint8_t sig_alg[SIG_ALG_WIDTH];
  uint8_t kdf_alg[KDF_ALG_WIDTH];
  uint8_t chk_alg[CHK_ALG_WIDTH];
  uint8_t kdf_salt[KDF_SALT_WIDTH];
  uint64_t kdf_opslimit;
  uint64_t kdf_memlimit;
  // Below this line is essentially "keynum_sk"
  // We encrypt for security
  uint8_t key_id[KEY_ID_WIDTH];
  uint8_t secret_key[SEC_KEY_WIDTH];
  uint8_t checksum[CHK_WIDTH];
} * SecretKey;

typedef struct public_key_s {
  uint8_t sig_alg[SIG_ALG_WIDTH];
  uint8_t key_id[KEY_ID_WIDTH];
  uint8_t public_key[PUB_KEY_WIDTH];
} * PublicKey;

typedef struct signed_msg_s {
  uint8_t sig_alg[SIG_ALG_WIDTH];
  uint8_t key_id[KEY_ID_WIDTH];
  uint8_t sig[SIG_WIDTH];
  size_t msglen;
  uint8_t *msg;
} * SignedMsg;

// --- Functions ---
Error generate_key_pair(SecretKey *sk, PublicKey *pk);

Error is_valid_sigmsg(SignedMsg sm);
Error is_valid_pubkey(PublicKey pk);
Error is_correct_options(SecretKey sk);
Error is_correct_checksum(SecretKey sk);

Error alter_seckey(char encrypt, SecretKey sk,
                   const uint8_t * const passwd,
                   unsigned long long pwlen);

Error verify_message(PublicKey pk, SignedMsg sm);

Error sign_message(SecretKey sk, SignedMsg sm);
