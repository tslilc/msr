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

#include "utils.h"

void* catch_malloc(size_t size, const char * const err) {
  errno = 0;
  void *m = malloc(size);
  if (m == NULL || errno != 0) {
    fprintf(stderr,"Error: %s\n",err);
    exit(1);
  }
  return m;
}


void* catch_smalloc(size_t size, const char * const err) {
  errno = 0;
  void* m = sodium_malloc(size);
  if (m == NULL || errno != 0) {
    fprintf(stderr,"Error: %s\n",err);
    exit(1);
  }
  return m;
}

const char * error_to_str(const Error e) {
  switch (e) {
    case SUCCESS: return NULL;
    case E_NULL: return "Null argument.";
    case E_CHECKSUM: return "Secret key checksum failed.";
    case E_ALG_CHOICE: return "Unsupported algorithm choice.";
    case E_ALREADY_ENCRYPTED: return "Secret key already encrypted.";
    case E_ALREADY_DECRYPTED: return "Secret key already decrypted.";
    case E_KDF_FAIL: return "Internal KDF error.";
    case E_BAD_PASS: return "Incorrect password for secret key.";
    case E_VERIFY: return "Verification failed";
    case E_WRONG_PUBKEY: return "Public key ID mismatch.";
    case E_SIGN: return "Internal signing error.";
    case E_SMALL_BUFF: return "Buffer too small.";
    case E_INVALID_LEN: return "Invalid buffer length.";
    case E_B64_BAD_STR: return "Invalid characters found in string.";
    case E_PASS_MISMATCH: return "Passwords do not match.";
    case E_BAD_FILE: return "Unable to open file.";
    case E_BAD_PUBKEY_DAT: return "Invalid public key data.";
    case E_BAD_SECKEY_DAT: return "Invalid secret key data.";
    case E_ENCRYPTED: return "Secret key is encrypted and so unusable.";
    case E_INVALID_ARG: return "Invalid argument.";
    default: return "Unreachable.";
  }
}
