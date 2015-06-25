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

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sodium.h>

#define PROGRAMME_NAME "msr"
#define PROGRAMME_VER "0.0.1"

typedef enum error_e { SUCCESS, E_NULL, E_CHECKSUM, E_ALG_CHOICE,
                       E_ALREADY_DECRYPTED, E_ALREADY_ENCRYPTED,
                       E_ENCRYPTED, E_KDF_FAIL, E_BAD_PASS, E_BAD_PUBKEY_DAT,
                       E_VERIFY, E_WRONG_PUBKEY, E_SIGN,
                       E_SMALL_BUFF, E_INVALID_LEN, E_B64_BAD_STR,
                       E_PASS_MISMATCH, E_BAD_FILE, E_BAD_SECKEY_DAT,
                       E_INVALID_ARG} Error;

void* catch_malloc(size_t size, const char * const err);
void* catch_smalloc(size_t size, const char * const err);

const char * error_to_str(const Error e);
