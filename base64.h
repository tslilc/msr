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
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include "utils.h"

Error bin_to_base64(uint8_t const * const bin, size_t binlen,
                    uint8_t *out, size_t maxoutlen, size_t *outlen);

Error base64_to_bin(uint8_t const * const str, size_t strlen,
                    uint8_t *buf, size_t bufmaxlen, size_t *buflen);
