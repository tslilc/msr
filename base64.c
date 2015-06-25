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

#include "base64.h"

static const char b64padchar = (uint8_t)'=';
static const char b64chars[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/*
;; Precompute inverse lookup with skippable stuff and padding
(insert
 (apply #'concat
        (let ((str "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
              (skip " \t\n\r") (skipnum 65)
              (pad ?=) (padnum 64) (invalidnum 66))
          (cl-loop for k from 0 to 255
                   for j = (let* ((s (char-to-string k))
                                  (v (s-index-of s str))
                                  (w (s-index-of s skip))
                                  (x (char-equal k pad)))
                             (if v (format "%2dU " v)
                                (if w "SKIP"
                                  (if x "PADD" "INVD"))))
                   collect (concat ", " j)))))
*/
#define INVD (uint8_t)66
#define SKIP (uint8_t)65
#define PADD (uint8_t)64
static const uint8_t b64inverse[256] = {
  INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, SKIP, SKIP, INVD, INVD, SKIP, INVD, INVD,
  INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD,
  SKIP, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, 62  , INVD, INVD, INVD, 63 ,
  52  , 53  , 54  , 55  , 56  , 57  , 58  , 59  , 60  , 61  , INVD, INVD, INVD, PADD, INVD, INVD,
  INVD,  0  ,  1  ,  2  ,  3  ,  4  ,  5  ,  6  ,  7  ,  8  ,  9  , 10  , 11  , 12  , 13  , 14  ,
  15  , 16  , 17  , 18  , 19  , 20  , 21  , 22  , 23  , 24  , 25  , INVD, INVD, INVD, INVD, INVD,
  INVD, 26  , 27  , 28  , 29  , 30  , 31  , 32  , 33  , 34  , 35  , 36  , 37  , 38  , 39  , 40  ,
  41  , 42  , 43  , 44  , 45  , 46  , 47  , 48  , 49  , 50  , 51  , INVD, INVD, INVD, INVD, INVD,
  INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD,
  INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD,
  INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD,
  INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD,
  INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD,
  INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD,
  INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD,
  INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD, INVD
};

Error bin_to_base64(uint8_t const * const bin, size_t binlen,
                    uint8_t *out, size_t maxoutsize, size_t *outlen) {
  if ((*outlen = 4*(binlen/3)+4) > maxoutsize) return E_SMALL_BUFF;
  size_t k, l;
  uint32_t n = 0;
  // Look at floor(binlen/3) groups of three bytes
  for (k=0, l=0; k<binlen/3; k++) {
    n = ((uint32_t)bin[3*k])<<16;
    n |= ((uint32_t)bin[3*k+1])<<8;
    n |= ((uint32_t)bin[3*k+2]);
    
    out[l++] = b64chars[(n>>18)&63];
    out[l++] = b64chars[(n>>12)&63];
    out[l++] = b64chars[(n>>6)&63];
    out[l++] = b64chars[n&63];
  }
  // What is the actual index in bin?
  k *= 3;
  // Now deal with remainders
  if (k<binlen) {
    n = ((uint32_t)bin[k])<<16;
    out[l+3] = b64padchar;
    if (k+1<binlen) {
      n |= ((uint32_t)bin[k+1])<<8;
      out[l+2] = b64chars[(n>>6)&63];
    } else out[l+2] = b64padchar;
    out[l] = b64chars[(n>>18)&63];
    out[l+1] = b64chars[(n>>12)&63];
    l+=4;
  };
  out[l]=0;
  return SUCCESS;
}

// Note: will read first valid b64 encoded string and stop caring
Error base64_to_bin(uint8_t const * const str, size_t strlen,
                    uint8_t *buf, size_t bufmaxsize, size_t *buflen) {
  if (str == NULL) return E_NULL;
  *buflen = 0;
  size_t k = 0;
  uint8_t c = 0;
  uint32_t t = 0;
  while(k<strlen) {
    uint8_t l = b64inverse[str[k++]];
    switch (l) {
        // Skip = Skip, a universal truth
      case SKIP: break;
        // We don't take these transgressions lightly
      case INVD: return E_B64_BAD_STR;
        // Annoying validity checks here
      case PADD: {
        if (c<2) return E_B64_BAD_STR;
        // If we have only consumed 2/4 chars, then there must be 2 x pad || .* || eof
        if (c==2 && ( str[k]!=b64padchar))
          return E_B64_BAD_STR;
        k = strlen;
        // If we have 3/4 chars, pad || .* || eof
        break;
      }
        // A valid b64 char (not incl. padding)
      default: {
        // Store these six bits
        t = (t<<6) | l;
        // If we've done this four times, then output three bytes
        if (++c > 3) {
          if ((*buflen)>=bufmaxsize) return E_SMALL_BUFF;
          buf[(*buflen)++] = (uint8_t)((t>>16)&255);
          if ((*buflen)>=bufmaxsize) return E_SMALL_BUFF;
          buf[(*buflen)++] = (uint8_t)((t>>8)&255);
          if ((*buflen)>=bufmaxsize) return E_SMALL_BUFF;
          buf[(*buflen)++] = (uint8_t)(t&255);
          c = t = 0;
        }
      }
    }
  }
  // This should not happen
  if (c==1) return E_B64_BAD_STR;
  // Finish up, c=2 => 1 byte, c=3 => 2 bytes
  else if (c==2) {
    if ((*buflen)>=bufmaxsize) return E_SMALL_BUFF;
    buf[(*buflen)++] = (uint8_t)((t>>4)&255);
  }
  else if (c==3) {
    if ((*buflen)>=bufmaxsize) return E_SMALL_BUFF;
    buf[(*buflen)++] = (uint8_t)((t>>10)&255);
    if ((*buflen)>=bufmaxsize) return E_SMALL_BUFF;
    buf[(*buflen)++] = (uint8_t)((t>>2)&255);
  }
  // done
  return SUCCESS;
}
