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

#include "io.h"

Error read_password_stdin(uint8_t * passwd, char repeat, size_t *len) {
  Error e = SUCCESS;
  struct termios old,noecho;

  if (len) *len = 0;
  
  tcgetattr(STDIN_FILENO,&old);
  noecho = old;
  noecho.c_lflag &= ~ECHO;
  tcsetattr(STDIN_FILENO,TCSANOW,&noecho);

  printf("Password: ");
  
  // Read in the passwd, if its blank then warn
  if ( fgets((char*)passwd,MAX_PASS_LEN,stdin) == NULL ) {
    sodium_free(passwd);
    return E_NULL;
  }
  // If we were interactive then we don't want the terminal return
  size_t k = strnlen((char*)passwd,MAX_PASS_LEN);
  if (k==1) puts("(blank)");
  else {
    putchar('\n');
    if (passwd[k-1]=='\n') passwd[--k]=0;
  }
  // Are we asking the user to repeat the password?
  if (repeat) {
    // Reset terminal settings in the event that we die when allocating
    tcsetattr(STDIN_FILENO,TCSANOW,&old);
    uint8_t *passwd2 = catch_smalloc(MAX_PASS_LEN,
                                  "Could not allocate secure memory for password storage");
    // Prompt and set no echo
    printf("Repeat password: ");
    tcsetattr(STDIN_FILENO,TCSANOW,&noecho);
    // Read in, if this one is blank they must both be for a match
    if ( fgets((char*)passwd2,MAX_PASS_LEN,stdin) == NULL) {
      tcsetattr(STDIN_FILENO,TCSANOW,&old);    
      putchar('\n');
      sodium_free(passwd2);
      sodium_free(passwd);
      return E_NULL;
    }
    // Set back terminal
    tcsetattr(STDIN_FILENO,TCSANOW,&old);
    size_t k2 = strnlen((char*)passwd2,MAX_PASS_LEN);
    // Trim this one too
    if (k2 == 1) puts("(blank)");
    else {
      putchar('\n');
      if (passwd2[k2-1]=='\n') passwd2[--k2]=0;
    }
    // They must be of the same length (note: both taken with possible terminal return)
    if (k2 != k) {
      sodium_memzero(passwd,MAX_PASS_LEN);
      sodium_free(passwd2);
      return E_PASS_MISMATCH;
    };
    // Do they match?
    if (sodium_memcmp(passwd,passwd2,k) != 0) {
      sodium_memzero(passwd,MAX_PASS_LEN);
      sodium_free(passwd2);
      return E_PASS_MISMATCH;
    }
    sodium_free(passwd2);
  }
  if (len) *len = k;
  return e;
}

Error memory_map_file(const char * const fn,
                      uint8_t **dataptr,
                      size_t *size) {
  if (fn == NULL || *fn == 0 || dataptr == NULL || size == NULL )
    return E_NULL;
  *size = 0;
  *dataptr = 0;
  // --- Map ---
  int fd = open(fn, O_RDONLY);
  if (fd <= 0) return E_BAD_FILE;
  struct stat stt;
  if ( fstat(fd, &stt) != 0 || stt.st_size == 0) {
    close(fd);
    return E_BAD_FILE;
  }
  *dataptr = mmap(0, stt.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  // Check that all is kosher
  if (*dataptr == MAP_FAILED) {
    close(fd);
    return E_BAD_FILE;
  }
  *size = stt.st_size;
  return SUCCESS;
}

Error read_password_file(const char * const fn, uint8_t **passptr, size_t *len) {
  if (fn == NULL) return E_NULL;
  size_t flen; uint8_t *data;
  *passptr = NULL;
  if (len) *len = 0;
  Error e = memory_map_file(fn,&data,&flen);
  if (e!=SUCCESS) {
    if (verbose) printf("Error reading password from file: %s\n",error_to_str(e));
    return e;
  }
  size_t to_read = (flen>=MAX_PASS_LEN)?MAX_PASS_LEN:flen;
  *passptr = catch_smalloc(to_read,"Unable to allocate secure password storage.");
  memcpy(*passptr,data,to_read);
  munmap(data,flen);
  if (len) *len = to_read;
  return SUCCESS;
}

Error prompt_decryption_password(uint8_t ** passptr, size_t *len) {
  uint8_t *passwd = catch_smalloc(MAX_PASS_LEN,
                               "Unable to allocate secure memory for password.");
  *len = 0;
  Error e = read_password_stdin(passwd,1,len);
  if (e != SUCCESS) {
    sodium_free(passwd);
    passwd = NULL;
    if (verbose) printf("Error reading decryption password: %s\n",error_to_str(e));
  }
  *passptr = passwd;
  return e;
}

Error prompt_encryption_password(uint8_t ** passptr, size_t *len) {
  uint8_t *passwd = catch_smalloc(MAX_PASS_LEN,
                               "Unable to allocate secure memory for password.");
  *len = 0;
  Error e = read_password_stdin(passwd,1,len);
  if ( e != SUCCESS ) {
    sodium_free(passwd);
    passwd = NULL;
    if (verbose) printf("Error reading encryption password: %s\n",error_to_str(e));
  }
  *passptr = passwd;
  return e;
}

Error read_pubkey_string(const char * const str, PublicKey *pk) {
  // This would be bad
  if (str == NULL) return E_NULL;
  // Init stuff
  *pk = NULL;
  size_t size = 0;
  // We use smalloc even though we don't *have to*
  PublicKey p = catch_smalloc(PUB_KEY_STORE_WIDTH,
                      "Could not allocate secure public key memory.");
  // Try to decode the alleged public key
  Error e = base64_to_bin((uint8_t*)str,strnlen(str,4*(PUB_KEY_STORE_WIDTH/3+1)),
                          (uint8_t*)(void*)p,PUB_KEY_STORE_WIDTH,&size);
  // Fatal = die
  if ( e != SUCCESS ) {
    sodium_free(p);
    if (verbose) printf("Error decoding public key: %s\n",error_to_str(e));
    return e;
  }
  // Maybe it was valid base 64, but was it the correct size?
  if (size!=PUB_KEY_STORE_WIDTH) {
    sodium_free(p);
    if (verbose) printf("Error decoding public key: %s\n",error_to_str(E_BAD_PUBKEY_DAT));
    return E_BAD_PUBKEY_DAT;
  }
  // Check if we have a valid public key
  e = is_valid_pubkey(p);
  if ( e != SUCCESS ) {
    sodium_free(p);
    if (verbose) printf("Error decoding public key: %s\n",error_to_str(e));
    return e;
  };
  // Cool
  *pk = p;
  return e;
}

Error read_seckey_string(const char * const str, SecretKey *sk) {
  // Same as public one, really
  if (str == NULL) return E_NULL;
  // Init stuff
  *sk = NULL;
  size_t size = 0;
  SecretKey s = catch_smalloc(SEC_KEY_STORE_WIDTH,
                              "Could not allocate secure secure secret key memory.");
  // Attempt to decode
  Error e = base64_to_bin((uint8_t*)str,strnlen(str,4*(SEC_KEY_STORE_WIDTH/3+1)),
                          ((uint8_t*)(void*)s),SEC_KEY_STORE_WIDTH,&size);
  // Fatal = die
  if ( e != SUCCESS ) {
    sodium_free(s);
    if (verbose) printf("Error decoding secret key: %s\n",error_to_str(e));
    return e;
  }
  // Maybe it was valid base 64, but was it the correct size?
  if (size!=SEC_KEY_STORE_WIDTH) {
    sodium_free(s);
    if (verbose) printf("Error decoding secret key: %s\n",error_to_str(E_BAD_SECKEY_DAT));
    return E_BAD_SECKEY_DAT;
  }
  // Check if we have a 'valid' secret key
  e = is_correct_options(s);
  if ( e != SUCCESS ) {
    sodium_free(s);
    if (verbose) printf("Error decoding secret key: %s\n",error_to_str(e));
    return e;
  }
  // Cool
  *sk = s;
  return e;
}

Error read_file_internal(const char * const fn,
                         size_t maxclen, size_t maxdlen,
                         char **comment, size_t *commentlen, 
                         char **data, size_t *datalen) {
  // Initial wipes, to be sure
  *comment = NULL;
  *data = NULL;
  *commentlen = 0;
  *datalen = 0;
  // Open the file, do some checks
  FILE *fl = fopen(fn,"r");
  if (fl == NULL) return E_BAD_FILE;
  char *buf = catch_smalloc(maxclen,
                            "Unable to allocate secure internal storage to read from file.");
  // Read the comment line
  if (fgets(buf,maxclen,fl) == NULL) {
    sodium_free(buf);
    fclose(fl);
    return E_BAD_FILE;
  }
  *comment = buf;
  *commentlen = strnlen(*comment,maxclen);
  // Try and read the second line
  buf = catch_smalloc(maxdlen,
                      "Unable to allocate secure internal storage to read from file.");
  if (fgets(buf,maxdlen,fl) == NULL) {
    sodium_free(buf);
    sodium_free(*comment);
    *comment = NULL;
    *commentlen = 0;
    fclose(fl);
    return E_BAD_FILE;
  }
  fclose(fl);
  
  *data = buf;
  *datalen = strnlen(*data,maxdlen);

  // Trime terminal newlines if there are any
  if (*datalen!=0 && (*data)[*datalen-1]=='\n') {
    (*data)[*datalen-1]=0; (*datalen)--;
  }
  if (*commentlen!=0 && (*comment)[*commentlen-1]=='\n') {
    (*comment)[*commentlen-1]=0; (*commentlen)--;
  }
  return SUCCESS;
}

Error display_key_id(const uint8_t * const id) {
  if (id==NULL) return E_NULL;
  size_t k;
  for (k=1;k<=KEY_ID_WIDTH;k++) {
    printf("%02X",id[KEY_ID_WIDTH-k]);
    if (k<KEY_ID_WIDTH) putchar(':');
  }
  return SUCCESS;
}

Error read_pubkey_file(char const * const fn, PublicKey *pk) {
  char *comment, *pkstr;
  size_t csize, pksize;
  Error e = read_file_internal(fn,sizeof(DEFAULT_COMMENT_PREFIX)+MAX_COMMENT_LEN-1,
                               4*(PUB_KEY_STORE_WIDTH/3+1),
                               &comment, &csize, &pkstr, &pksize);
  if ( e != SUCCESS ) {
    sodium_free(comment);
    sodium_free(pkstr);
    if (verbose) printf("Error reading public key file: %s\n",error_to_str(e));
    return e;
  }
  e = read_pubkey_string(pkstr,pk);
  if ( e != SUCCESS ) {
    sodium_free(comment);
    sodium_free(pkstr);
    if (verbose) printf("Error reading public key file: %s\n",error_to_str(e));
    return e;
  }
  if (verbose) {
    printf("Public key ");
    display_key_id((*pk)->key_id);
    printf(" loaded successfully.\n'%s'\n\n",comment);
  }
  sodium_free(comment);
  return SUCCESS;
}

Error read_seckey_file(char const * const fn, SecretKey *sk) {
  char *comment, *skstr;
  size_t csize, pksize;
  Error e = read_file_internal(fn,sizeof(DEFAULT_COMMENT_PREFIX)+MAX_COMMENT_LEN-1,
                               4*(SEC_KEY_STORE_WIDTH/3+1),
                               &comment, &csize, &skstr, &pksize);
  if ( e != SUCCESS ) {
    sodium_free(comment);
    sodium_free(skstr);
    if (verbose) printf("Error reading secret key file: %s\n",error_to_str(e));
    return e;
  }
  e = read_seckey_string(skstr,sk);
  if ( e != SUCCESS ) {
    sodium_free(comment);
    sodium_free(skstr);
    if (verbose) printf("Error reading secret key file: %s\n",error_to_str(e));
    return e;
  }
  // Check if it's not encrypted, then we can display the id
  if (verbose) {
    if (is_correct_checksum(*sk) == SUCCESS) {
      printf("Secret key ");
      display_key_id((*sk)->key_id);
      puts(" loaded successfully.");
    } else  puts("Encrypted secret key loaded successfully.");
    printf("'%s'\n\n",comment);
  }
  sodium_free(comment);
  return SUCCESS;  
}

Error pubkey_to_string(PublicKey pk, char **pksptr) {
  if (pksptr == NULL) return E_NULL;
  Error e = is_valid_pubkey(pk);
  if ( e != SUCCESS ) return e;
  *pksptr = catch_smalloc(4*(PUB_KEY_STORE_WIDTH/3)+4+1,
                      "Unable to allocate secure internal storage for public key string.");
  size_t l = 0;
  e = bin_to_base64((uint8_t*)(void*)pk,PUB_KEY_STORE_WIDTH,
                    (uint8_t*)*pksptr,4*(PUB_KEY_STORE_WIDTH/3)+4,&l);
  if ( e != SUCCESS ) {
    sodium_free(*pksptr);
    *pksptr = NULL;
  }
  return e;
}

// TODO: Warn when writing unencrypted secret key?
Error seckey_to_string(SecretKey sk, char **sksptr) {
  if (sksptr == NULL) return E_NULL;
  Error e = is_correct_options(sk);
  if ( e != SUCCESS ) return e;
  *sksptr = catch_smalloc(4*(SEC_KEY_STORE_WIDTH/3)+4+1,
                      "Unable to allocate secure internal storage for secret key string.");
  size_t l = 0;
  e = bin_to_base64((uint8_t*)(void*)sk,SEC_KEY_STORE_WIDTH,
                (uint8_t*)*sksptr,4*(SEC_KEY_STORE_WIDTH/3)+4,&l);
  if ( e != SUCCESS ) {
    sodium_free(*sksptr);
    *sksptr = NULL;
  }
  return e;
}

Error unlock_seckey(const char * const passwdfn, SecretKey sk) {
  uint8_t *passwd; size_t passlen;
  Error e;
  if (passwdfn == NULL) e = prompt_decryption_password(&passwd,&passlen);
  else e = read_password_file(passwdfn, &passwd, &passlen);
  if ( e != SUCCESS ) {
    if (verbose) printf("Error reading passphrase: %s\n",error_to_str(e));
    return e;
  }
  if (verbose) puts("Attempting to decrypt key...");
  e = alter_seckey(0,sk,passwd,passlen);
  if ( e != SUCCESS ) {
    if (verbose) printf("Error decrypting secret key: %s\n",error_to_str(e));
    return e;
  }
  if (verbose) {
    printf("Successfully decrypted secret key ");
    display_key_id(sk->key_id);
    putchar('\n');
  }
  return e;
}

Error write_to_file_internal(const char * const fn,
                             const char * const keystr,
                             const char * const comment) {
  if (fn == NULL || keystr == NULL || comment == NULL)
    return E_NULL;
  FILE *f = fopen(fn,"w");
  if ( f == NULL ) return E_BAD_FILE;
  // Error on writing no bytes? Why not.
  Error e = SUCCESS;
  if ( fprintf(f,"%s\n%s\n",comment,keystr) <= 0 )
    e = E_BAD_FILE;
  fclose(f);
  return e;
}

Error display_key_id_s(const uint8_t * const id, char * s) {
  if (id==NULL) return E_NULL;
  size_t k;
  for (k=1;k<=KEY_ID_WIDTH;k++) {
    sprintf(s,"%02X",id[KEY_ID_WIDTH-k]);
    s+=2;
    if (k<KEY_ID_WIDTH) sprintf(s++,":");
  }
  return SUCCESS;
}

Error write_pubkey_to_file(const char * const pkfn, PublicKey pk,
                           const char * const comment) {
  // Pretty standard stuff, check for errors
  if (pkfn == NULL || pk == NULL) return E_NULL;
  char *pkstr = NULL;
  // Generate the b64 string
  Error e = pubkey_to_string(pk,&pkstr);
  if ( e != SUCCESS ) return e;
  // If the comment is blank, make the default one
  char *comm = catch_malloc(MAX_COMMENT_LEN+sizeof(DEFAULT_COMMENT_PREFIX),
                               "Unable to allocate secure internal memory.");
  if (comment == NULL) {
    /*
      We want 'untrusted comment: <default_pubkey_prefix> <key id>' where key
      id is hex for eight bytes with colons between. Note -1 for 0
      delim double counting.
    */
    memcpy(comm,DEFAULT_COMMENT_PREFIX,sizeof(DEFAULT_COMMENT_PREFIX));
    int l = sizeof(DEFAULT_COMMENT_PREFIX)-1;
    memcpy(comm+l, DEFAULT_PUBKEY_PREFIX, sizeof(DEFAULT_PUBKEY_PREFIX));
    l += sizeof(DEFAULT_PUBKEY_PREFIX)-1;
    // No errors are checked here as it's impossible for pk to be
    // invalid and have passed pubkey_to_string
    display_key_id_s(pk->key_id,comm+l);
    // Otherwise we use the given comment
  } else snprintf(comm,MAX_COMMENT_LEN+sizeof(DEFAULT_COMMENT_PREFIX),
                  "%s%s",DEFAULT_COMMENT_PREFIX,comment);
  e = write_to_file_internal(pkfn,pkstr,comm);
  free(comm);
  sodium_free(pkstr);
  return e;
}

Error write_seckey_to_file(const char * const skfn, SecretKey sk,
                           const char * const comment) {
  // This is copy pasta of the public one, mutatis mutandis
  if (skfn == NULL || sk == NULL) return E_NULL;
  char *skstr = NULL;
  Error e = seckey_to_string(sk,&skstr);
  if ( e != SUCCESS ) return e;
  char *comm = catch_malloc(MAX_COMMENT_LEN+sizeof(DEFAULT_COMMENT_PREFIX),
                            "Unable to allocate internal storage for comment.");
  snprintf(comm,MAX_COMMENT_LEN+sizeof(DEFAULT_COMMENT_PREFIX),
           "%s%s",DEFAULT_COMMENT_PREFIX,
           (comment==NULL)?DEFAULT_SECKEY_PREFIX:comment);
  e = write_to_file_internal(skfn,skstr,comm);
  free(comm);
  sodium_free(skstr);
  return e;
}

Error generate_to_file(const char * fn,
                       const char * const passwdfn,
                       const char * const pkcomment,
                       const char * const skcomment) {
  if (pkcomment != NULL &&
      strnlen(pkcomment,MAX_COMMENT_LEN) > MAX_COMMENT_LEN) {
    if (verbose) puts("Error generating new key pair: Desired public key comment is too long.");
    return E_INVALID_LEN;
  }
  if (skcomment != NULL &&
      strnlen(skcomment,MAX_COMMENT_LEN) > MAX_COMMENT_LEN) {
    if (verbose) puts("Error generating new key pair: Desired secret key comment is too long.");
    return E_INVALID_LEN;
  }
  PublicKey pk = NULL;
  SecretKey sk = NULL;
  uint8_t *passwd = NULL;
  size_t passlen = 0;
  Error e;
  // --- Generate key pair ---
  if (verbose) printf("Generating a new key pair... ");
  e = generate_key_pair(&sk,&pk);
  if ( e != SUCCESS ) {
    if (verbose) printf("error!\nError generating key pair: %s\n",error_to_str(e));
    return e;
  }
  if (verbose) puts("done.\n");
  // --- Retrieve password ---
  if (passwdfn == NULL) {
    if (verbose) puts("Please enter a password to encrypt the secret key.");
    e = prompt_encryption_password(&passwd,&passlen);
  } else e = read_password_file(passwdfn,&passwd,&passlen);
  if ( e != SUCCESS ) {
    sodium_free(sk); sodium_free(pk);
    return e;
  }
  // --- Encrypt the key ---
  if (verbose) printf("\nDeriving a key from the password for encryption... ");
  fflush(stdout);
  e = alter_seckey(1,sk,passwd,passlen);
  if ( e != SUCCESS ) {
    sodium_free(sk); sodium_free(pk);
    if (verbose) printf("error!\nError encrypting secret key: %s\n",error_to_str(e));
    return e;
  }
  // --- Write files ---
  char *skfn, *pkfn;
  char default_fn[] = "msr";
  if (fn==NULL) fn = default_fn;
  size_t fnlen = strnlen(fn,MAX_FILENAME_LEN);
  skfn = catch_malloc(fnlen+5, "Unable to allocate filename storage.");
  pkfn = catch_malloc(fnlen+5, "Unable to allocate filename storage.");
  snprintf(skfn,fnlen+5,"%s.key",fn);
  snprintf(pkfn,fnlen+5,"%s.pub",fn);
  
  if (verbose) printf("done.\n\nCreating key files:\n\tWriting secret key into '%s'... ",skfn);
  fflush(stdout);
  e = write_seckey_to_file(skfn,sk,skcomment);
  if ( e != SUCCESS ) {
    sodium_free(sk); sodium_free(pk);
    if (verbose) printf("error!\nError writing secret key: %s\n",error_to_str(e));
    return e;    
  }
  if (verbose) printf("done.\n\tWriting public key into '%s'... ",pkfn);
  e = write_pubkey_to_file(pkfn,pk,pkcomment);
  if ( e != SUCCESS ) {
    sodium_free(sk); sodium_free(pk);
    if (verbose) printf("error!\nError writing public key: %s\n",error_to_str(e));
    return e;    
  }
  if (verbose) {
    printf("done.\n\nThe new key pair has ID ");
    display_key_id(pk->key_id);
    putchar('\n');
  }
  return SUCCESS;
}

Error load_and_sign_file_contents(const char * const fn, SecretKey sk, SignedMsg *smptr) {
  // Usual checks
  if (fn == NULL || sk == NULL || smptr == NULL) return E_NULL;
  /*
    Note: we effectively do the following checks twice because of the
    way sign_message was written. I'd rather we hash twice than crypto
    reveal an unsafe API, though. Design input welcome.
  */
  Error e;
  if ((e=is_correct_options(sk))!=SUCCESS) return e;
  if (is_correct_checksum(sk)!=SUCCESS) return E_ENCRYPTED;
  // Map the file
  size_t size; uint8_t *data;
  e = memory_map_file(fn, &data, &size);
  if ( e != SUCCESS ) return e;
  // Initialise the signed message structure
  *smptr = catch_smalloc(sizeof(struct signed_msg_s),
                         "Unable to allocate secure internal storage for message signing.");
  memcpy((*smptr)->sig_alg,sk->sig_alg,SIG_ALG_WIDTH);
  memcpy((*smptr)->key_id,sk->key_id,KEY_ID_WIDTH);
  (*smptr)->msglen = size;
  (*smptr)->msg = data;
  // Sign the message
  if ( (e = sign_message(sk,*smptr)) != SUCCESS) {
    sodium_free(*smptr); *smptr = NULL;
  }
  munmap(data, size);
  return e;
}

Error trusted_comment_sign(const uint8_t * const sig, const char * const tc,
                           SecretKey sk, char **sptr) {
  // Let's skip some of the normal validation here beacuaz I am laz
  if (sig == NULL || tc == NULL || sk == NULL || sptr == NULL)
    return E_NULL;
  *sptr = NULL;
  // This stuff will probably happen multiple times for a single key,
  // but hey, data integrity checks!
  Error e = is_correct_options(sk);
  if ( e != SUCCESS ) return e;
  if ( is_correct_checksum(sk) != SUCCESS ) return E_ENCRYPTED;
  // Do lots of accounting, wow this is taxing
  const size_t tclen = strnlen(tc,MAX_COMMENT_LEN);
  const size_t len = SIG_WIDTH+tclen;
  uint8_t* cat = catch_malloc(len+1,
                              "Could not allocate internal memory for second signature.");
  // Blah blah, cat = <sig> || <trusted comment>
  memcpy(cat,sig,SIG_WIDTH);
  memcpy(cat+SIG_WIDTH,tc,tclen);
  // Now sign it (maybe I should have designed the crypto interface better)
  // (in my defense, I didn't think I'd be doing trusted comments)
  uint8_t ssig[SIG_WIDTH];
  if ( crypto_sign_detached(ssig, NULL, cat, len, sk->secret_key) != 0 ) {
    free(cat);
    return E_SIGN;
  } else free(cat);
  // Now encode the signature
  char *b64 = catch_malloc(4*(SIG_WIDTH/3)+4+1 ,
                              "Could not allocate internal memory for second signature.");
  size_t out;
  e = bin_to_base64(ssig, SIG_WIDTH,
                    (uint8_t*)b64, 4*(SIG_WIDTH/3)+4,
                    &out);
  if ( e == SUCCESS ) *sptr = b64;
  else free(b64);
  return e;
}

Error signed_message_to_signature(SignedMsg sm, char **sigptr) {
  *sigptr = NULL;
  char *b64sig = catch_malloc(4*(SIGNED_MSG_WIDTH/3)+4+1 ,
                              "Could not allocate internal memory for signature.");
  size_t out;
  Error e = bin_to_base64((uint8_t*)(void*)sm, SIGNED_MSG_WIDTH,
                          (uint8_t*)b64sig, 4*(SIGNED_MSG_WIDTH/3)+4,
                          &out);
  if ( e == SUCCESS ) *sigptr = b64sig;
  else free(b64sig);
  return e;
}

#define SA_ERR "Error attaching signature: %s\n"
Error sign_attached(const char * const fn,
                    const char * const passwdfn, SecretKey sk) {
  // Standard checks
  if (fn == NULL) {
    if (verbose) printf(SA_ERR,"No file specified.");
    return E_NULL;
  }
  if (strnlen(fn,MAX_FILENAME_LEN)==MAX_FILENAME_LEN) {
    if (verbose) printf(SA_ERR,"Filename is too long.");
    return E_BAD_FILE;
  }
  Error e;
  if ( (e = is_correct_options(sk)) != SUCCESS ) {
    if (verbose) printf(SA_ERR,error_to_str(e));
    return e;
  }
  // Decrypt key if necessary
  e = is_correct_checksum(sk);
  if ( e == E_CHECKSUM ) {
    if ( (e = unlock_seckey(passwdfn,sk)) != SUCCESS ) {
      if (verbose) printf(SA_ERR,error_to_str(e));
      return e;
    }
  } else if (e != SUCCESS) {
    if (verbose) printf(SA_ERR,error_to_str(e));
    return e;
  }
  // Attempt to sign
  SignedMsg sm;
  if ( (e = load_and_sign_file_contents(fn,sk,&sm)) != SUCCESS ) {
    if (verbose) printf(SA_ERR,error_to_str(e));
    return e;
  }
  // Write signature to file
  FILE *fle = fopen(fn, "a+");
  if (fle == NULL) {
    if (verbose) printf(SA_ERR,"Could not open the file to append signature.");
    sodium_free(sm);
    return E_BAD_FILE;
  }
  char *b64sig;
  e = signed_message_to_signature(sm,&b64sig);
  if ( e != SUCCESS) { if (verbose) printf(SA_ERR,error_to_str(e)); }
  else {
    fprintf(fle,"\n%s\n%s\n",DEFAULT_SIG_DELIM,b64sig);
    free(b64sig);
  }

  // Clean up, one way or another
  sodium_free(sm);
  fclose(fle);

  if (verbose) printf("\nSuccessfully appended signature to file %s\n",fn);
  
  return e;
}

#define SD_ERR "Error creating detached signature: %s\n"
Error sign_detached(const char * const fn, const char * const sfn,
                    const char * const comment, const char * const trusted_comment,
                    const char * const passwdfn, SecretKey sk) {
  // Standard checks
  if (fn == NULL) {
    if (verbose) printf(SD_ERR,"No file to sign specified.");
    return E_NULL;
  }
  if (strnlen(fn,MAX_FILENAME_LEN)==MAX_FILENAME_LEN) {
    if (verbose) printf(SD_ERR,"Filename is too long.");
    return E_BAD_FILE;
  }
  if (comment != NULL && strnlen(comment,MAX_COMMENT_LEN)==MAX_COMMENT_LEN) {
    if (verbose) printf(SD_ERR,"Comment is too long.");
    return E_INVALID_ARG;
  }
  // Handle the signature file (if not specificied be intelligent)
  char *sfn_internal;
  if (sfn == NULL) {
    sfn_internal = catch_malloc(strnlen(fn,MAX_FILENAME_LEN)+5,
                                "Unable to allocate filename storage.");
    sprintf(sfn_internal,"%s.sig",fn);
  } else {
    size_t l = strnlen(sfn,MAX_FILENAME_LEN);
    if (l == MAX_FILENAME_LEN) {
      if (verbose) printf(SD_ERR,"Signature filename is too long.");
    }
    sfn_internal = catch_malloc(l+1, "Unable to allocate signature filename storage.");
    memcpy(sfn_internal,sfn,l);
  }
  // Handle the comment, just do your best
  char *comment_internal = catch_malloc(MAX_COMMENT_LEN+1,
                                       "Unable to allocate internal comment storage.");
  snprintf(comment_internal, MAX_COMMENT_LEN, "%s", (comment==NULL)?DEFAULT_COMMENT_TEXT:comment);
  // Handle the trusted comment (if not specified be intelligent)
  char *tcomment_internal = catch_malloc(MAX_COMMENT_LEN+1,
                                       "Unable to allocate internal trusted comment storage.");
  if (trusted_comment == NULL) {
    /*
      We want 'trusted comment: timestamp: <...>, file: <basename>'
      Using -D_GNU_SOURCE we get the nice basename function and we
      truncate the basename if it's too long. Such is life.
    */
    snprintf(tcomment_internal,
             MAX_COMMENT_LEN,
             DEFAULT_TCOMMENT_FORMAT,
             time(NULL), basename(fn));
  } else snprintf(tcomment_internal,MAX_COMMENT_LEN,"%s",trusted_comment);

  Error e;
  if ( (e = is_correct_options(sk)) != SUCCESS ) {
    if (verbose) printf(SD_ERR,error_to_str(e));
    free(sfn_internal);
    free(comment_internal);
    free(tcomment_internal);
    return e;
  }
  // Decrypt key if necessary
  e = is_correct_checksum(sk);
  if ( e == E_CHECKSUM ) {
    if ( (e = unlock_seckey(passwdfn,sk)) != SUCCESS ) {
      if (verbose) printf(SD_ERR,error_to_str(e));
      free(sfn_internal);
      free(comment_internal);
      free(tcomment_internal);
      return e;
    }
  } else if (e != SUCCESS) {
    if (verbose) printf(SD_ERR,error_to_str(e));
    free(sfn_internal);
    free(comment_internal);
    free(tcomment_internal);
    return e;
  }
  // Attempt to sign the content of the file for the first signature
  SignedMsg sm;
  if ( (e = load_and_sign_file_contents(fn,sk,&sm)) != SUCCESS ) {
    if (verbose) printf(SD_ERR,error_to_str(e));
    free(sfn_internal);
    free(comment_internal);
    free(tcomment_internal);
    return e;
  }
  // Write signature to file
  FILE *fle = fopen(sfn_internal, "w+");
  if (fle == NULL) {
    if (verbose) printf(SA_ERR,"Could not open the signature file for writing.");
    sodium_free(sm);
    free(comment_internal);
    free(tcomment_internal);
    free(sfn_internal);
    return E_BAD_FILE;
  }
  char *b64sig;
  e = signed_message_to_signature(sm,&b64sig);
  if ( e != SUCCESS) { if (verbose) printf(SA_ERR,error_to_str(e)); }
  else {
    // We now have what we need for the first signature, so write it
    fprintf(fle,"%s%s\n%s\n",DEFAULT_COMMENT_PREFIX,comment_internal,b64sig);
    // Now we must compute the second signature
    char *secondsig;
    e = trusted_comment_sign(sm->sig,tcomment_internal,sk,&secondsig);
    if ( e != SUCCESS ) { if (verbose) printf(SA_ERR,error_to_str(e)); }
    else {
      fprintf(fle,"%s%s\n%s\n",DEFAULT_TCOMMENT_PREFIX,tcomment_internal,secondsig);
      free(secondsig);
      if (verbose) printf("\nSuccessfully wrote signature to file %s\n",sfn_internal);
    }
    free(b64sig);
  }
  
  // Clean up, one way or another
  sodium_free(sm);
  free(comment_internal);
  free(tcomment_internal);
  free(sfn_internal);
  fclose(fle);
  
  return e;
}

Error generic_verify_detached(uint8_t * msg, size_t msg_len,
                              uint8_t * b64sig, size_t b64sig_len,
                              uint8_t *savesig, PublicKey pk) {
  // --- Forgo most verification ---
  if (msg == NULL || msg_len == 0 || b64sig == NULL || b64sig_len == 0 || pk == NULL)
    return E_NULL;
  // --- Create signedmessage and init it ---
  SignedMsg sm = catch_malloc(sizeof(struct signed_msg_s),
                              "Unable to allocate signed message structure for verification.");
  sm->msg = msg;
  sm->msglen = msg_len;
  // --- Attempt decode ---
  size_t rawlen;
  Error e = base64_to_bin(b64sig, b64sig_len,
                          (uint8_t*)(void*)sm, SIGNED_MSG_WIDTH, &rawlen);
  if ( e != SUCCESS ) {
    free(sm);
    return e;
  }
  // --- Verify ---
  e = verify_message(pk,sm);
  // Ugly hack, but the format spec is weird and this saves effort
  if (savesig != NULL) memcpy(savesig,sm->sig,SIG_WIDTH);
  free(sm);
  return e;
}

#define VA_ERR "Error verifying inline signature: %s\n"
Error verify_attached(const char * const fn, PublicKey pk) {
  // --- Standard checks ---
  if (fn == NULL) {
    if (verbose) printf(VA_ERR,"No file specified.");
    return E_NULL;
  }
  if (strnlen(fn,MAX_FILENAME_LEN)==MAX_FILENAME_LEN) {
    if (verbose) printf(VA_ERR,"Filename is too long.");
    return E_BAD_FILE;
  }
  Error e;
  if ( (e = is_valid_pubkey(pk)) != SUCCESS ) {
    if (verbose) printf(VA_ERR,error_to_str(e));
    return e;
  }
  // --- Memory map file ---
  size_t flen; uint8_t *data;
  e = memory_map_file(fn,&data,&flen);
  if (e != SUCCESS ) {
    if (verbose) printf(VA_ERR,error_to_str(e));
    return e;
  }
  // --- Split file into content + sig ---
  size_t k = 1;
  while (k<flen) {
    if (data[k-1] == '\n' &&
        k+sizeof(DEFAULT_SIG_DELIM) < flen+1 &&
        (sodium_memcmp(data+k,DEFAULT_SIG_DELIM,sizeof(DEFAULT_SIG_DELIM)-1) == 0))
      break;
    else k++;
  }
  if (k==flen) {
    munmap(data,flen);
    if (verbose) printf(VA_ERR,"Unable to find signature delimeter.");
    return E_BAD_FILE;
  }
  // --- Verfify ---
  e = generic_verify_detached(data, k-1,
                              data+k+sizeof(DEFAULT_SIG_DELIM),
                              flen-(k+sizeof(DEFAULT_SIG_DELIM)),
                              NULL,pk);
  if ( e != SUCCESS ) {
    if (verbose) printf(VA_ERR,error_to_str(e));
  } else {
    if (verbose) {
      printf("Successfully verified %s with key ",fn);
      display_key_id(pk->key_id);
      putchar('\n');
    }
  }
  munmap(data,flen);
  return e;
}

void trim_str(char *buf, size_t *buflen, size_t maxbuflen) {
  if (buf == NULL || *buf == 0 || maxbuflen == 0) return;
  size_t k = strnlen(buf,maxbuflen); 
  if (buf[k-1]=='\n') {
    buf[k-1]=0;
    k--;
  }
  if (buflen != NULL) *buflen = k;
}

#define VD_ERR "Error verifying detached signature: %s\n"
Error verify_detached(const char * const fn, const char * const sfn,
                      PublicKey pk) {
  // --- Standard checks ---
  if (fn == NULL || *fn == 0) {
    if (verbose) printf(VD_ERR,"No file specified.");
    return E_NULL;
  }
  if (strnlen(fn,MAX_FILENAME_LEN)==MAX_FILENAME_LEN) {
    if (verbose) printf(VD_ERR,"Filename is too long.");
    return E_BAD_FILE;
  }
  Error e;
  if ( (e = is_valid_pubkey(pk)) != SUCCESS ) {
    if (verbose) printf(VD_ERR,error_to_str(e));
    return e;
  }
  char *sfn_internal; 
  if (sfn == NULL || *fn == 0) {
    sfn_internal = catch_malloc(strnlen(fn,MAX_FILENAME_LEN)+5,
                                "Unable to allocate memory for signature filename.");
    snprintf(sfn_internal,MAX_FILENAME_LEN+4,"%s.sig",fn);
  } else {
    size_t l = strnlen(sfn,MAX_FILENAME_LEN);
    if (l == MAX_FILENAME_LEN) {
      if (verbose) printf(VD_ERR,"Signature filename too long.");
      return E_INVALID_LEN;
    }
    sfn_internal = catch_malloc(l, "Unable to allocate memory for signature filename.");
    memcpy(sfn_internal,sfn,l);
  }
  // --- Memory map data ---
  size_t datalen; uint8_t *data;
  e = memory_map_file(fn,&data,&datalen);
  if (e != SUCCESS ) {
    if (verbose) printf(VD_ERR,error_to_str(e));
    free(sfn_internal);
    return e;
  }
  // --- Parse signature file ---
  FILE *fle = fopen(sfn_internal, "r");
  if (fle == NULL) {
    if (verbose) printf("Error verifying detached signature: Unable to open the signature file %s\n",sfn);
    munmap(data,datalen);
    free(sfn_internal);
    return E_BAD_FILE;
  }
  #define ERR_STR_MALLOC "Unable to allocate internal memory for verification."
  char *tc = catch_malloc(MAX_COMMENT_LEN+2, ERR_STR_MALLOC), *tcc;
  char *sig1 = catch_malloc(4*(SIGNED_MSG_WIDTH/3+1)+2, ERR_STR_MALLOC);
  char *sig2 = catch_malloc(4*(SIG_WIDTH/3+1)+2, ERR_STR_MALLOC);
  if (fgets(tc,MAX_COMMENT_LEN+sizeof(DEFAULT_COMMENT_PREFIX),fle) == NULL
      || sodium_memcmp(tc,DEFAULT_COMMENT_PREFIX,sizeof(DEFAULT_COMMENT_PREFIX)-1) != 0) {
    if (verbose) printf(VD_ERR,"Error reading signature file, untrusted comment.");
    free(sig2); free(sig1); free(tc); free(sfn_internal);
    munmap(data,datalen);
    fclose(fle);
    return E_BAD_FILE;
  }
  if (fgets(sig1,4*(SIGNED_MSG_WIDTH/3+1)+2,fle) == NULL) {
    if (verbose) printf(VD_ERR,"Error reading signature file, data signature.");
    free(sig2); free(sig1); free(tc); free(sfn_internal);
    munmap(data,datalen);
    fclose(fle);
    return E_BAD_FILE;
  }
  trim_str(sig1,NULL,4*(SIGNED_MSG_WIDTH/3+1)+1);
  if (fgets(tc,MAX_COMMENT_LEN+sizeof(DEFAULT_TCOMMENT_PREFIX),fle) == NULL
      || sodium_memcmp(tc,DEFAULT_TCOMMENT_PREFIX,sizeof(DEFAULT_TCOMMENT_PREFIX)-1) != 0) {
    if (verbose) printf(VD_ERR,"Error reading signature file, trusted comment.");
    free(sig2); free(sig1); free(tc); free(sfn_internal);
    munmap(data,datalen);
    fclose(fle);
    return E_BAD_FILE;
  }
  size_t tclen;
  tcc = tc + sizeof(DEFAULT_TCOMMENT_PREFIX) - 1;
  trim_str(tcc,&tclen,MAX_COMMENT_LEN);
  if (fgets(sig2,4*(SIG_WIDTH/3+1)+1,fle) == NULL) {
    if (verbose) printf(VD_ERR,"Error reading signature file, global signature.");
    free(sig2); free(sig1); free(tc); free(sfn_internal);
    munmap(data,datalen);
    fclose(fle);
    return E_BAD_FILE;
  }
  fclose(fle);
  // --- Verify standard signature ---
  uint8_t *sig_and_tcc = catch_malloc(SIG_WIDTH+tclen,
                                     "Unable to allocate internal storage for verification.");
  e = generic_verify_detached(data, datalen,
                              (uint8_t*)sig1, 4*(SIGNED_MSG_WIDTH/3+1),
                              sig_and_tcc, pk);
  munmap(data,datalen);
  if ( e != SUCCESS ) {
    if (verbose) printf(VA_ERR,error_to_str(e));
    free(sig1); free(tc); free(sig2); free(sfn_internal);
    free(sig_and_tcc);
    return e;
  }
  // -- Verify global signature ---
  memcpy(sig_and_tcc + SIG_WIDTH,tcc,tclen);
  uint8_t rawsig2[SIG_WIDTH]; size_t t;
  e = base64_to_bin((uint8_t*)sig2, 4*(SIG_WIDTH/3+1),
                    rawsig2, SIGNED_MSG_WIDTH, &t);
  if ( e != SUCCESS ) {
    if (verbose) printf(VA_ERR,error_to_str(e));
    free(sig1); free(tc); free(sig2); free(sfn_internal);
    free(sig_and_tcc);
    return e;
  }
  if (crypto_sign_verify_detached(rawsig2,sig_and_tcc,SIG_WIDTH+tclen,pk->public_key) != 0)
    e = E_VERIFY;
  if ( e != SUCCESS ) {
    if (verbose) printf(VA_ERR,error_to_str(e));
    free(sig1); free(tc); free(sig2); free(sfn_internal);
    free(sig_and_tcc);
    return e;
  }
  // Output
  if (verbose) {
    printf("Successfully verified %s against %s with key ",fn,sfn_internal);
    display_key_id(pk->key_id);
    putchar('\n');
    printf("%s\n",tc);
  }
  // Cleanup
  free(sig1); free(tc); free(sig2); free(sfn_internal);
  free(sig_and_tcc);
  return e;
}
