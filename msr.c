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

#include <stdlib.h>
#include <argp.h>
#include "io.h"

enum opt_key {O_PUBKEY_STR, O_SECKEY_STR, O_PUBKEY_COMMENT, O_SECKEY_COMMENT,
              O_PUBKEY_FLE, O_SECKEY_FLE, O_SIG_FLE, O_SIGN_INLINE, O_PASS_FLE};

enum action {A_NULL, A_SIGN_D, A_SIGN_T, A_VERIFY_D, A_VERIFY_T, A_GEN};

typedef struct option_state_s {
  char *pkstr, *pkfn, *pkc;
  char *skstr, *skfn, *skc, *skpf;
  char *utc, *tc;
  char *fn, *sfn;
  char quiet;
  enum action action;
} * OptionState;

static struct argp_option options[] = {
  // Actions
  {"generate", 'G', "FILE", OPTION_ARG_OPTIONAL, "Generate a new key pair, storing in `FILE.{pub,key}' (FILE defaults to msr)", 1},
  {"sign-detached", 'S', "FILE", 0, "Sign FILE by generating a separate signature", 1},
  {"sign-text", 'T', "FILE", 0, "Sign FILE by appending a signature", 1},
  {"verify-detached", 'V', "FILE", 0, "Verify the detached signature on FILE", 1},
  {"verify-text", 'X', "FILE", 0, "Verify the inline text signature in FILE", 1},
  // Odd-one-out
  {"signature-file", 'f', "FILE", 0, "Use FILE as the signature file for detached signing and verification purposes", 2},
  // Keys
  {"pubkey-file", 'p', "FILE", 0, "Use the public key in FILE", 3},
  {"pubkey-string", O_PUBKEY_STR, "STR", 0, "Use the public key encoded in STR", 3},
  {"seckey-file", 's', "FILE", 0, "Use the secret key in FILE", 3},
  {"seckey-string", O_SECKEY_STR, "STR", 0, "Use the secret key encoded in STR", 3},
  {"password-file", O_PASS_FLE, "FILE", 0, "Load secret key passphrase from FILE", 4},
  // Comments
  {"comment-untrusted", 'u', "STR", 0, "Use STR for the default untrusted comment when making a detached signature", 5},
  {"comment-trusted", 't', "STR", 0, "Use STR for the trusted comment when making a detached signature", 5},
  {"comment-pubkey", O_PUBKEY_COMMENT, "STR", 0, "Use STR for the default untrusted comment in the generated public key file", 5},
  {"comment-seckey", O_SECKEY_COMMENT, "STR", 0, "Use STR for the default untrusted comment in the generated secret key file", 5},
  // Miscellaneous
  {"quiet", 'q', 0, 0, "Produce no output",6},
  {0,0,0,0,0,0}
};


char *action_to_string(enum action a) {
  switch (a) {
    case A_GEN: return "generation of key pair";
    case A_SIGN_D: return "signing detached";
    case A_SIGN_T: return "signing inline text";
    case A_VERIFY_D: return "verification of detached signature";
    case A_VERIFY_T: return "verification of inline text signature";
    default: return "null action";
  }
}

// --- Some macros to make argument checking sane ---
#define FAIL(str) (argp_error(state, (str)))
#define ACT_CHECK { if (s->action!=A_NULL) FAIL("Cannot execute conflicting actions."); }
#define BADARG(arg) (argp_error(state, "%s stipulated for %s",arg,action_to_string(s->action)))
#define ARGCHECK(a,b,c,d,e,f,g,h,i,j) { \
    if(a && s->pkc) BADARG("public key comment");                \
    if(b && s->pkfn) BADARG("public key file");                  \
    if(c && s->pkstr) BADARG("public key string");               \
    if(d && s->skc) BADARG("secret key comment");                \
    if(e && s->skfn) BADARG("secret key file");                  \
    if(f && s->skstr) BADARG("secret key string");               \
    if(g && s->tc) BADARG("trusted comment");                    \
    if(h && s->utc) BADARG("untrusted comment");                 \
    if(i && s->skpf) BADARG("secret key password file");         \
    if(j && s->sfn) BADARG("signature file"); }

error_t parse_opt(int key, char *arg, struct argp_state *state) {
  OptionState s = state->input;
  switch (key) {
    case ARGP_KEY_FINI: {
      switch (s->action) {
        case A_NULL: argp_state_help(state,state->out_stream,ARGP_HELP_SEE);
        case A_GEN: { ARGCHECK(0,1,1,0,1,1,1,1,1,1); break; };
        case A_VERIFY_D:
        case A_SIGN_D: { ARGCHECK(1,0,0,1,0,0,0,0,0,0); break; }
        case A_VERIFY_T:
        case A_SIGN_T: { ARGCHECK(1,0,0,1,0,0,1,1,0,1); break; }
        }
      break;
    }
    case ARGP_KEY_INIT: {
      s->action = A_NULL;
      s->pkc = s->pkfn = s->pkstr = NULL;
      s->skc = s->skfn = s->skstr = NULL;
      s->tc = s->utc = NULL;
      s->fn = s->sfn = NULL;
      s->skpf = NULL;
      s->quiet = 0;
      break;
    }
    case 'G': {ACT_CHECK; s->action = A_GEN; s->fn = arg; break; }
    case 'S': {ACT_CHECK; s->action = A_SIGN_D; s->fn = arg; break; }
    case 'T': {ACT_CHECK; s->action = A_SIGN_T; s->fn = arg; break; }
    case 'V': {ACT_CHECK; s->action = A_VERIFY_D; s->fn = arg; break; }
    case 'X': {ACT_CHECK; s->action = A_VERIFY_T; s->fn = arg; break; }
    case 'p': {
      if (s->pkfn) FAIL("Already set public key filename.");
      if (s->pkstr) FAIL("Already set public key string.");
      s->pkfn = arg;
      break;
    }
    case O_PUBKEY_STR: {
      if (s->pkfn) FAIL("Already set public key filename.");
      if (s->pkstr) FAIL("Already set public key string.");
      s->pkstr = arg;
      break;
    }
    case 's': {
      if (s->skfn) FAIL("Already set private key filename.");
      if (s->skstr) FAIL("Already set private key string.");
      s->skfn = arg;
      break;
    }
    case O_SECKEY_STR: {
      if (s->skfn) FAIL("Already set private key filename.");
      if (s->skstr) FAIL("Already set private key string.");
      s->skstr = arg;
      break;
    }
    case O_PASS_FLE: {
      if (s->skpf) FAIL("Already set secret key password file.");
      s->skpf = arg;
    }
    case 't': {
      if (s->tc) FAIL("Already set trusted comment string.");
      s->tc = arg;
      break;
    }
    case 'u': {
      if (s->utc) FAIL("Already set untrusted comment string.");
      s->utc = arg;
      break;
    }
    case O_PUBKEY_COMMENT: {
      if (s->pkc) FAIL("Already set public key comment.");
      s->pkc = arg;
      break;
    }
    case O_SECKEY_COMMENT: {
      if (s->skc) FAIL("Already set secret key comment.");
      s->skc = arg;
      break;
    }
    case 'f': {
      if (s->sfn) FAIL("Already set signature file name.");
      s->sfn = arg;
      break;
    }
    case 'q': {s->quiet = 1; break; }
    default: return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

const char *argp_program_version = "msr 0.0.2";
const char *argp_program_bug_address = "http://github.com/tslilc/msr or <tslil@posteo.de>";
static char doc[] = "msr -- small public key verification tool.\v\
Copyright (C) 2015 Tslil Clingman\nThis is free software and is \
licensed under the terms of the GNU GPL version three or later. This \
program comes with ABSOLUTELY NO WARRANTY; consult the LICENSE file \
for details.";

static struct argp argp = {options, parse_opt, NULL, doc, NULL, NULL, NULL};

int main(int argc, char ** argv) {
  
  struct option_state_s s;
  argp_parse(&argp,argc,argv, ARGP_NO_ARGS, 0, &s);

  if (s.quiet) verbose = 0;
  
  if (sodium_init() == -1) {
    puts("Unable to initialise libsodium");
    return 1;
  }
  Error e;
  SecretKey sk;
  PublicKey pk;
  switch (s.action) {
    case A_GEN: {
      e = generate_to_file(s.fn,s.skpf,s.pkc,s.skc);
      if (e != SUCCESS) exit(1);
      break;
    }
    case A_SIGN_D: {
      if (s.skstr) e = read_seckey_string(s.skstr,&sk);
      else e = read_seckey_file(s.skstr,&sk);
      if (e != SUCCESS) exit(1);
      e = sign_detached(s.fn,s.sfn,s.utc,s.tc,s.skpf,sk);
      if ( e != SUCCESS ) exit(1);
      break;
    }
    case A_SIGN_T: {
      if (s.skstr) e = read_seckey_string(s.skstr,&sk);
      else e = read_seckey_file(s.skstr,&sk);
      if (e != SUCCESS) exit(1);
      e = sign_attached(s.fn,s.skpf,sk);
      if ( e != SUCCESS ) exit(1);
      break;
    }
    case A_VERIFY_D: {
      if (s.pkstr) e = read_pubkey_string(s.pkstr,&pk);
      else e = read_pubkey_file(s.pkfn,&pk);
      if (e != SUCCESS) exit(1);
      e = verify_detached(s.fn,s.sfn,pk);
      if ( e != SUCCESS ) exit(1);
      break;
    }
    case A_VERIFY_T: {
      if (s.pkstr) e = read_pubkey_string(s.pkstr,&pk);
      else e = read_pubkey_file(s.pkfn,&pk);
      if (e != SUCCESS) exit(1);
      e = verify_attached(s.fn,pk);
      if ( e != SUCCESS ) exit(1);
      break;
    }
      // Should not be here
    case A_NULL: exit(1);
  }
  
  return 0;
}

