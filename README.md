# msr
*Small public key verification tool*

Inspired by OpenBSD's [signify](http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/signify/signify.c) and [minisign](https://jedisct1.github.io/minisign/) I decided to spend some time learning [libsodium](https://github.com/jedisct1/libsodium) and re-implement minisign for myself.

Currently, this programme is a superset of minisign (and so partially signify) but in the future signatures and or keys may become incompatible -- it seemed in bad taste to do that immediately.

## Usage
Compile it and run `msr --help` and you'll find

      -G, --generate[=FILE]      Generate a new key pair, storing in
                                 `FILE.{pub,key}' (FILE defaults to msr)
      -S, --sign-detached=FILE   Sign FILE by generating a separate signature
      -T, --sign-text=FILE       Sign FILE by appending a signature
      -V, --verify-detached=FILE Verify the detached signature on FILE
      -X, --verify-text=FILE     Verify the inline text signature in FILE
      -f, --signature-file=FILE  Use FILE as the signature file for detached
                                 signing and verification purposes
      -p, --pubkey-file=FILE     Use the public key in FILE
          --pubkey-string=STR    Use the public key encoded in STR
      -s, --seckey-file=FILE     Use the secret key in FILE
          --seckey-string=STR    Use the secret key encoded in STR
          --password-file=FILE   Load secret key passphrase from FILE
          --comment-pubkey=STR   Use STR for the default untrusted comment in the
                                 generated public key file
          --comment-seckey=STR   Use STR for the default untrusted comment in the
                                 generated secret key file
      -t, --comment-trusted=STR  Use STR for the trusted comment when making a
                                 detached signature
      -u, --comment-untrusted=STR   Use STR for the default untrusted comment when
                                 making a detached signature
      -q, --quiet                Produce no output
      -?, --help                 Give this help list
          --usage                Give a short usage message
          --version              Print program version

## Specifications

At the behest of libsodium, we use [ed25519](http://ed25519.cr.yp.to/) for all things signing, `scryptsalsa208sha256` for the KDF, and [BLAKE2](https://blake2.net/) for computing hashes otherwise. Thus, for what follows we have

`sig_alg = Ed`
`chk_alg = B2`
`kdf_alg = Sc`

Finally, to minimise key collisions and provide a convenient necessary match criterion, each key is assigned a `key_id` which is eight random bytes.

### Secret Key Files
    untrusted comment: <1024 bytes, arbitrarily changeable>
    base64( <sig_alg> || <kdf_alg> || <chk_alg> || <kdf_salt> || <kdf_opsl> || <kdf_meml> || <encrypted key> )

where
* `kdf_salt = 32 random bytes`
* `kdf_opsl` and `kdf_meml` are the operations and memory limits for the KDF (defined in libsodium as `crypto_pwhash_scryptsalsa208sha256_{OPS,MEM}LIMIT_SENSITIVE`)
* `checksum = BLAKE2( <sig_alg> || <key id> || <secret key)`
* `encrypted key = <kdf output> ^ (<key id> || <secret key> || <checksum>)`

### Public Key Files
    untrusted comment: <1024 bytes, arbitrarily changeable>
    base64( <signature algorithm> || <key id> || <public key> )

### Signatures
Detached signatures have the format

    untrusted comment: <1024 bytes, arbitrarily changeable>
    base64( <signature algorithm> || <key id> || <signature> )
    trusted comment: <1024 bytes, fixed at signing>
    base64( <global signature> )
    
where 
* `signature = ed25519( <file data> )`
* `global signature = ed25519( <signature> || <trusted comment> )`

whereas inline signatures are simply of the form

    <file contents>
    --- BEGIN SIGNATURE ---
    base64( <signature algorithm> || <key id> || <signature> )

### Dependencies
`libsodium`, `argp` and a compiler/stdlib that will understand `-D_GNU_SOURCE` (for non-modifying `basename`)

I doubt it's *that* portable, but it should probably work on most unix-y systems.

### License
GPL3+

### Author's notes
The idea that you can squeeze public key verification into just a few bytes (sub ~100 for everything concerned) and have it still be "128 bit strong" is really amazing. Moreover, I felt that this would be a good learning exercise -- I haven't really done much library interfacing in C (this project entailed using both libsodium and argp), and I haven't ever concluded a mid-sized C project before. I have no doubt the code is crufty and poorly designed, but I had fun and it was an interesting paradigm shift from my usual language of choice.

All input welcome and desired!
