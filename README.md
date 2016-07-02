## Simple-sha256
A minimal sha256 implementation for learning and fun. This can be used as a library,
embedded or otherwise.

This is a very minimalistic implementation of SHA256. One caveat, supported data
length is limited to 2^32 bits (as apposed to 2^64 bits). It's easy to fix but
I haven't had a need for it.

Only testing so far has been with NIST test vectors.

## Details
Here are a few documents describing the algorithm.
1. http://www.iwar.org.uk/comsec/resources/cipher/sha256-384-512.pdf
1. http://www-ma2.upc.es/~cripto/Q2-06-07/SHA256english.pdf

## Usage

```
make
./simple-sha256.exe

# or use it as a library
```