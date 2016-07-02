/*
*   SHA-256 implementation.
*
*   Copyright (c) 2016, Norman Patrick
*
*   Permission to use, copy, modify, and distribute this software for any
*   purpose with or without fee is hereby granted, provided that the above
*   copyright notice and this permission notice appear in all copies.
*
*   THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
*   WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
*   MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
*   ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
*   WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
*   ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
*   OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/
#include <stdio.h>
#include <string.h>
#include "simple-sha256.h"

#ifdef _DEBUG_SHA2
#define BREADCRUMB(_a, _b, _c, _d, _e, _f, _g, _h, _i) \
    do {                                                \
        printf("%3d(%2d): ", __LINE__, (_i));           \
        printf("%08x ", (_a));                          \
        printf("%08x ", (_b));                          \
        printf("%08x ", (_c));                          \
        printf("%08x ", (_d));                          \
        printf("%08x ", (_e));                          \
        printf("%08x ", (_f));                          \
        printf("%08x ", (_g));                          \
        printf("%08x ", (_h));                          \
        printf("\n");                                   \
    } while(0)
#else
#define BREADCRUMB(_a, _b, _c, _d, _e, _f, _g, _h, _i) \
    do {                                                \
    } while(0)
#endif

#define PADBASE_INDEX (448 / 8)
#define RTR(a,b) (((a) >> (b)) | ((a) << (32-(b))))

#define Ch(_x,_y,_z) (((_x) & (_y)) ^ (~(_x) & (_z)))
#define Maj(_x,_y,_z) (((_x) & (_y)) ^ ((_x) & (_z)) ^ ((_y) & (_z)))
#define E0(_x) (RTR(_x,2) ^ RTR(_x,13) ^ RTR(_x,22))
#define E1(_x) (RTR(_x,6) ^ RTR(_x,11) ^ RTR(_x,25))
#define SIG0(_x) (RTR(_x,7) ^ RTR(_x,18) ^ ((_x) >> 3))
#define SIG1(_x) (RTR(_x,17) ^ RTR(_x,19) ^ ((_x) >> 10))
#define INV32(_x)                               \
    (((_x) & 0x000000ff) << 24) |               \
    (((_x) & 0x0000ff00) << 8) |                \
    (((_x) & 0x00ff0000) >> 8) |                \
    (((_x) & 0xff000000) >> 24)

u32 Kj[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
    0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
    0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
    0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
    0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
    0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

u32 H0[8] = {
    0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
    0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
};

static int sha2_op(u32* Hi, u8* message_64_bytes) {
    int i;
    u32 Wi[64];
    u32 a,b,c,d,e,f,g,h,T1,T2;

    if(!Hi || !message_64_bytes) {
        return ERROR_MSHA2_BAD_PARAMS;
    }
    for(i=0; i < 16; i++) {
        Wi[i] = INV32(*((u32*)&message_64_bytes[i*4]));
    }
    for(; i < 64; i++) {
        Wi[i] = SIG1(Wi[i-2]) + Wi[i-7] + SIG0(Wi[i-15]) + Wi[i-16];
    }
    #if 0
    for (i = 0; i < 64; ++i) {
        //printf("%08x - %08x\n", message_64_bytes[i], Wi[i]);
        printf("%08x - %08x\n", i, Wi[i]);
    }
    #endif
    a = Hi[0];
    b = Hi[1];
    c = Hi[2];
    d = Hi[3];
    e = Hi[4];
    f = Hi[5];
    g = Hi[6];
    h = Hi[7];
    for(i=0; i < 64; i++) {
        BREADCRUMB(a,b,c,d,e,f,g,h,i);
        T1 = h + E1(e) + Ch(e,f,g) + Kj[i] + Wi[i];
        T2 = E0(a) + Maj(a,b,c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }
    BREADCRUMB(a,b,c,d,e,f,g,h,i);
    Hi[0] += a;
    Hi[1] += b;
    Hi[2] += c;
    Hi[3] += d;
    Hi[4] += e;
    Hi[5] += f;
    Hi[6] += g;
    Hi[7] += h;
    BREADCRUMB(Hi[0],Hi[1],Hi[2],Hi[3],Hi[4],Hi[5],Hi[6],Hi[7], i+1);
    return ERROR_MSHA2_SUCCESS;
}

// Note: maxlen 32 bits, using PADBASE_INDEX+4 for everything
int sha2_exec(u32* Hi, u8* data, int len) {
    int i;
    u8 tempdata[64];
    int remainder = len;

    // assume all buffere are right size(!)
    if(!Hi || !data || (len <= 0)) {
        return ERROR_MSHA2_BAD_PARAMS;
    }
    // work away on the whole bloacks first
    while(remainder >= 64) {
        sha2_op(Hi, &data[len - remainder]);
        remainder -= 64;
    }
    memcpy(tempdata, &data[len - remainder], remainder);
    tempdata[remainder] = 0x80;
    if(remainder < PADBASE_INDEX) {
        // the remaining bytes 0..55 can be fitted onto one last block
        for(i=remainder+1; i < PADBASE_INDEX+4; i++) {
            tempdata[i] = 0x00;
        }
    } else {
        // remainder is more than 448 bits, hence we would need two blocks
        for(i=remainder+1; i < 64; i++) {
            tempdata[i] = 0x00;
        }
        sha2_op(Hi, tempdata);
        memset(tempdata,0,56+4);
    }
    // fill up the last 32 bits (spec defines 64 bits, in this case
    // we just set the top 32 bits to zeros).
    for(i=PADBASE_INDEX+4; i < 64; i++) {
        tempdata[i] = (len << 3) >> (24 - ((i - PADBASE_INDEX)*8));
    }
    sha2_op(Hi, tempdata);
    return ERROR_MSHA2_SUCCESS;
}

int sha2_init(u32* hash) {
    // assume hash buffer is correct size
    if(!hash) {
        return ERROR_MSHA2_BAD_PARAMS;
    }
    memcpy(hash, H0, sizeof(H0));
    return ERROR_MSHA2_SUCCESS;
}

#ifdef _TESTMAIN

#define BYTECOUNT(_x) (sizeof(_x) - 1)

int main(int argc, char* argv[]) {
    u32 hash[8];
    char abc[] = "abc";
    // 56 bytes - two blocks
    char _2blocks[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    u8 space[64];

    (void)abc; (void)_2blocks;
    memset(space, 0, sizeof(space));

    sha2_init(hash);

    //strcpy((char*)space, abc);
    //sha2_exec(hash, space, BYTECOUNT(abc));

    strcpy((char*)space, _2blocks);
    sha2_exec(hash, space, BYTECOUNT(_2blocks));
    return 0;
}
#endif
