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
#ifndef __simple_sha256_h__
#define __simple_sha256_h__

#define u8 unsigned char
#define u32 unsigned int

#define ERROR_MSHA2_BASE -1000
#define ERROR_MSHA2_SUCCESS 0
#define ERROR_MSHA2_BAD_PARAMS (ERROR_MSHA2_BASE - 1)

#ifdef __cplusplus
extern "C" {
#endif

    int sha2_init(u32* hash);
    int sha2_exec(u32* Hi, u8* data, int len);


#ifdef __cplusplus
}
#endif

#endif // __simple_sha256_h__
