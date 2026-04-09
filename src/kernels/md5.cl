// MD5 OpenCL kernel for brutecraber GPU acceleration
// Computes MD5 hashes for a batch of words and checks against target hashes.
// Supports single-block messages only (word length < 56 bytes).

__constant uint K[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

__constant uint S[64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};

__kernel void md5_crack(
    __global const uchar* words_data,
    __global const uint* word_offsets,
    __global const uint* word_lengths,
    const uint num_words,
    __global const uchar* target_hashes,
    const uint num_targets,
    __global uint* results
) {
    uint gid = get_global_id(0);
    if (gid >= num_words) return;

    uint offset = word_offsets[gid];
    uint len = word_lengths[gid];

    // Skip words >= 56 bytes (would need multi-block MD5)
    if (len >= 56) {
        results[gid] = 0xFFFFFFFF;
        return;
    }

    // Prepare padded message block (16 x uint32 = 64 bytes)
    uint M[16];
    for (int i = 0; i < 16; i++) M[i] = 0;

    // Copy word bytes into M in little-endian order
    for (uint i = 0; i < len; i++) {
        uint byte_val = (uint)words_data[offset + i];
        M[i >> 2] |= byte_val << ((i & 3) * 8);
    }

    // Append 0x80 padding bit
    M[len >> 2] |= 0x80u << ((len & 3) * 8);

    // Append message length in bits at bytes 56-63 (M[14], M[15])
    M[14] = len << 3;
    M[15] = 0;

    // Initialize hash state
    uint a = 0x67452301;
    uint b = 0xefcdab89;
    uint c = 0x98badcfe;
    uint d = 0x10325476;

    uint aa = a, bb = b, cc = c, dd = d;

    // 64 rounds
    for (uint i = 0; i < 64; i++) {
        uint f, g;
        if (i < 16) {
            f = (b & c) | ((~b) & d);
            g = i;
        } else if (i < 32) {
            f = (d & b) | ((~d) & c);
            g = (5 * i + 1) & 15;
        } else if (i < 48) {
            f = b ^ c ^ d;
            g = (3 * i + 5) & 15;
        } else {
            f = c ^ (b | (~d));
            g = (7 * i) & 15;
        }

        uint temp = d;
        d = c;
        c = b;
        b = b + rotate(a + f + K[i] + M[g], S[i]);
        a = temp;
    }

    a += aa;
    b += bb;
    c += cc;
    d += dd;

    // Build 16-byte digest (little-endian)
    uchar digest[16];
    digest[0]  = (uchar)(a);       digest[1]  = (uchar)(a >> 8);
    digest[2]  = (uchar)(a >> 16);  digest[3]  = (uchar)(a >> 24);
    digest[4]  = (uchar)(b);       digest[5]  = (uchar)(b >> 8);
    digest[6]  = (uchar)(b >> 16);  digest[7]  = (uchar)(b >> 24);
    digest[8]  = (uchar)(c);       digest[9]  = (uchar)(c >> 8);
    digest[10] = (uchar)(c >> 16);  digest[11] = (uchar)(c >> 24);
    digest[12] = (uchar)(d);       digest[13] = (uchar)(d >> 8);
    digest[14] = (uchar)(d >> 16);  digest[15] = (uchar)(d >> 24);

    // Compare against target hashes
    for (uint t = 0; t < num_targets; t++) {
        __global const uchar* target = target_hashes + t * 16;
        bool match = true;
        for (uint i = 0; i < 16; i++) {
            if (digest[i] != target[i]) {
                match = false;
                break;
            }
        }
        if (match) {
            results[gid] = t;
            return;
        }
    }

    results[gid] = 0xFFFFFFFF;
}
