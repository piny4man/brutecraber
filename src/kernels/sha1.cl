// SHA-1 OpenCL kernel for brutecraber GPU acceleration
// Computes SHA-1 hashes for a batch of words and checks against target hashes.
// Big-endian byte order. Supports single-block messages only (word length < 56 bytes).

__constant uint SHA1_K[4] = {
    0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6
};

__kernel void sha1_crack(
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

    if (len >= 56) {
        results[gid] = 0xFFFFFFFF;
        return;
    }

    // Prepare padded message block (16 x uint32) -- big-endian
    uint M[16];
    for (int i = 0; i < 16; i++) M[i] = 0;

    for (uint i = 0; i < len; i++) {
        uint byte_val = (uint)words_data[offset + i];
        M[i >> 2] |= byte_val << (24 - (i & 3) * 8);
    }

    // Append 0x80 padding bit
    M[len >> 2] |= 0x80u << (24 - (len & 3) * 8);

    // Append message length in bits (big-endian, 64-bit at end of block)
    M[15] = len << 3;

    // Expand to 80-word message schedule
    uint W[80];
    for (int i = 0; i < 16; i++) W[i] = M[i];
    for (int i = 16; i < 80; i++) {
        uint t = W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16];
        W[i] = rotate(t, 1u);
    }

    // Initialize hash state
    uint a = 0x67452301;
    uint b = 0xEFCDAB89;
    uint c = 0x98BADCFE;
    uint d = 0x10325476;
    uint e = 0xC3D2E1F0;

    // 80 rounds
    for (uint i = 0; i < 80; i++) {
        uint f, k;
        if (i < 20) {
            f = (b & c) | ((~b) & d);
            k = SHA1_K[0];
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = SHA1_K[1];
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = SHA1_K[2];
        } else {
            f = b ^ c ^ d;
            k = SHA1_K[3];
        }

        uint temp = rotate(a, 5u) + f + e + k + W[i];
        e = d;
        d = c;
        c = rotate(b, 30u);
        b = a;
        a = temp;
    }

    a += 0x67452301;
    b += 0xEFCDAB89;
    c += 0x98BADCFE;
    d += 0x10325476;
    e += 0xC3D2E1F0;

    // Build 20-byte digest (big-endian)
    uchar digest[20];
    digest[0]  = (uchar)(a >> 24); digest[1]  = (uchar)(a >> 16);
    digest[2]  = (uchar)(a >> 8);  digest[3]  = (uchar)(a);
    digest[4]  = (uchar)(b >> 24); digest[5]  = (uchar)(b >> 16);
    digest[6]  = (uchar)(b >> 8);  digest[7]  = (uchar)(b);
    digest[8]  = (uchar)(c >> 24); digest[9]  = (uchar)(c >> 16);
    digest[10] = (uchar)(c >> 8);  digest[11] = (uchar)(c);
    digest[12] = (uchar)(d >> 24); digest[13] = (uchar)(d >> 16);
    digest[14] = (uchar)(d >> 8);  digest[15] = (uchar)(d);
    digest[16] = (uchar)(e >> 24); digest[17] = (uchar)(e >> 16);
    digest[18] = (uchar)(e >> 8);  digest[19] = (uchar)(e);

    // Compare against target hashes
    for (uint t = 0; t < num_targets; t++) {
        __global const uchar* target = target_hashes + t * 20;
        bool match = true;
        for (uint j = 0; j < 20; j++) {
            if (digest[j] != target[j]) {
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
