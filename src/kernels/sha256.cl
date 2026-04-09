// SHA-256 OpenCL kernel for brutecraber GPU acceleration
// Computes SHA-256 hashes for a batch of words and checks against target hashes.
// Big-endian byte order. Supports single-block messages only (word length < 56 bytes).

__constant uint SHA256_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

__kernel void sha256_crack(
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

    // Prepare padded message block -- big-endian
    uint M[16];
    for (int i = 0; i < 16; i++) M[i] = 0;

    for (uint i = 0; i < len; i++) {
        uint byte_val = (uint)words_data[offset + i];
        M[i >> 2] |= byte_val << (24 - (i & 3) * 8);
    }

    M[len >> 2] |= 0x80u << (24 - (len & 3) * 8);
    M[15] = len << 3;

    // Message schedule (64 words)
    uint W[64];
    for (int i = 0; i < 16; i++) W[i] = M[i];
    for (int i = 16; i < 64; i++) {
        uint s0 = ROTR(W[i - 15], 7) ^ ROTR(W[i - 15], 18) ^ (W[i - 15] >> 3);
        uint s1 = ROTR(W[i - 2], 17) ^ ROTR(W[i - 2], 19) ^ (W[i - 2] >> 10);
        W[i] = W[i - 16] + s0 + W[i - 7] + s1;
    }

    // Initialize hash state
    uint a = 0x6a09e667;
    uint b = 0xbb67ae85;
    uint c = 0x3c6ef372;
    uint d = 0xa54ff53a;
    uint e = 0x510e527f;
    uint f = 0x9b05688c;
    uint g = 0x1f83d9ab;
    uint h = 0x5be0cd19;

    // 64 rounds
    for (uint i = 0; i < 64; i++) {
        uint S1 = ROTR(e, 6) ^ ROTR(e, 11) ^ ROTR(e, 25);
        uint ch = (e & f) ^ ((~e) & g);
        uint temp1 = h + S1 + ch + SHA256_K[i] + W[i];
        uint S0 = ROTR(a, 2) ^ ROTR(a, 13) ^ ROTR(a, 22);
        uint maj = (a & b) ^ (a & c) ^ (b & c);
        uint temp2 = S0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    a += 0x6a09e667;
    b += 0xbb67ae85;
    c += 0x3c6ef372;
    d += 0xa54ff53a;
    e += 0x510e527f;
    f += 0x9b05688c;
    g += 0x1f83d9ab;
    h += 0x5be0cd19;

    // Build 32-byte digest (big-endian)
    uchar digest[32];
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
    digest[20] = (uchar)(f >> 24); digest[21] = (uchar)(f >> 16);
    digest[22] = (uchar)(f >> 8);  digest[23] = (uchar)(f);
    digest[24] = (uchar)(g >> 24); digest[25] = (uchar)(g >> 16);
    digest[26] = (uchar)(g >> 8);  digest[27] = (uchar)(g);
    digest[28] = (uchar)(h >> 24); digest[29] = (uchar)(h >> 16);
    digest[30] = (uchar)(h >> 8);  digest[31] = (uchar)(h);

    // Compare against target hashes
    for (uint t = 0; t < num_targets; t++) {
        __global const uchar* target = target_hashes + t * 32;
        bool match = true;
        for (uint j = 0; j < 32; j++) {
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
