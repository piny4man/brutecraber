// SHA-512 OpenCL kernel for brutecraber GPU acceleration
// Computes SHA-512 hashes for a batch of words and checks against target hashes.
// 64-bit words, big-endian byte order. Single-block messages only (word length < 112 bytes).

__constant ulong SHA512_K[80] = {
    0x428a2f98d728ae22UL, 0x7137449123ef65cdUL, 0xb5c0fbcfec4d3b2fUL, 0xe9b5dba58189dbbcUL,
    0x3956c25bf348b538UL, 0x59f111f1b605d019UL, 0x923f82a4af194f9bUL, 0xab1c5ed5da6d8118UL,
    0xd807aa98a3030242UL, 0x12835b0145706fbeUL, 0x243185be4ee4b28cUL, 0x550c7dc3d5ffb4e2UL,
    0x72be5d74f27b896fUL, 0x80deb1fe3b1696b1UL, 0x9bdc06a725c71235UL, 0xc19bf174cf692694UL,
    0xe49b69c19ef14ad2UL, 0xefbe4786384f25e3UL, 0x0fc19dc68b8cd5b5UL, 0x240ca1cc77ac9c65UL,
    0x2de92c6f592b0275UL, 0x4a7484aa6ea6e483UL, 0x5cb0a9dcbd41fbd4UL, 0x76f988da831153b5UL,
    0x983e5152ee66dfabUL, 0xa831c66d2db43210UL, 0xb00327c898fb213fUL, 0xbf597fc7beef0ee4UL,
    0xc6e00bf33da88fc2UL, 0xd5a79147930aa725UL, 0x06ca6351e003826fUL, 0x142929670a0e6e70UL,
    0x27b70a8546d22ffcUL, 0x2e1b21385c26c926UL, 0x4d2c6dfc5ac42aedUL, 0x53380d139d95b3dfUL,
    0x650a73548baf63deUL, 0x766a0abb3c77b2a8UL, 0x81c2c92e47edaee6UL, 0x92722c851482353bUL,
    0xa2bfe8a14cf10364UL, 0xa81a664bbc423001UL, 0xc24b8b70d0f89791UL, 0xc76c51a30654be30UL,
    0xd192e819d6ef5218UL, 0xd69906245565a910UL, 0xf40e35855771202aUL, 0x106aa07032bbd1b8UL,
    0x19a4c116b8d2d0c8UL, 0x1e376c085141ab53UL, 0x2748774cdf8eeb99UL, 0x34b0bcb5e19b48a8UL,
    0x391c0cb3c5c95a63UL, 0x4ed8aa4ae3418acbUL, 0x5b9cca4f7763e373UL, 0x682e6ff3d6b2b8a3UL,
    0x748f82ee5defb2fcUL, 0x78a5636f43172f60UL, 0x84c87814a1f0ab72UL, 0x8cc702081a6439ecUL,
    0x90befffa23631e28UL, 0xa4506cebde82bde9UL, 0xbef9a3f7b2c67915UL, 0xc67178f2e372532bUL,
    0xca273eceea26619cUL, 0xd186b8c721c0c207UL, 0xeada7dd6cde0eb1eUL, 0xf57d4f7fee6ed178UL,
    0x06f067aa72176fbaUL, 0x0a637dc5a2c898a6UL, 0x113f9804bef90daeUL, 0x1b710b35131c471bUL,
    0x28db77f523047d84UL, 0x32caab7b40c72493UL, 0x3c9ebe0a15c9bebcUL, 0x431d67c49c100d4cUL,
    0x4cc5d4becb3e42b6UL, 0x597f299cfc657e2aUL, 0x5fcb6fab3ad6faecUL, 0x6c44198c4a475817UL
};

#define ROTR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

__kernel void sha512_crack(
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

    // SHA-512 block is 128 bytes; single-block limit: len < 112
    if (len >= 112) {
        results[gid] = 0xFFFFFFFF;
        return;
    }

    // Prepare padded message block (16 x ulong = 128 bytes) -- big-endian
    ulong M[16];
    for (int i = 0; i < 16; i++) M[i] = 0;

    for (uint i = 0; i < len; i++) {
        ulong byte_val = (ulong)words_data[offset + i];
        M[i >> 3] |= byte_val << (56 - (i & 7) * 8);
    }

    // Append 0x80 padding bit
    M[len >> 3] |= (ulong)0x80 << (56 - (len & 7) * 8);

    // Append message length in bits (big-endian, 128-bit at end; upper 64 bits = 0)
    M[15] = (ulong)len << 3;

    // Message schedule (80 words)
    ulong W[80];
    for (int i = 0; i < 16; i++) W[i] = M[i];
    for (int i = 16; i < 80; i++) {
        ulong s0 = ROTR64(W[i - 15], 1) ^ ROTR64(W[i - 15], 8) ^ (W[i - 15] >> 7);
        ulong s1 = ROTR64(W[i - 2], 19) ^ ROTR64(W[i - 2], 61) ^ (W[i - 2] >> 6);
        W[i] = W[i - 16] + s0 + W[i - 7] + s1;
    }

    // Initialize hash state
    ulong a = 0x6a09e667f3bcc908UL;
    ulong b = 0xbb67ae8584caa73bUL;
    ulong c = 0x3c6ef372fe94f82bUL;
    ulong d = 0xa54ff53a5f1d36f1UL;
    ulong e = 0x510e527fade682d1UL;
    ulong f = 0x9b05688c2b3e6c1fUL;
    ulong g = 0x1f83d9abfb41bd6bUL;
    ulong h = 0x5be0cd19137e2179UL;

    // 80 rounds
    for (uint i = 0; i < 80; i++) {
        ulong S1 = ROTR64(e, 14) ^ ROTR64(e, 18) ^ ROTR64(e, 41);
        ulong ch = (e & f) ^ ((~e) & g);
        ulong temp1 = h + S1 + ch + SHA512_K[i] + W[i];
        ulong S0 = ROTR64(a, 28) ^ ROTR64(a, 34) ^ ROTR64(a, 39);
        ulong maj = (a & b) ^ (a & c) ^ (b & c);
        ulong temp2 = S0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    a += 0x6a09e667f3bcc908UL;
    b += 0xbb67ae8584caa73bUL;
    c += 0x3c6ef372fe94f82bUL;
    d += 0xa54ff53a5f1d36f1UL;
    e += 0x510e527fade682d1UL;
    f += 0x9b05688c2b3e6c1fUL;
    g += 0x1f83d9abfb41bd6bUL;
    h += 0x5be0cd19137e2179UL;

    // Build 64-byte digest (big-endian)
    uchar digest[64];
    ulong vals[8];
    vals[0] = a; vals[1] = b; vals[2] = c; vals[3] = d;
    vals[4] = e; vals[5] = f; vals[6] = g; vals[7] = h;

    for (int v = 0; v < 8; v++) {
        ulong val = vals[v];
        int base = v * 8;
        digest[base]     = (uchar)(val >> 56);
        digest[base + 1] = (uchar)(val >> 48);
        digest[base + 2] = (uchar)(val >> 40);
        digest[base + 3] = (uchar)(val >> 32);
        digest[base + 4] = (uchar)(val >> 24);
        digest[base + 5] = (uchar)(val >> 16);
        digest[base + 6] = (uchar)(val >> 8);
        digest[base + 7] = (uchar)(val);
    }

    // Compare against target hashes
    for (uint t = 0; t < num_targets; t++) {
        __global const uchar* target = target_hashes + t * 64;
        bool match = true;
        for (uint j = 0; j < 64; j++) {
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
