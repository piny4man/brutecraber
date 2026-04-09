// SHA3-256 OpenCL kernel for brutecraber GPU acceleration
// Keccak sponge construction. Rate = 136 bytes, output = 32 bytes.
// Supports single-block messages only (word length < 136 bytes).

__constant ulong KECCAK_RC[24] = {
    0x0000000000000001UL, 0x0000000000008082UL,
    0x800000000000808AUL, 0x8000000080008000UL,
    0x000000000000808BUL, 0x0000000080000001UL,
    0x8000000080008081UL, 0x8000000000008009UL,
    0x000000000000008AUL, 0x0000000000000088UL,
    0x0000000080008009UL, 0x000000008000000AUL,
    0x000000008000808BUL, 0x800000000000008BUL,
    0x8000000000008089UL, 0x8000000000008003UL,
    0x8000000000008002UL, 0x8000000000000080UL,
    0x000000000000800AUL, 0x800000008000000AUL,
    0x8000000080008081UL, 0x8000000000008080UL,
    0x0000000080000001UL, 0x8000000080008008UL
};

__constant ulong KECCAK_RHO[25] = {
     0,  1, 62, 28, 27,
    36, 44,  6, 55, 20,
     3, 10, 43, 25, 39,
    41, 45, 15, 21,  8,
    18,  2, 61, 56, 14
};

__constant int KECCAK_PI[25] = {
     0, 10, 20,  5, 15,
    16,  1, 11, 21,  6,
     7, 17,  2, 12, 22,
    23,  8, 18,  3, 13,
    14, 24,  9, 19,  4
};

void keccak_f_256(ulong* S) {
    ulong B[25];
    ulong C[5], D[5];

    for (int round = 0; round < 24; round++) {
        // Theta
        for (int x = 0; x < 5; x++)
            C[x] = S[x] ^ S[x + 5] ^ S[x + 10] ^ S[x + 15] ^ S[x + 20];

        for (int x = 0; x < 5; x++) {
            D[x] = C[(x + 4) % 5] ^ rotate(C[(x + 1) % 5], (ulong)1);
            for (int y = 0; y < 5; y++)
                S[x + 5 * y] ^= D[x];
        }

        // Rho + Pi
        for (int i = 0; i < 25; i++)
            B[KECCAK_PI[i]] = rotate(S[i], KECCAK_RHO[i]);

        // Chi
        for (int y = 0; y < 5; y++) {
            for (int x = 0; x < 5; x++) {
                int idx = x + 5 * y;
                S[idx] = B[idx] ^ ((~B[((x + 1) % 5) + 5 * y]) & B[((x + 2) % 5) + 5 * y]);
            }
        }

        // Iota
        S[0] ^= KECCAK_RC[round];
    }
}

__kernel void sha3_256_crack(
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

    // SHA3-256 rate = 136 bytes; single-block limit
    if (len >= 136) {
        results[gid] = 0xFFFFFFFF;
        return;
    }

    // Initialize state to zero
    ulong S[25];
    for (int i = 0; i < 25; i++) S[i] = 0;

    // Absorb message bytes into state (little-endian byte order)
    for (uint i = 0; i < len; i++) {
        ulong byte_val = (ulong)words_data[offset + i];
        S[i >> 3] ^= byte_val << ((i & 7) * 8);
    }

    // SHA-3 domain separation padding: 0x06 at byte position len
    S[len >> 3] ^= (ulong)0x06 << ((len & 7) * 8);

    // Multi-rate padding: 0x80 at byte position (rate - 1) = 135
    S[135 >> 3] ^= (ulong)0x80 << ((135 & 7) * 8);

    // Apply Keccak-f[1600]
    keccak_f_256(S);

    // Extract 32-byte digest from state (little-endian)
    uchar digest[32];
    for (int w = 0; w < 4; w++) {
        ulong val = S[w];
        digest[w * 8]     = (uchar)(val);
        digest[w * 8 + 1] = (uchar)(val >> 8);
        digest[w * 8 + 2] = (uchar)(val >> 16);
        digest[w * 8 + 3] = (uchar)(val >> 24);
        digest[w * 8 + 4] = (uchar)(val >> 32);
        digest[w * 8 + 5] = (uchar)(val >> 40);
        digest[w * 8 + 6] = (uchar)(val >> 48);
        digest[w * 8 + 7] = (uchar)(val >> 56);
    }

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
