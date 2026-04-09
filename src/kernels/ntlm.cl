// NTLM OpenCL kernel for brutecraber GPU acceleration
// NTLM = MD4(UTF-16LE(password))
// Little-endian byte order. Single-block: password < 28 characters (UTF-16LE doubles length).

// MD4 word indices and rotation amounts per round
__constant uint R2_IDX[16] = {0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15};
__constant uint R3_IDX[16] = {0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15};

__constant uint R1_S[4] = {3, 7, 11, 19};
__constant uint R2_S[4] = {3, 5, 9, 13};
__constant uint R3_S[4] = {3, 9, 11, 15};

__kernel void ntlm_crack(
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

    // UTF-16LE doubles the length; single-block MD4 requires < 56 bytes
    if (len >= 28) {
        results[gid] = 0xFFFFFFFF;
        return;
    }

    // Prepare MD4 message block (16 x uint32 = 64 bytes)
    // Encode ASCII password as UTF-16LE: each byte -> (byte, 0x00)
    uint M[16];
    for (int i = 0; i < 16; i++) M[i] = 0;

    // Pack character pairs: M[i/2] = char[i] | (char[i+1] << 16)
    for (uint i = 0; i < len; i++) {
        uint ch = (uint)words_data[offset + i];
        M[i >> 1] |= ch << ((i & 1) * 16);
    }

    // Append 0x80 at UTF-16LE byte position 2*len (little-endian)
    // Word index: (2*len) / 4 = len / 2
    // Byte shift: ((2*len) % 4) * 8 = (len & 1) ? 16 : 0
    M[len >> 1] |= 0x80u << ((len & 1) * 16);

    // Message length in bits: 2*len*8 = len*16 = len << 4
    M[14] = len << 4;

    // Initialize MD4 state
    uint a = 0x67452301;
    uint b = 0xefcdab89;
    uint c = 0x98badcfe;
    uint d = 0x10325476;

    uint aa = a, bb = b, cc = c, dd = d;

    // Round 1: F(x,y,z) = (x & y) | (~x & z)
    for (uint i = 0; i < 16; i++) {
        uint f = (b & c) | ((~b) & d);
        uint temp = d;
        d = c;
        c = b;
        b = rotate(a + f + M[i], R1_S[i & 3]);
        a = temp;
    }

    // Round 2: G(x,y,z) = (x & y) | (x & z) | (y & z)
    for (uint i = 0; i < 16; i++) {
        uint f = (b & c) | (b & d) | (c & d);
        uint temp = d;
        d = c;
        c = b;
        b = rotate(a + f + M[R2_IDX[i]] + 0x5A827999u, R2_S[i & 3]);
        a = temp;
    }

    // Round 3: H(x,y,z) = x ^ y ^ z
    for (uint i = 0; i < 16; i++) {
        uint f = b ^ c ^ d;
        uint temp = d;
        d = c;
        c = b;
        b = rotate(a + f + M[R3_IDX[i]] + 0x6ED9EBA1u, R3_S[i & 3]);
        a = temp;
    }

    a += aa;
    b += bb;
    c += cc;
    d += dd;

    // Build 16-byte digest (little-endian, same as MD5)
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
        for (uint j = 0; j < 16; j++) {
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
