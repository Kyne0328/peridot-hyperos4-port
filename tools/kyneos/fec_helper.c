/*
 * Minimal Android AVB FEC helper for the KyneOS builder.
 *
 * Implements only the two operations avbtool.py uses:
 *   fec --print-fec-size SIZE --roots 2
 *   fec --encode --roots 2 INPUT OUTPUT
 *
 * The RS parameters match Android libfec FEC_PARAMS(2):
 * GF(2^8), primitive polynomial 0x11d, fcr=0, prim=1, roots=2, pad=0.
 * For two roots the generator is x^2 + 3x + 2. The interleave layout
 * matches system/extras/libfec/include/fec/ecc.h.
 *
 * --input-size is a validation-only extension that limits INPUT to a prefix.
 */
#define _FILE_OFFSET_BITS 64
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#define FEC_BLOCKSIZE 4096ULL
#define FEC_RSM 255ULL
#define FEC_ROOTS 2ULL
#define FEC_RSN (FEC_RSM - FEC_ROOTS)
#define FEC_MAGIC 0xFECFECFEu
#define FEC_VERSION 0u

struct __attribute__((packed)) fec_header {
    uint32_t magic;
    uint32_t version;
    uint32_t size;
    uint32_t roots;
    uint32_t fec_size;
    uint64_t inp_size;
    uint8_t hash[SHA256_DIGEST_LENGTH];
};

static void die(const char *msg) {
    if (errno) {
        fprintf(stderr, "fec: %s: %s\n", msg, strerror(errno));
    } else {
        fprintf(stderr, "fec: %s\n", msg);
    }
    exit(1);
}

static uint64_t div_up(uint64_t x, uint64_t y) {
    return x / y + (x % y != 0);
}

static uint64_t raw_fec_size(uint64_t input_size) {
    const uint64_t blocks = div_up(input_size, FEC_BLOCKSIZE);
    const uint64_t rounds = div_up(blocks, FEC_RSN);
    return rounds * FEC_ROOTS * FEC_BLOCKSIZE;
}

static uint64_t encoded_fec_size(uint64_t input_size) {
    return raw_fec_size(input_size) + FEC_BLOCKSIZE;
}

static inline uint8_t gf_mul2(uint8_t value) {
    return (uint8_t)((value << 1) ^ ((value & 0x80u) ? 0x1du : 0u));
}

static inline uint8_t gf_mul3(uint8_t value) {
    return (uint8_t)(gf_mul2(value) ^ value);
}

static void encode_codeword(const uint8_t *input, uint64_t input_size,
                            uint64_t pos, uint64_t stride, uint8_t *out) {
    uint8_t p0 = 0;
    uint8_t p1 = 0;
    for (uint64_t j = 0; j < FEC_RSN; ++j) {
        const uint64_t offset = pos + j * stride;
        const uint8_t data = offset < input_size ? input[offset] : 0;
        const uint8_t feedback = (uint8_t)(data ^ p0);
        p0 = (uint8_t)(p1 ^ gf_mul3(feedback));
        p1 = gf_mul2(feedback);
    }
    out[0] = p0;
    out[1] = p1;
}

static int self_test(void) {
    uint8_t data[FEC_RSN];
    for (uint64_t i = 0; i < FEC_RSN; ++i) {
        data[i] = (uint8_t)i;
    }
    uint8_t p0 = 0;
    uint8_t p1 = 0;
    for (uint64_t i = 0; i < FEC_RSN; ++i) {
        const uint8_t feedback = (uint8_t)(data[i] ^ p0);
        p0 = (uint8_t)(p1 ^ gf_mul3(feedback));
        p1 = gf_mul2(feedback);
    }
    if (p0 != 62 || p1 != 194) {
        fprintf(stderr, "fec: RS self-test failed: got %u,%u expected 62,194\n", p0, p1);
        return 1;
    }
    puts("fec self-test: PASS");
    return 0;
}

static uint64_t parse_u64(const char *text, const char *name) {
    char *end = NULL;
    errno = 0;
    unsigned long long value = strtoull(text, &end, 0);
    if (errno || !text[0] || !end || *end) {
        fprintf(stderr, "fec: invalid %s: %s\n", name, text);
        exit(1);
    }
    return (uint64_t)value;
}

static void write_all(int fd, const void *buffer, size_t length) {
    const uint8_t *p = (const uint8_t *)buffer;
    while (length) {
        ssize_t n = write(fd, p, length);
        if (n < 0) {
            if (errno == EINTR) continue;
            die("write failed");
        }
        p += (size_t)n;
        length -= (size_t)n;
    }
}

static int encode_file(const char *input_name, const char *output_name,
                       uint64_t requested_size, int has_requested_size) {
    int input_fd = open(input_name, O_RDONLY);
    if (input_fd < 0) die("failed to open input");

    struct stat st;
    if (fstat(input_fd, &st) != 0) die("failed to stat input");
    if (st.st_size <= 0) die("empty input");

    uint64_t input_size = (uint64_t)st.st_size;
    if (has_requested_size) {
        if (!requested_size || requested_size > input_size) {
            errno = 0;
            die("--input-size is outside the input file");
        }
        input_size = requested_size;
    }
    if (input_size % FEC_BLOCKSIZE) {
        errno = 0;
        die("input size is not a multiple of 4096");
    }

    uint8_t *input = mmap(NULL, (size_t)input_size, PROT_READ, MAP_SHARED, input_fd, 0);
    if (input == MAP_FAILED) die("failed to mmap input");

    const uint64_t blocks = input_size / FEC_BLOCKSIZE;
    const uint64_t rounds = div_up(blocks, FEC_RSN);
    const uint64_t codewords = rounds * FEC_BLOCKSIZE;
    const uint64_t fec_size64 = codewords * FEC_ROOTS;
    if (fec_size64 > UINT32_MAX || fec_size64 > SIZE_MAX) {
        errno = 0;
        die("FEC output is too large");
    }
    const size_t fec_size = (size_t)fec_size64;
    uint8_t *fec = malloc(fec_size);
    if (!fec) die("failed to allocate FEC output");

    const uint64_t stride = rounds * FEC_BLOCKSIZE;
#ifdef _OPENMP
#pragma omp parallel for schedule(static)
#endif
    for (uint64_t pos = 0; pos < codewords; ++pos) {
        encode_codeword(input, input_size, pos, stride, &fec[pos * FEC_ROOTS]);
    }

    uint8_t header_block[FEC_BLOCKSIZE];
    memset(header_block, 0, sizeof(header_block));
    struct fec_header header;
    memset(&header, 0, sizeof(header));
    header.magic = FEC_MAGIC;
    header.version = FEC_VERSION;
    header.size = (uint32_t)sizeof(header);
    header.roots = (uint32_t)FEC_ROOTS;
    header.fec_size = (uint32_t)fec_size;
    header.inp_size = input_size;
    SHA256(fec, fec_size, header.hash);
    memcpy(header_block, &header, sizeof(header));
    memcpy(header_block + FEC_BLOCKSIZE - sizeof(header), &header, sizeof(header));

    int output_fd = open(output_name, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (output_fd < 0) die("failed to open output");
    write_all(output_fd, fec, fec_size);
    write_all(output_fd, header_block, sizeof(header_block));
    if (fsync(output_fd) != 0) die("failed to fsync output");
    if (close(output_fd) != 0) die("failed to close output");

    free(fec);
    if (munmap(input, (size_t)input_size) != 0) die("failed to unmap input");
    if (close(input_fd) != 0) die("failed to close input");
    return 0;
}

static void usage(void) {
    fprintf(stderr,
        "usage:\n"
        "  fec --print-fec-size SIZE --roots 2\n"
        "  fec --encode --roots 2 [--input-size SIZE] INPUT OUTPUT\n"
        "  fec --self-test\n");
}

int main(int argc, char **argv) {
    int encode = 0;
    int print_size = 0;
    int self = 0;
    uint64_t size_value = 0;
    uint64_t input_size = 0;
    int has_input_size = 0;
    uint64_t roots = FEC_ROOTS;
    const char *positional[2] = {0};
    int positional_count = 0;

    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--encode") || !strcmp(argv[i], "-e")) {
            encode = 1;
        } else if (!strcmp(argv[i], "--self-test")) {
            self = 1;
        } else if (!strcmp(argv[i], "--print-fec-size") || !strcmp(argv[i], "-s")) {
            if (++i >= argc) { usage(); return 1; }
            size_value = parse_u64(argv[i], "size");
            print_size = 1;
        } else if (!strncmp(argv[i], "--print-fec-size=", 17)) {
            size_value = parse_u64(argv[i] + 17, "size");
            print_size = 1;
        } else if (!strcmp(argv[i], "--roots") || !strcmp(argv[i], "-r")) {
            if (++i >= argc) { usage(); return 1; }
            roots = parse_u64(argv[i], "roots");
        } else if (!strcmp(argv[i], "--input-size")) {
            if (++i >= argc) { usage(); return 1; }
            input_size = parse_u64(argv[i], "input size");
            has_input_size = 1;
        } else if (argv[i][0] == '-') {
            usage();
            return 1;
        } else if (positional_count < 2) {
            positional[positional_count++] = argv[i];
        } else {
            usage();
            return 1;
        }
    }

    if (roots != FEC_ROOTS) {
        fprintf(stderr, "fec: this pinned helper supports exactly 2 roots\n");
        return 1;
    }
    if (self) {
        return self_test();
    }
    if (print_size && !encode && positional_count == 0) {
        printf("%" PRIu64 "\n", encoded_fec_size(size_value));
        return 0;
    }
    if (encode && !print_size && positional_count == 2) {
        return encode_file(positional[0], positional[1], input_size, has_input_size);
    }

    usage();
    return 1;
}
