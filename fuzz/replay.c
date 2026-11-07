/* SPDX-License-Identifier: ISC */
/* Copyright (c) 2026 David Walther <david@clearbrookdistillery.com> */
/* Replay driver: feeds each file named on the command line to LLVMFuzzerTestOneInput, so the corpus
 * can run under valgrind or gcc without libFuzzer. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int main(int argc, char **argv)
{
    for (int i = 1; i < argc; i++) {
        FILE *f = fopen(argv[i], "rb");
        uint8_t *buf = malloc(65536);
        size_t n;

        if (!f || !buf) {
            perror(argv[i]);
            return 2;
        }
        n = fread(buf, 1, 65536, f);
        fclose(f);
        LLVMFuzzerTestOneInput(buf, n);
        free(buf);
    }
    return 0;
}
