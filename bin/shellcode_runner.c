#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

typedef int(*shellcode_t)();

void bail(const char *msg) {
    puts(msg);
    exit(EXIT_FAILURE);
}

int main(int argc, char **argv) {
    const char *filename;
    size_t size;
    struct stat st;
    int mmap_flags;
    bool is_fixed_load_addr;
    void *mmap_addr;

    ssize_t num_read;
    ssize_t n;

    shellcode_t shellcode;

    if (2 != argc && 3 != argc) {
        bail(
	    "Usage:\n"
	    "    shellcode_runner <filename>\n"
	    "    shellcode_runner <filename> <load_addr>"
	);
    }

    is_fixed_load_addr = argc == 3;
    filename = argv[1];

    memset(&st, 0, sizeof(st));
    stat(filename, &st);
    size = st.st_size;

    mmap_flags = MAP_SHARED | MAP_ANONYMOUS;
    if (is_fixed_load_addr) {
	mmap_flags |= MAP_FIXED;
	mmap_addr = (void *)strtoul(argv[2], NULL, 16);
    }
    else {
	mmap_addr = NULL;
    }

    uint8_t *data = mmap(mmap_addr, size, PROT_READ | PROT_WRITE | PROT_EXEC, mmap_flags, -1, 0);
    if (NULL == data) {
        bail("mmap() failed");
    }

    int fd = open(filename, O_RDONLY);
    if (-1 == fd) {
        bail("open() failed");
    }

    num_read = 0;
    while (1) {
        ssize_t remaining = size - num_read;
        if (0 == remaining) {
            break;
        }

        n = read(fd, data, remaining);
        if (n < 0) {
            bail("read() failed");
        }
        else if (n == 0) {
            break;
        }
        else {
            num_read += n;
        }
    }

    shellcode = (shellcode_t)data;
    shellcode();

    return EXIT_SUCCESS;
}
