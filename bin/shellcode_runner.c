#include <fcntl.h>
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

    ssize_t num_read;
    ssize_t n;

    shellcode_t shellcode;

    if (2 != argc) {
        bail("Usage: shellcode_runner <filename>");
    }

    filename = argv[1];

    memset(&st, 0, sizeof(st));
    stat(filename, &st);
    size = st.st_size;

    uint8_t *data = mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
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
