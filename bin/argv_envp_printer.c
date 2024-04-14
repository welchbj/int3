#include <stdio.h>

int main(int argc, char **argv, char **envp) {
    char *env;
    int i;

    for (i = 0; i < argc; ++i) {
        printf("argv[%i] -> %s\n", i, argv[i]);
    }

    i = 0;
    while (1) {
        env = envp[i];
        if (NULL == env) {
            break;
        }

        printf("envp[%i] -> %s\n", i, env);
        ++i;
    }
}
