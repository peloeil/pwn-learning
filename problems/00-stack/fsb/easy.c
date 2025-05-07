#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void win(void) {
    system("/bin/sh");
}

int main(void) {
    char buf[0x30] = {};

    setbuf(stdout, NULL);

    puts("Input message");
    read(STDIN_FILENO, buf, sizeof(buf));
    printf(buf);

    exit(0);
}
// gcc easy.c -no-pie -o easy
