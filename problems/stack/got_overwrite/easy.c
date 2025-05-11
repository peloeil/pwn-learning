#include <stdio.h>
#include <stdlib.h>

void win(void) {
    system("/bin/sh");
}

int main(void) {
    void **ptr;

    setbuf(stdout, NULL);
    printf("Input address to write >> ");
    scanf("%p", &ptr);
    printf("Input value >> ");
    scanf("%p", ptr);

    exit(0);
}
// gcc easy.c -no-pie -o easy
