#include <stdio.h>
#include <stdlib.h>

__attribute__((naked)) void pop_rdi_ret() {
    __asm__("pop %rdi; ret");
}

void win(unsigned int key) {
    if (key == 0xdeadbeef) {
        system("/bin/sh");
    } else {
        puts("You are not allowed to access this function.\n");
    }
}

int main(void) {
    char buf[30];
    scanf("%s", buf);
    puts(buf);
    return 0;
}
// gcc easy.c -fno-stack-protector -no-pie -o easy
