#include <stdio.h>
#include <unistd.h>

int main(void) {
    char msg[0x10] = {};

    setbuf(stdout, NULL);

    puts("You can put message 3 times");
    for (int i = 0; i < 3; i++) {
        printf("Input (%d/3) >> ", i + 1);
        read(STDIN_FILENO, msg, 0x70);
        printf("Output : %s\n", msg);
    }
    puts("Bye!");

    return 0;
}
// gcc medium.c -o medium
