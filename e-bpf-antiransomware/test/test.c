#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

int main()
{
    FILE *fd = fopen("/dev/urandom", "r");    
    int count = 0;
    char buf[4096];

    if (!fd) {
        printf("Can't open urandom\n");
        return -1;
    }
    
    count = fread(buf, 4096, 1, fd);
    fclose(fd);
    printf("I've read the random data I need, now, i'll write it !\n");
    if (count) {
        fd = fopen("safe_test.txt", "w");
        fwrite(buf, 4096, 1, fd);
        printf("Written ! This means that I am not dead !\n");
    }
}