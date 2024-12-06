#include <stdio.h>
int main(int argc, char *argv[])
{
    FILE *file;
    while (1)
    {
        if (!(file = fopen("a.txt", "w")))
        {
            printf("Couldn't open file!/n");
        }
        fprintf(file, "Hi");
        fclose(file);
    }

    return 0;
}
