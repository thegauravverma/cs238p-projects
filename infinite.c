#include <stdio.h>
int main(int argc, char *argv[]) {
    FILE *file;

    while(1) {
        	if (!(file = fopen("a.txt", "w"))) {
		}
        fprintf(file,"Hi");
        fclose(file);
    }
    return 0;
}
