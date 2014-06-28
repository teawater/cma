#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

int
main(int argc,char *argv[])
{
	char *a;

	while(1) {
	  a = malloc(10);
	  free(a);
	}
}

