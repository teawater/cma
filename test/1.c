#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

int
main(int argc,char *argv[])
{
	int **i,j;
	i=calloc(sizeof(int *),100);
	for(j=0;j<20;j++) {
		i[j]=&j;
	}
	for(j=0;j<20;j++) {
		printf("%d\n",*(i[j]));
	}
	free(i);

	exit(0);
}

