#include<stdio.h>
#include<stdlib.h>


struct node{
	struct node* next;
	char fingerprint;
};

typedef struct node node;

int insertLL(node **, char);
int removeLL(node **, char);
int searchLL(node *, char); 