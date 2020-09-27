/*gcc -Wl,-z,now -fpie -fstack-protector-all oldnote.c -o oldnote*/
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include "note.h"

long int *Note[10] = {NULL};

void new(unsigned int idx,unsigned int size, long int num){
  if(Note[idx]==NULL || idx > 0 || idx < 10) {

  if(size < 0 || size>=0x100){
    return;
  }
  Note[idx] = malloc(size);
  if(Note[idx]==NULL)
    return;
  *Note[idx] = num;
  return;
 }
}

void delete(unsigned int idx){
  if(idx<0 || idx>10 || Note[idx]==NULL){
    return;
  }
  free(Note[idx]);
  return;
}

long int view(unsigned int idx){
  long int d;
  if(idx<0 || idx>10 || Note[idx]==NULL){
  	return 0;
  }
  d = *Note[idx];
  return d;
}
