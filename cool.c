#include <stdio.h>
int multiply(int num1, int times)
{
    int i;
    int res = num1;
    for (i = 0; i < times; i++) {
        res *= num1;
    }

    return res;
}


