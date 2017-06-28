#include <stdio.h>

void foo(void)
{
    puts("Hello, this is function foo");
}

int plus(int num1, int times)
{
    int i;
    int res = 0;
    for (i = 0; i < times; i++) {
        res += num1;
    }

    return res;
}

int test(){
    return 1+1;
}

void odd(int num) {
    if (num % 2 == 0) {
        puts("It's a EVEN number");
    }
    else {
        puts("It's a ODD number");
    }
}
