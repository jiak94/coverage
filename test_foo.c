#include <stdio.h>
#include "foo.h"
#include "cool.h"

int main(void) {
    int res;
    res = plus(1, 2);
    /* res = test(); */
    printf("%d\n", res);

    res = multiply(2, 2);
    printf("%d\n", res);
    return 0;
}
