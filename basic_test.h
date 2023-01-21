//
// Created by amit levi on 20/01/2023.
//

#ifndef ATAMWET4_BASIC_TEST_H
#define ATAMWET4_BASIC_TEST_H
#include <stdio.h>

int foo(int a, int b)
{
    return a + b;
}
int main()
{
    foo(3, 4);

    foo(0, 0);
    foo(42, 42);
    return 0;
}
#endif //ATAMWET4_BASIC_TEST_H