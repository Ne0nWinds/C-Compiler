#pragma once

#include "base.h"

struct unit_test {
    string8 SourceCode;
    s32 ExpectedResult;
};

static constexpr unit_test UnitTestsPass[] = {
    {
        u8"int main(void) {\n"
        u8"  return 2;\n"
        u8"}",
        2
    },
    {
        u8"int main(void) {\n"
        u8"  return -2;\n"
        u8"}",
        -2
    },
    {
        u8"int main(void) {\n"
        u8"  return ~(-8);\n"
        u8"}",
        ~(-8)
    },
    {
        u8"int main(void) {\n"
        u8"  return -(-1024);\n"
        u8"}",
        1024
    },
    {
        u8"int main(void) {\n"
        u8"  return -~~~~~~~-(-19);\n"
        u8"}",
        -~~~~~~~-(-19)
    },
    {
        u8"int main(void) {\n"
        u8"  return -(-(-(-(-(-(98))))));\n"
        u8"}",
        -(-(-(-(-(-(98))))))
    },
};

static constexpr bool ShowCompilerErrorsInUnitTests = false;
static string8 UnitTestsFail[] = {
    u8"int main(void) {\n"
    u8"  return &2;\n"
    u8"}",

    u8"int main(void) {\n"
    u8"  return 2$;\n"
    u8"}",

    u8"int main(void) {\n"
    u8"  return value!;\n"
    u8"}",

    u8"int main(void) {\n"
    u8"  retun 2;\n"
    u8"}",

    u8"int main(void) {\n"
    u8"  return --2;\n"
    u8"}",
};