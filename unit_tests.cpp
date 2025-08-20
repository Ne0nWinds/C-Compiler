#pragma once

#include "base.h"

static constexpr bool ShowCompilerErrorsInUnitTests = false;

struct unit_test {
    string8 SourceCode;
    s32 ExpectedResult;
    u32 LineNumber;
};

static constexpr unit_test UnitTestsPass[] = {
    {
        u8"int main(void) {\n"
        u8"  return 2;\n"
        u8"}",
        2,
        __LINE__
    },
    {
        u8"int main(void) {\n"
        u8"  return -2;\n"
        u8"}",
        -2,
        __LINE__
    },
    {
        u8"int main(void) {\n"
        u8"  return ~(-8);\n"
        u8"}",
        ~(-8),
        __LINE__
    },
    {
        u8"int main(void) {\n"
        u8"  return -(-1024);\n"
        u8"}",
        1024,
        __LINE__
    },
    {
        u8"int main(void) {\n"
        u8"  return -~~~~~~~-(-19);\n"
        u8"}",
        -~~~~~~~-(-19),
        __LINE__
    },
    {
        u8"int main(void) {\n"
        u8"  return -(-(-(-(-(-(98))))));\n"
        u8"}",
        -(-(-(-(-(-(98)))))),
        __LINE__
    },
    {
        u8"int main(void) {\n"
        u8"  return 2 + 2;\n"
        u8"}",
        4,
        __LINE__
    },
    {
        u8"int main(void) {\n"
        u8"  return 10 + 5 + 5;\n"
        u8"}",
        20,
        __LINE__
    },
    {
        u8"int main(void) {\n"
        u8"  return 10 + 5 - 7;\n"
        u8"}",
        8,
        __LINE__
    },
    {
        u8"int main(void) {\n"
        u8"  return -10 + 5 + -8;\n"
        u8"}",
        -10 + 5 + -8,
        __LINE__
    },
    {
        u8"int main(void) {\n"
        u8"  return -~-(~9);\n"
        u8"}",
        -~-(~9),
        __LINE__
    },
    {
        u8"int main(void) {\n"
        u8"  return -~-(~9) + -89 - ~67 + -(-(-1024));\n"
        u8"}",
        -~-(~9) + -89 - ~67 + -(-(-1024)),
        __LINE__
    },
    {
        u8"int main(void) {\n"
        u8"  return 3 * 4;\n"
        u8"}",
        3 * 4,
        __LINE__
    },
    {
        u8"int main(void) {\n"
        u8"  return 3 * 4 + 1;\n"
        u8"}",
        3 * 4 + 1,
        __LINE__
    },
    {
        u8"int main(void) {\n"
        u8"  return 21 + 3 * 4 - 9 * 2 - -6;\n"
        u8"}",
        21 + 3 * 4 - 9 * 2 - -6,
        __LINE__
    },
    {
        u8"int main(void) {\n"
        u8"  return ~1024 + ~98 * ~49;\n"
        u8"}",
        ~1024 + ~98 * ~49,
        __LINE__
    },
    {
        u8"int main(void) {\n"
        u8"  return 4 / 2;\n"
        u8"}",
        2,
        __LINE__
    },
    {
        u8"int main(void) {\n"
        u8"  return 10 + 4 / 2;\n"
        u8"}",
        12,
        __LINE__
    },
    {
        u8"int main(void) {\n"
        u8"  return 10 + 4 / 2 - 7;\n"
        u8"}",
        10 + 4 / 2 - 7,
        __LINE__
    },
    {
        u8"int main(void) {\n"
        u8"  return 15 % 10;\n"
        u8"}",
        15 % 10,
        __LINE__
    },
    {
        u8"int main(void) {\n"
        u8"  return 15 % 10 * 100;\n"
        u8"}",
        500,
        __LINE__
    },
    {
        u8"int main(void) {\n"
        u8"  return -15 % 10;\n"
        u8"}",
        -15 % 10,
        __LINE__
    },
    {
        u8"int main(void) {\n"
        u8"  return (10 + 4 / -(~2) - 7 * 4 / 6 + ~~~~21 - 7 * 16 - 42) % 29;\n"
        u8"}",
        (10 + 4 / -(~2) - 7 * 4 / 6 + ~~~~21 - 7 * 16 - 42) % 29,
        __LINE__
    },
};

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