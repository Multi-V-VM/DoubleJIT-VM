//
// Created by flo on 23.06.20.
//

#include "../riscvminilib/rv64minilibc.h"
#include <stdbool.h>
#include <stdint.h>

void init(int number, char *name);

bool check_condition(bool cond);

void assert_equals(size_t expected, size_t actual, int *failed_tests);

/**
 * Compile with:
 * riscv64-unknown-linux-gnu-gcc -o arithm compiled_test_arithm.c rv64minilibc.c rv64minilibc.h -fPIE -static -march=rv64im -mabi=lp64 -nostdlib -lgcc
 * Reference run: qemu-riscv64 arithm
 * or ./translator -v -f arithm.
 *
 * Makefile for compile:
 * arithmetic: compiled_test_arithm.c rv64minilibc.c rv64minilibc.h
	riscv64-unknown-linux-gnu-gcc -o arithm compiled_test_arithm.c rv64minilibc.c rv64minilibc.h -fPIE -static -march=rv64im -mabi=lp64 -nostdlib -lgcc
 * @param argc
 * @param argv
 * @return
 */
int main(int argc, char **argv) {
    int num = 0;
    int failed_tests;

    {
        init(++num, "4/2");
        size_t i = 4;
        i /= 2;
        assert_equals(2, i, &failed_tests);
    }

    {
        init(++num, "4<<2");
        size_t j = 4;
        j <<= 2;
        assert_equals(16, j, &failed_tests);
    }

    {
        init(++num, "5/2");
        size_t m = 5;
        m /= 2;
        assert_equals(2, m, &failed_tests);
    }

    {
        init(++num, "pdm");
        size_t n = 256;
        size_t o = 128;
        n += o;
        n *= 10;
        n /= 19;
        assert_equals(202, n, &failed_tests);
    }

    {
        init(++num, "3000*7");
        size_t n = 3000;
        size_t m = 7;
        assert_equals(21000, (n * m), &failed_tests);
    }

    {
        init(++num, "3000/7");
        size_t n = 3000;
        size_t m = 7;
        assert_equals(428, (n / m), &failed_tests);
    }

    {
        //div-zero quotient should have all bits set
        init(++num, "DivZero (unsigned)");
        uint32_t n = 256;
        uint32_t m = 0;
        assert_equals(0xFFFFFFFF, (n / m), &failed_tests);
    }

    {
        //div-zero quotient should have all bits set
        init(++num, "DivZero (signed)");
        int n = 256;
        int m = 0;
        assert_equals(0xFFFFFFFFFFFFFFFF, (n / m), &failed_tests);
    }

    {
        //div-zero quotient should have all bits set
        init(++num, "DivZero (64b unsigned)");
        uint64_t n = 256;
        uint64_t m = 0;
        assert_equals(0xFFFFFFFFFFFFFFFF, (n / m), &failed_tests);
    }

    {
        //div-zero quotient should have all bits set
        init(++num, "DivZero (64b signed)");
        int64_t n = 256;
        int64_t m = 0;
        assert_equals(0xFFFFFFFFFFFFFFFF, (n / m), &failed_tests);
    }

    {
        //div-zero remainder should equal the dividend
        init(++num, "RemZero");
        size_t n = 256;
        size_t m = 0;
        assert_equals(256, (n % m), &failed_tests);
    }

    {
        init(++num, "1<<10");
        size_t res = 1 << 10;
        assert_equals(0b10000000000, res, &failed_tests);
    }

    {
        //control flow experiment
        init(++num, "SumGauss");
        const int bound = 2048;

        size_t sum = 0;
        for (int i = 1; i <= bound; ++i) {
            sum += i;
        }

        assert_equals(2098176, sum, &failed_tests);
    }

    {
        init(++num, "MulGauss");

        //see above, we just check the gauss formula instead of the sum
        const int bound = 2048;

        size_t gauss = (bound * (bound + 1)) / 2;
        assert_equals(2098176, gauss, &failed_tests);
    }

    {
        //factorial experiments
        const size_t len = 19;
        static uint64_t expecteds[] = {
                1, 2, 6, 24, 120, 720, 5040, 40320, 362880, 3628800, 39916800, 479001600, 6227020800, 87178291200,
                1307674368000, 20922789888000, 355687428096000, 6402373705728000, 121645100408832000
        };

        for (int n = 1; n < len; ++n) {
            init(++num, "Factorial");

            //calculate the factorial
            size_t fact = 1;

            for (size_t i = 1; i <= n; i++) {
                fact *= i;
            }

            assert_equals(expecteds[n - 1], fact, &failed_tests);
        }
    }

    m_exit(failed_tests);
}

void init(int number, char *name) {
    m_write(1, "Test ", 5);
    printi(number);
    m_write(1, "\t(", 2);
    print(name);
    m_write(1, ")", 1);
    m_write(1, "...\t", 4);
}

bool check_condition(bool cond) {
    if (cond) {
        m_write(1, "PASSED\n", 7);
        return true;
    } else {
        m_write(1, "FAILED\n", 7);
        return false;
    }
}

void assert_equals(size_t expected, size_t actual, int *failed_tests) {
    //check the condition, printout expected but was when false
    if (!check_condition(expected == actual)) {
        (*failed_tests)++;
        print("Expected: ");
        printi(expected);
        print(" but was: ");
        printi(actual);
        print("\n");
    }
}