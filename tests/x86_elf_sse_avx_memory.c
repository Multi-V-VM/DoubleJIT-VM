#include <immintrin.h>

int main(void) {
    double doubles[] = {1.25, 2.5};
    double double_result = 0.0;
    float singles[] = {1.5f, 3.0f};
    float single_result = 0.0f;

    __m128d left_double = _mm_load_sd(&doubles[0]);
    __m128d right_double = _mm_load_sd(&doubles[1]);
    _mm_store_sd(&double_result, _mm_add_sd(left_double, right_double));

    __m128 left_single = _mm_load_ss(&singles[0]);
    __m128 right_single = _mm_load_ss(&singles[1]);
    _mm_store_ss(&single_result, _mm_mul_ss(left_single, right_single));

    if (double_result != 3.75) {
        return 11;
    }
    return single_result == 4.5f ? 0 : 12;
}
