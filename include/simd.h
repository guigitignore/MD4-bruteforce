#ifndef SIMD_H_INCLUDED
#define SIMD_H_INCLUDED
#include <immintrin.h>

#ifdef SIMD_MMX
typedef __m64 simd_vector;

#define simd_vector_add_epi32 _mm_add_pi32
#define simd_vector_sub_epi32 _mm_sub_pi32
#define simd_vector_slli_epi32 _mm_slli_pi32
#define simd_vector_srli_epi32 _mm_srli_pi32
#define simd_vector_set1_epi32 _mm_set1_pi32
#define simd_vector_movemask_epi8 _mm_movemask_pi8
#define simd_vector_cmpeq_epi32 _mm_cmpeq_pi32

#elif defined SIMD_SSE
typedef __m128i simd_vector;

#define simd_vector_add_epi32 _mm_add_epi32
#define simd_vector_sub_epi32 _mm_sub_epi32
#define simd_vector_slli_epi32 _mm_slli_epi32
#define simd_vector_srli_epi32 _mm_srli_epi32
#define simd_vector_set1_epi32 _mm_set1_epi32
#define simd_vector_movemask_epi8 _mm_movemask_epi8
#define simd_vector_cmpeq_epi32 _mm_cmpeq_epi32

#elif defined SIMD_AVX
typedef __m256i simd_vector;

#define simd_vector_add_epi32 _mm256_add_epi32
#define simd_vector_sub_epi32 _mm256_sub_epi32
#define simd_vector_slli_epi32 _mm256_slli_epi32
#define simd_vector_srli_epi32 _mm256_srli_epi32
#define simd_vector_set1_epi32 _mm256_set1_epi32
#define simd_vector_movemask_epi8 _mm256_movemask_epi8
#define simd_vector_cmpeq_epi32 _mm256_cmpeq_epi32

#else
#error "You must define with commandline which type of simd instructions you are using: -D [SIMD_MMX|SIMD_SSE|SIMD_AVX]"
#endif

#endif