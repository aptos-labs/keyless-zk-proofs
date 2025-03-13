#include <string>
#include <iostream>
#include <thread>
#include <vector>
#include <assert.h> 
#include <sys/time.h>

#include "fr.h"

FrElement nqr;
uint32_t maxS;

using namespace std;

// The function we want to execute on the new thread.

uint32_t log2(uint32_t n) {
    assert(n!=0);
    uint32_t res=0;
    while (n!=1) {
        n >>= 1;
        res ++;
    }
    return res;
}


void printRaw(FrRawElement a) {
    FrElement tmp;
    char *s;
    tmp.type = Fr_LONGMONTGOMERY;
    Fr_rawCopy(tmp.longVal, a);
    s = Fr_element2str(&tmp);
    printf("%s\n", s);
    free(s);
}

void setRaw(FrRawElement r, uint32_t a) {
    FrElement tmp;
    tmp.type = Fr_SHORT;
    tmp.shortVal = a;
    Fr_toMontgomery(&tmp);
    Fr_rawCopy(r, tmp.longVal);
}

static inline uint32_t BR(uint32_t x, uint32_t l)
{
    x = (x >> 16) | (x << 16);
    x = ((x & 0xFF00FF00) >> 8) | ((x & 0x00FF00FF) << 8);
    x = ((x & 0xF0F0F0F0) >> 4) | ((x & 0x0F0F0F0F) << 4);
    x = ((x & 0xCCCCCCCC) >> 2) | ((x & 0x33333333) << 2);
    return (((x & 0xAAAAAAAA) >> 1) | ((x & 0x55555555) << 1)) >> (32-l);
}

static FrRawElement *rootsOfUnit = NULL;
#define ROOT(s,j) (rootsOfUnit[(1<<(s))+(j)])

void init(uint32_t maxDomainSize) {
    uint32_t s =log2(maxDomainSize)-1;
    assert((1 << (s+1)) == maxDomainSize);
    FrElement one = {1, Fr_SHORT};
    FrElement two = {2, Fr_SHORT};
    FrElement q;
    Fr_copy(&q, &Fr_q);
    FrElement qDiv2;
    Fr_idiv(&qDiv2, &q, &two);

    // Find nqr
    Fr_copy(&nqr, &two);

    FrElement res;
    Fr_pow(&res, &nqr, &qDiv2);
    Fr_eq(&res, &res, &one);
    while (Fr_isTrue(&res)) {
        Fr_add(&nqr, &nqr, &one);
        Fr_pow(&res, &nqr, &qDiv2);
        Fr_eq(&res, &res, &one);
    }


    maxS = 0;
    FrElement rem;
    Fr_copy(&rem, &qDiv2);

    Fr_band(&res, &rem, &one);
    while (!Fr_isTrue(&res)) {
        Fr_idiv(&rem, &rem, &two);
        Fr_band(&res, &rem, &one);
        maxS++;
    }

    assert(s <= maxS);

    FrElement lowOmega;
    Fr_pow(&lowOmega, &nqr, &rem);
    for (int i=s; i<maxS; i++) {
        Fr_mul(&lowOmega, &lowOmega, &lowOmega);
    }
    Fr_toMontgomery(&lowOmega);
    

    rootsOfUnit = (FrRawElement *)malloc(maxDomainSize * sizeof(FrRawElement));

    Fr_toMontgomery(&one);


    Fr_rawCopy(rootsOfUnit[0], one.longVal);
    for (int j=0; j<=s; j++) {
        Fr_rawCopy(ROOT(j, 0), one.longVal);
    }

    for (int i=1; i< (maxDomainSize>>1); i++) {
        Fr_rawMMul(ROOT(s, i), ROOT(s, i-1), lowOmega.longVal);
        int ss = s;
        int ii = i;

        // Fill the lowe s roots.
        // We could avoid them as they are redundant, but we add them 
        // So in the normal process we will have better cache hit perfornamce.
        while ((ii&1) == 0) {
            ii >>= 1;
            ss--;
            Fr_rawCopy(ROOT(ss, ii), ROOT(s, i));
        }
    }
}

void reversePermutationInnerLoop(FrRawElement *a, uint32_t from, uint32_t to, uint32_t l2) {
    FrRawElement tmp;
    for (int i=from; i<to; i++) {
        int r = BR(i, l2);
        if (i>r) {
            Fr_rawCopy(tmp, a[i]);
            Fr_rawCopy(a[i], a[r]);
            Fr_rawCopy(a[r], tmp);
        }
    }
}


void reversePermutation(FrRawElement *a, uint32_t n, uint32_t nThreads) {
    int l2 = log2(n);
    std::vector<std::thread> threads(nThreads-1);
    uint32_t increment = n / nThreads;
    if (increment) {
        for (uint32_t i=0; i<nThreads-1; i++) {
            threads[i] = std::thread (reversePermutationInnerLoop, a, i*increment, (i+1)*increment, l2);
        }
    }
    reversePermutationInnerLoop(a, (nThreads-1)*increment, n, l2);
    for (uint32_t i=0; i<nThreads-1; i++) {
        if (threads[i].joinable()) threads[i].join();
    }

}


void fftInnerLoop(FrRawElement *a, uint32_t from, uint32_t to, uint32_t s) {
    FrRawElement t;
    FrRawElement u;
    uint32_t mdiv2 = (1<<s);
    uint32_t m = mdiv2 << 1;
    for (int i=from; i<to; i++) {
        uint32_t k=(i/mdiv2)*m;
        uint32_t j=i%mdiv2;

        Fr_rawMMul(t, ROOT(s, j), a[k+j+mdiv2]);
        Fr_rawCopy(u,a[k+j]);
        Fr_rawAdd(a[k+j], t, u);
        Fr_rawSub(a[k+j+mdiv2], u, t);
    }
}

void fft(FrRawElement *a, uint32_t n, uint32_t nThreads ) {
    reversePermutation(a, n, nThreads);
    uint32_t l2 =log2(n);
    assert((1 << l2) == n);
    std::vector<std::thread> threads(nThreads-1);
    for (uint32_t s=0; s<l2; s++) {
        uint32_t increment = (n >> 1) / nThreads;
        if (increment) {
            for (uint32_t i=0; i<nThreads-1; i++) {
                threads[i] = std::thread (fftInnerLoop, a, i*increment, (i+1)*increment, s);
            }
        }
        fftInnerLoop(a, (nThreads-1)*increment, (n >> 1), s);

        for (uint32_t i=0; i<nThreads-1; i++) {
            if (threads[i].joinable()) threads[i].join();
        }
    }
}

int main(int argc, char**argv)
{

    uint32_t eN = atoi(argv[1]);
    uint32_t nThreads = atoi(argv[2]);

    uint32_t N = (1<<eN);

    Fr_init();
    init(N);

    FrRawElement *v = (FrRawElement *)malloc(N * sizeof(FrRawElement));

    for (uint32_t i=0; i<N; i++) {
        setRaw(v[i], i);
        // printRaw(v[i]);
    }

    printf("Starting...\n");

    struct timeval stop, start;
    gettimeofday(&start, NULL);

    fft(v, N, nThreads);
    fft(v, N, nThreads);

    gettimeofday(&stop, NULL);
    uint32_t diff = (stop.tv_sec - start.tv_sec) * 1000000 + stop.tv_usec - start.tv_usec;

    double diffD = (float)diff / 1000000.0;

    printf("Time: %.2lf\n", diffD);



/*
    for (uint32_t i=0; i<N; i++) {
        printRaw(v[i]);
    }
*/

    free(v);

}