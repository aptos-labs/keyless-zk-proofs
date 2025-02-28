#ifndef FFT_H
#define FFT_H

#include "scope_guard.hpp"

#include <gmp.h>
#include <iostream>
#include <tbb/parallel_for.h>

#include <thread>
#include <vector>

template <typename Field>
class FFT
{
    Field                           f;
    typedef typename Field::Element Element;

    std::uint32_t        s;
    Element              nqr;
    std::vector<Element> roots;
    std::vector<Element> powTwoInv;
    // std::uint32_t        nThreads; // not used

    void reversePermutationInnerLoop(Element* a, std::uint64_t from,
                                     std::uint64_t to, std::uint32_t domainPow);
    void reversePermutation(Element* a, std::uint64_t n);
    void fftInnerLoop(Element* a, std::uint64_t from, std::uint64_t to,
                      std::uint32_t s);
    void finalInverseInner(Element* a, std::uint64_t from, std::uint64_t to,
                           std::uint32_t domainPow);

public:
    FFT(std::uint64_t maxDomainSize, std::uint32_t _nThreads = 0);
    // ~FFT();
    void fft(Element* a, std::uint64_t n);
    void ifft(Element* a, std::uint64_t n);

    std::uint32_t   log2(std::uint64_t n);
    inline Element& root(std::uint32_t domainPow, std::uint64_t idx)
    {
        return roots[idx << (s - domainPow)];
    }

    void printVector(Element* a, std::uint64_t n);
};

// The function we want to execute on the new thread.


#endif // FFT_H
