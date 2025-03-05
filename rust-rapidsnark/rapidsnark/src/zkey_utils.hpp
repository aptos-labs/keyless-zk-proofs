#pragma once

#include <gmp.h>
#include <memory>
#include <stdexcept>

#include "binfile_utils.hpp"

namespace ZKeyUtils
{

class Header
{

public:
    std::uint32_t n8q;
    mpz_t         qPrime;
    std::uint32_t n8r;
    mpz_t         rPrime;

    std::uint32_t nVars;
    std::uint32_t nPublic;
    std::uint32_t domainSize;
    uint64_t     nCoefs;

    void* vk_alpha1;
    void* vk_beta1;
    void* vk_beta2;
    void* vk_gamma2;
    void* vk_delta1;
    void* vk_delta2;

    Header()
    {
        mpz_init(qPrime);
        mpz_init(rPrime);
    }

    ~Header()
    {
        mpz_clear(qPrime);
        mpz_clear(rPrime);
    }

    Header(Header const&)            = delete; // no copy constructor
    Header& operator=(Header const&) = delete;

    static std::unique_ptr<Header>
    make_from_bin_file(BinFileUtils::BinFile& bin_file)
    {
        // A memory leak was here
        auto ret = std::make_unique<Header>();

        bin_file.startReadSection(1);
        uint32_t protocol = bin_file.readU32LE();
        if (protocol != 1)
        {
            throw std::invalid_argument("zkey file is not groth16");
        }
        bin_file.endReadSection();

        bin_file.startReadSection(2);

        ret->n8q = bin_file.readU32LE();
        mpz_import(ret->qPrime, ret->n8q, -1, 1, -1, 0,
                   bin_file.read(ret->n8q));

        ret->n8r = bin_file.readU32LE();
        mpz_import(ret->rPrime, ret->n8r, -1, 1, -1, 0,
                   bin_file.read(ret->n8r));

        ret->nVars      = bin_file.readU32LE();
        ret->nPublic    = bin_file.readU32LE();
        ret->domainSize = bin_file.readU32LE();

        ret->vk_alpha1 = bin_file.read(ret->n8q * 2);
        ret->vk_beta1  = bin_file.read(ret->n8q * 2);
        ret->vk_beta2  = bin_file.read(ret->n8q * 4);
        ret->vk_gamma2 = bin_file.read(ret->n8q * 4);
        ret->vk_delta1 = bin_file.read(ret->n8q * 2);
        ret->vk_delta2 = bin_file.read(ret->n8q * 4);
        bin_file.endReadSection();

        ret->nCoefs = bin_file.getSectionSize(4) / (12 + ret->n8r);

        return ret;
    }

}; // class Header

} // namespace ZKeyUtils
