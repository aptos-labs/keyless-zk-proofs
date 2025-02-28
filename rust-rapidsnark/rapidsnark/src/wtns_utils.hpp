# ifndef WTNS_UTILS_H
# define WTNS_UTILS_H


#include <cstdint>
#include <gmp.h>

#include "binfile_utils.hpp"

namespace WtnsUtils
{

class Header
{
public:
    std::uint32_t n8;
    mpz_t         prime;

    std::uint32_t nVars;

    Header() { mpz_init(prime); };

    Header(Header const&)            = delete;
    Header& operator=(Header const&) = delete;

    ~Header() { mpz_clear(prime); }

    static std::unique_ptr<Header>
    make_from_bin_file(BinFileUtils::BinFile& bin_file)
    {
        auto ret = std::make_unique<Header>();

        bin_file.startReadSection(1);

        ret->n8 = bin_file.readU32LE();
        mpz_import(ret->prime, ret->n8, -1, 1, -1, 0, bin_file.read(ret->n8));

        ret->nVars = bin_file.readU32LE();

        bin_file.endReadSection();

        return ret;
    }

}; // class Header

} // namespace WtnsUtils
  
# endif
