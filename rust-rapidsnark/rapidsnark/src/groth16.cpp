
#include "src/groth16.hpp"
#    include "logging.hpp"
#    include "random_generator.hpp"
#    include "scope_guard.hpp"
#    include "spinlock.hpp"
#include "alt_bn128.hpp"

#    include <array>
#    include <chrono>
#    include <future>
#    include <iostream>
#    include <tbb/parallel_for.h>

namespace Groth16
{

template <typename Engine>
std::unique_ptr<Prover<Engine>>
makeProver(std::uint32_t nVars, std::uint32_t nPublic, std::uint32_t domainSize,
           std::uint64_t nCoeffs, void* vk_alpha1, void* vk_beta_1,
           void* vk_beta_2, void* vk_delta_1, void* vk_delta_2, void* coefs,
           void* pointsA, void* pointsB1, void* pointsB2, void* pointsC,
           void* pointsH)
{
    return std::make_unique<Prover<Engine>>(
        Engine::engine, nVars, nPublic, domainSize, nCoeffs,
        *(typename Engine::G1PointAffine*)vk_alpha1,
        *(typename Engine::G1PointAffine*)vk_beta_1,
        *(typename Engine::G2PointAffine*)vk_beta_2,
        *(typename Engine::G1PointAffine*)vk_delta_1,
        *(typename Engine::G2PointAffine*)vk_delta_2,
        (Coef<Engine>*)((uint64_t)coefs + 4),
        (typename Engine::G1PointAffine*)pointsA,
        (typename Engine::G1PointAffine*)pointsB1,
        (typename Engine::G2PointAffine*)pointsB2,
        (typename Engine::G1PointAffine*)pointsC,
        (typename Engine::G1PointAffine*)pointsH);
}

template <typename Engine>
std::unique_ptr<Proof<Engine>>
Prover<Engine>::prove(typename Engine::FrElement* wtns)
{

// #define DONT_USE_FUTURES // seems to be slower on both x86 and M2

#    ifdef DONT_USE_FUTURES
    // std::cout << "num variables: " << nVars << std::endl;
    // std::cout << "domain size: " << domainSize << std::endl;
    // std::cout << "num coeffs: " << nCoefs << std::endl;
    LOG_TRACE("Start Multiexp A");
    uint32_t                 sW = sizeof(wtns[0]);
    typename Engine::G1Point pi_a;
    E.g1.multiMulByScalar(pi_a, pointsA, (uint8_t*)wtns, sW, nVars);
    std::ostringstream ss2;
    ss2 << "pi_a: " << E.g1.toString(pi_a);
    LOG_DEBUG(ss2);

    LOG_TRACE("Start Multiexp B1");
    typename Engine::G1Point pib1;
    E.g1.multiMulByScalar(pib1, pointsB1, (uint8_t*)wtns, sW, nVars);
    std::ostringstream ss3;
    ss3 << "pib1: " << E.g1.toString(pib1);
    LOG_DEBUG(ss3);

    LOG_TRACE("Start Multiexp B2");
    typename Engine::G2Point pi_b;
    E.g2.multiMulByScalar(pi_b, pointsB2, (uint8_t*)wtns, sW, nVars);
    std::ostringstream ss4;
    ss4 << "pi_b: " << E.g2.toString(pi_b);
    LOG_DEBUG(ss4);

    LOG_TRACE("Start Multiexp C");
    typename Engine::G1Point pi_c;
    E.g1.multiMulByScalar(pi_c, pointsC,
                          (uint8_t*)((uint64_t)wtns + (nPublic + 1) * sW), sW,
                          nVars - nPublic - 1);
    std::ostringstream ss5;
    ss5 << "pi_c: " << E.g1.toString(pi_c);
    LOG_DEBUG(ss5);

#    else // use futures (for scalar multiplications)

    LOG_TRACE("Start Multiexp A");
    uint32_t                 sW = sizeof(wtns[0]);
    typename Engine::G1Point pi_a;
    auto                     pA_future = std::async(
        [&]()
        { E.g1.multiMulByScalar(pi_a, pointsA, (uint8_t*)wtns, sW, nVars); });

    LOG_TRACE("Start Multiexp B1");
    typename Engine::G1Point pib1;
    auto                     pB1_future = std::async(
        [&]()
        { E.g1.multiMulByScalar(pib1, pointsB1, (uint8_t*)wtns, sW, nVars); });

    LOG_TRACE("Start Multiexp B2");
    typename Engine::G2Point pi_b;
    auto                     pB2_future = std::async(
        [&]()
        { E.g2.multiMulByScalar(pi_b, pointsB2, (uint8_t*)wtns, sW, nVars); });

    LOG_TRACE("Start Multiexp C");
    typename Engine::G1Point pi_c;
    auto                     pC_future = std::async(
        [&]()
        {
            E.g1.multiMulByScalar(
                pi_c, pointsC, (uint8_t*)((uint64_t)wtns + (nPublic + 1) * sW),
                sW, nVars - nPublic - 1);
        });
#    endif

    LOG_TRACE("Start Initializing a b c A");
    auto a = new typename Engine::FrElement[domainSize];
    MAKE_SCOPE_EXIT(delete_a) { delete[] a; };

    auto b = new typename Engine::FrElement[domainSize];
    MAKE_SCOPE_EXIT(delete_b) { delete[] b; };

    auto c = new typename Engine::FrElement[domainSize];
    MAKE_SCOPE_EXIT(delete_c) { delete[] c; };

    tbb::parallel_for(tbb::blocked_range<std::uint32_t>(0, domainSize),
                      [&](tbb::blocked_range<std::uint32_t> range)
                      {
                          for (int i = range.begin(); i < range.end(); ++i)
                          {
                              E.fr.copy(a[i], E.fr.zero());
                              E.fr.copy(b[i], E.fr.zero());
                          }
                      });

    LOG_TRACE("Processing coefs");

    static constexpr int NUM_LOCKS = 1024;

    std::array<aptos::spinlock, NUM_LOCKS> spinlocks;

    tbb::parallel_for(
        tbb::blocked_range<std::uint64_t>(0, nCoefs),
        [&](tbb::blocked_range<std::uint64_t> range)
        {
            for (int i = range.begin(); i < range.end(); ++i)
            {
                typename Engine::FrElement* ab = (coefs[i].m == 0) ? a : b;
                typename Engine::FrElement  aux;

                E.fr.mul(aux, wtns[coefs[i].s], coefs[i].coef);
                {
                    std::unique_lock lock(spinlocks[coefs[i].c % NUM_LOCKS]);
                    E.fr.add(ab[coefs[i].c], ab[coefs[i].c], aux);
                }
            }
        });

    LOG_TRACE("Calculating c");

    tbb::parallel_for(tbb::blocked_range<std::uint32_t>(0, domainSize),
                      [&](auto range)
                      {
                          for (int i = range.begin(); i < range.end(); ++i)
                          {
                              E.fr.mul(c[i], a[i], b[i]);
                          }
                      });

    LOG_TRACE("Initializing fft");
    std::uint32_t domainPower = fft_.log2(domainSize);

    auto iFFT_A_future = std::async(
        [&]()
        {
            LOG_TRACE("Start iFFT A");
            fft_.ifft(a, domainSize);
            LOG_TRACE("a After ifft:");
            LOG_DEBUG(E.fr.toString(a[0]).c_str());
            LOG_DEBUG(E.fr.toString(a[1]).c_str());
            LOG_TRACE("Start Shift A");

            tbb::parallel_for(
                tbb::blocked_range<std::uint32_t>(0, domainSize),
                [&](auto range)
                {
                    for (int i = range.begin(); i < range.end(); ++i)
                    {
                        E.fr.mul(a[i], a[i], fft_.root(domainPower + 1, i));
                    }
                });
            LOG_TRACE("a After shift:");
            LOG_DEBUG(E.fr.toString(a[0]).c_str());
            LOG_DEBUG(E.fr.toString(a[1]).c_str());
            LOG_TRACE("Start FFT A");
            fft_.fft(a, domainSize);
            LOG_TRACE("a After fft:");
            LOG_DEBUG(E.fr.toString(a[0]).c_str());
            LOG_DEBUG(E.fr.toString(a[1]).c_str());
        });

    auto iFFT_B_future = std::async(
        [&]()
        {
            LOG_TRACE("Start iFFT B");
            fft_.ifft(b, domainSize);
            LOG_TRACE("b After ifft:");
            LOG_DEBUG(E.fr.toString(b[0]).c_str());
            LOG_DEBUG(E.fr.toString(b[1]).c_str());
            LOG_TRACE("Start Shift B");
            // #    pragma omp parallel for
            //     for (std::uint64_t i = 0; i < domainSize; i++)
            tbb::parallel_for(
                tbb::blocked_range<std::uint32_t>(0, domainSize),
                [&](auto range)
                {
                    for (int i = range.begin(); i < range.end(); ++i)
                    {
                        E.fr.mul(b[i], b[i], fft_.root(domainPower + 1, i));
                    }
                });
            LOG_TRACE("b After shift:");
            LOG_DEBUG(E.fr.toString(b[0]).c_str());
            LOG_DEBUG(E.fr.toString(b[1]).c_str());
            LOG_TRACE("Start FFT B");
            fft_.fft(b, domainSize);
            LOG_TRACE("b After fft:");
            LOG_DEBUG(E.fr.toString(b[0]).c_str());
            LOG_DEBUG(E.fr.toString(b[1]).c_str());
        });

    auto iFFT_C_future = std::async(
        [&]()
        {
            LOG_TRACE("Start iFFT C");
            fft_.ifft(c, domainSize);
            LOG_TRACE("c After ifft:");
            LOG_DEBUG(E.fr.toString(c[0]).c_str());
            LOG_DEBUG(E.fr.toString(c[1]).c_str());
            LOG_TRACE("Start Shift C");

            tbb::parallel_for(
                tbb::blocked_range<std::uint32_t>(0, domainSize),
                [&](auto range)
                {
                    for (int i = range.begin(); i < range.end(); ++i)
                    {
                        E.fr.mul(c[i], c[i], fft_.root(domainPower + 1, i));
                    }
                });
            LOG_TRACE("c After shift:");
            LOG_DEBUG(E.fr.toString(c[0]).c_str());
            LOG_DEBUG(E.fr.toString(c[1]).c_str());
            LOG_TRACE("Start FFT C");
            fft_.fft(c, domainSize);
            LOG_TRACE("c After fft:");
            LOG_DEBUG(E.fr.toString(c[0]).c_str());
            LOG_DEBUG(E.fr.toString(c[1]).c_str());
        });

    iFFT_A_future.get();
    iFFT_B_future.get();
    iFFT_C_future.get();

    LOG_TRACE("Start ABC");

    tbb::parallel_for(tbb::blocked_range<std::uint32_t>(0, domainSize),
                      [&](auto range)
                      {
                          for (int i = range.begin(); i < range.end(); ++i)
                          {
                              E.fr.mul(a[i], a[i], b[i]);
                              E.fr.sub(a[i], a[i], c[i]);
                              E.fr.fromMontgomery(a[i], a[i]);
                          }
                      });

    LOG_TRACE("abc:");
    LOG_DEBUG(E.fr.toString(a[0]).c_str());
    LOG_DEBUG(E.fr.toString(a[1]).c_str());

    LOG_TRACE("Start Multiexp H");
    typename Engine::G1Point pih;
    E.g1.multiMulByScalar(pih, pointsH, (uint8_t*)a, sizeof(a[0]), domainSize);
    std::ostringstream ss1;
    ss1 << "pih: " << E.g1.toString(pih);
    LOG_DEBUG(ss1);

    typename Engine::FrElement r;
    typename Engine::FrElement s;
    typename Engine::FrElement rs;

    // Scalar field modulus for BN128. Taken from the Arkworks algebra repository at
    // https://github.com/arkworks-rs/algebra/blob/master/curves/bn254/src/fields/fr.rs#L4
    // and cross referenced with the value at https://github.com/onurinanc/noir-bn254,
    // converted into hexadecimal with its 4 64-bit chunks being placed in little-endian order
    FrRawElement fr_modulus = {0x43E1F593F0000001ull, 0x2833E84879B97091ull,
                               0xB85045B68181585Dull, 0x30644E72E131A029ull};

    // Sample and reject algorithm for r and s uniformly random field elements
    for (int cmp = 0; cmp >= 0;)
    {
        randombytes_buf(&r, sizeof(r));
        r.v[3] &= 0x3FFFFFFFFFFFFFFFull;
        auto r_copy      = r.v;
        auto fr_mod_copy = fr_modulus;
        cmp              = mpn_cmp(r_copy, fr_mod_copy, Fr_N64);
    }

    for (int cmp = 0; cmp >= 0;)
    {
        randombytes_buf(&s, sizeof(s));
        s.v[3] &= 0x3FFFFFFFFFFFFFFFull;
        auto s_copy      = s.v;
        auto fr_mod_copy = fr_modulus;
        cmp              = mpn_cmp(s_copy, fr_mod_copy, Fr_N64);
    }

#    ifndef DONT_USE_FUTURES
    pA_future.get();
    pB1_future.get();
    pB2_future.get();
    pC_future.get();
#    endif

    typename Engine::G1Point p1;
    typename Engine::G2Point p2;

    E.g1.add(pi_a, pi_a, vk_alpha1);
    E.g1.mulByScalar(p1, vk_delta1, (uint8_t*)&r, sizeof(r));
    E.g1.add(pi_a, pi_a, p1);

    E.g2.add(pi_b, pi_b, vk_beta2);
    E.g2.mulByScalar(p2, vk_delta2, (uint8_t*)&s, sizeof(s));
    E.g2.add(pi_b, pi_b, p2);

    E.g1.add(pib1, pib1, vk_beta1);
    E.g1.mulByScalar(p1, vk_delta1, (uint8_t*)&s, sizeof(s));
    E.g1.add(pib1, pib1, p1);

    E.g1.add(pi_c, pi_c, pih);

    E.g1.mulByScalar(p1, pi_a, (uint8_t*)&s, sizeof(s));
    E.g1.add(pi_c, pi_c, p1);

    E.g1.mulByScalar(p1, pib1, (uint8_t*)&r, sizeof(r));
    E.g1.add(pi_c, pi_c, p1);

    E.fr.mul(rs, r, s);
    E.fr.toMontgomery(rs, rs);

    E.g1.mulByScalar(p1, vk_delta1, (uint8_t*)&rs, sizeof(rs));
    E.g1.sub(pi_c, pi_c, p1);

    auto p = std::make_unique<Proof<Engine>>(Engine::engine);
    E.g1.copy(p->A, pi_a);
    E.g2.copy(p->B, pi_b);
    E.g1.copy(p->C, pi_c);

    return p;
}

template <typename Engine>
std::string Proof<Engine>::toJsonStr()
{
    std::ostringstream ss;
    ss << "{ \"pi_a\":[\"" << E.f1.toString(A.x) << "\",\""
       << E.f1.toString(A.y) << "\",\"1\"], ";
    ss << " \"pi_b\": [[\"" << E.f1.toString(B.x.a) << "\",\""
       << E.f1.toString(B.x.b) << "\"],[\"" << E.f1.toString(B.y.a) << "\",\""
       << E.f1.toString(B.y.b) << "\"], [\"1\",\"0\"]], ";
    ss << " \"pi_c\": [\"" << E.f1.toString(C.x) << "\",\""
       << E.f1.toString(C.y) << "\",\"1\"], ";
    ss << " \"protocol\":\"groth16\" }";

    return ss.str();
}

template <typename Engine>
json Proof<Engine>::toJson()
{
    json p;

    p["pi_a"] = {};
    p["pi_a"].push_back(E.f1.toString(A.x));
    p["pi_a"].push_back(E.f1.toString(A.y));
    p["pi_a"].push_back("1");

    json x2;
    x2.push_back(E.f1.toString(B.x.a));
    x2.push_back(E.f1.toString(B.x.b));
    json y2;
    y2.push_back(E.f1.toString(B.y.a));
    y2.push_back(E.f1.toString(B.y.b));
    json z2;
    z2.push_back("1");
    z2.push_back("0");
    p["pi_b"] = {};
    p["pi_b"].push_back(x2);
    p["pi_b"].push_back(y2);
    p["pi_b"].push_back(z2);

    p["pi_c"] = {};
    p["pi_c"].push_back(E.f1.toString(C.x));
    p["pi_c"].push_back(E.f1.toString(C.y));
    p["pi_c"].push_back("1");

    p["protocol"] = "groth16";

    return p;
}

template class Proof<AltBn128::Engine>;
template class Prover<AltBn128::Engine>;
template struct Coef<AltBn128::Engine>;

template 
std::unique_ptr<Prover<AltBn128::Engine>>
makeProver(uint32_t nVars, uint32_t nPublic, uint32_t domainSize,
           uint64_t nCoefs, void* vk_alpha1, void* vk_beta1, void* vk_beta2,
           void* vk_delta1, void* vk_delta2, void* coefs, void* pointsA,
           void* pointsB1, void* pointsB2, void* pointsC, void* pointsH);

} // namespace Groth16

