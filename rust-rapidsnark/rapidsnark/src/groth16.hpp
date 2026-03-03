#ifndef GROTH16_HPP
#define GROTH16_HPP

#include <nlohmann/json.hpp>
#include <sstream>
#include <string>

using json = nlohmann::json;

#include "fft.hpp"

namespace Groth16
{

template <typename Engine>
class Proof
{
    Engine& E;

public:
    typename Engine::G1PointAffine A;
    typename Engine::G2PointAffine B;
    typename Engine::G1PointAffine C;

    Proof(Engine& _E)
        : E(_E)
    {
    }
    std::string toJsonStr();
    json        toJson();
};

#pragma pack(push, 1)
template <typename Engine>
struct Coef
{
    uint32_t                  m;
    uint32_t                  c;
    uint32_t                  s;
    typename Engine::FrElement coef;
};
#pragma pack(pop)

template <typename Engine>
class Prover
{

    Engine&                         E;
    uint32_t                       nVars;
    uint32_t                       nPublic;
    uint32_t                       domainSize;
    uint64_t                       nCoefs;
    typename Engine::G1PointAffine& vk_alpha1;
    typename Engine::G1PointAffine& vk_beta1;
    typename Engine::G2PointAffine& vk_beta2;
    typename Engine::G1PointAffine& vk_delta1;
    typename Engine::G2PointAffine& vk_delta2;
    Coef<Engine>*                   coefs;
    typename Engine::G1PointAffine* pointsA;
    typename Engine::G1PointAffine* pointsB1;
    typename Engine::G2PointAffine* pointsB2;
    typename Engine::G1PointAffine* pointsC;
    typename Engine::G1PointAffine* pointsH;

    FFT<typename Engine::Fr> fft_;

public:
    Prover(Engine& _E, uint32_t _nVars, uint32_t _nPublic,
           uint32_t _domainSize, uint64_t _nCoefs,
           typename Engine::G1PointAffine& _vk_alpha1,
           typename Engine::G1PointAffine& _vk_beta1,
           typename Engine::G2PointAffine& _vk_beta2,
           typename Engine::G1PointAffine& _vk_delta1,
           typename Engine::G2PointAffine& _vk_delta2, Coef<Engine>* _coefs,
           typename Engine::G1PointAffine* _pointsA,
           typename Engine::G1PointAffine* _pointsB1,
           typename Engine::G2PointAffine* _pointsB2,
           typename Engine::G1PointAffine* _pointsC,
           typename Engine::G1PointAffine* _pointsH)
        : E(_E)
        , nVars(_nVars)
        , nPublic(_nPublic)
        , domainSize(_domainSize)
        , nCoefs(_nCoefs)
        , vk_alpha1(_vk_alpha1)
        , vk_beta1(_vk_beta1)
        , vk_beta2(_vk_beta2)
        , vk_delta1(_vk_delta1)
        , vk_delta2(_vk_delta2)
        , coefs(_coefs)
        , pointsA(_pointsA)
        , pointsB1(_pointsB1)
        , pointsB2(_pointsB2)
        , pointsC(_pointsC)
        , pointsH(_pointsH)
        , fft_(domainSize * 2)
    {
    }

    Prover() = delete;

    Prover(Prover const&)            = delete;
    Prover& operator=(Prover const&) = delete;

    std::unique_ptr<Proof<Engine>> prove(typename Engine::FrElement* wtns);
};

template <typename Engine>
std::unique_ptr<Prover<Engine>>
makeProver(uint32_t nVars, uint32_t nPublic, uint32_t domainSize,
           uint64_t nCoefs, void* vk_alpha1, void* vk_beta1, void* vk_beta2,
           void* vk_delta1, void* vk_delta2, void* coefs, void* pointsA,
           void* pointsB1, void* pointsB2, void* pointsC, void* pointsH);
} // namespace Groth16

#endif
