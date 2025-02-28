#pragma once

class FullProverImpl;

enum ProverResponseType
{
    SUCCESS,
    ERROR
};

enum FullProverState
{
    OK,
    ZKEY_FILE_LOAD_ERROR,
    UNSUPPORTED_ZKEY_CURVE
};

enum ProverError
{
    NONE,
    PROVER_NOT_READY,
    INVALID_INPUT,
    WITNESS_GENERATION_INVALID_CURVE
};

struct ProverResponseMetrics
{
    int prover_time;
};

struct ProverResponse
{
    ProverResponseType    type;
    char const*           raw_json;
    ProverError           error;
    ProverResponseMetrics metrics;

private:
    static char const* const empty_string;

public:
    ProverResponse(ProverError _error);
    ProverResponse(const char* _raw_json, ProverResponseMetrics _metrics);

    ProverResponse()                                 = delete;
    ProverResponse(ProverResponse const&)            = delete;
    ProverResponse& operator=(ProverResponse const&) = delete;

    ~ProverResponse();
};

class FullProverImpl;

class FullProver
{
    FullProverImpl* impl;
    FullProverState state;

public:
    FullProver() = delete;
    FullProver(const char* _zkeyFileName);
    ~FullProver();
    ProverResponse prove(const char* input) const;
};
