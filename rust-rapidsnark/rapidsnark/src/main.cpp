#include "fullprover.hpp"
#include <iostream>

int main(int argc, char* argv[])
{
    auto zkey_file = argc > 1 ? argv[1] : "./testdata/circuit_final.zkey";
    auto wtns_file = argc > 2 ? argv[2] : "./witness.wtns";

    FullProver prover(zkey_file);

    while (1)
    {
        auto ret = prover.prove(wtns_file);

        if (ret.type == SUCCESS)
        {
            std::cout << "OK\n";
        }
        else
        {
            std::cout << "ERROR\n";
        }
        std::cout << ret.raw_json << "\n";
    }
}
