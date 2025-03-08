from utils import eprint
import utils
from trusted_setup.prepare_setups import *

def download_latest():
    eprint("Downloading latest trusted setup...")

    res_root = utils.resources_dir_root()

    prepare_single_setup(
        setup_root=f'{res_root}/setup_2024_05',
        url_prover_key='https://github.com/aptos-labs/aptos-keyless-trusted-setup-contributions-may-2024/raw/main/contributions/main_39f9c44b4342ed5e6941fae36cf6c87c52b1e17f_final.zkey',
        url_main_c='https://github.com/aptos-labs/devnet-groth16-keys/raw/master/main_c_cpp/main_c',
        url_main_c_dat='https://github.com/aptos-labs/devnet-groth16-keys/raw/master/main_c_cpp/main_c.dat',
        url_vk='https://raw.githubusercontent.com/aptos-labs/aptos-keyless-trusted-setup-contributions-may-2024/a26b171945fb2d0b08b015ef80dbca14e4916821/verification_key_39f9c44b4342ed5e6941fae36cf6c87c52b1e17f.json',
        url_circuit_config='https://raw.githubusercontent.com/aptos-labs/aptos-keyless-trusted-setup-contributions-may-2024/a26b171945fb2d0b08b015ef80dbca14e4916821/circuit_config.yml',
        url_generate_witness_js='https://github.com/aptos-labs/devnet-groth16-keys/raw/master/main_js/generate_witness.js',
        url_main_wasm='https://github.com/aptos-labs/devnet-groth16-keys/raw/master/main_js/main.wasm',
        url_witness_calculator_js='https://github.com/aptos-labs/devnet-groth16-keys/raw/master/main_js/witness_calculator.js'
    )

    prepare_single_setup(
        setup_root=f'{res_root}/setup_2025_01',
        url_prover_key='https://github.com/aptos-labs/aptos-keyless-trusted-setup-contributions-jan-2025/raw/107bc39ea0bdf8c76e63d189157d8bb6b8ff04da/contributions/main_final.zkey',
        url_main_c='https://github.com/aptos-labs/aptos-keyless-trusted-setup-contributions-jan-2025/raw/107bc39ea0bdf8c76e63d189157d8bb6b8ff04da/main_c_cpp_c60ae945e577295ac1a712391af1bcb337c584d2/main_c',
        url_main_c_dat='https://github.com/aptos-labs/aptos-keyless-trusted-setup-contributions-jan-2025/raw/107bc39ea0bdf8c76e63d189157d8bb6b8ff04da/main_c_cpp_c60ae945e577295ac1a712391af1bcb337c584d2/main_c.dat',
        url_vk='https://raw.githubusercontent.com/aptos-labs/aptos-keyless-trusted-setup-contributions-jan-2025/107bc39ea0bdf8c76e63d189157d8bb6b8ff04da/verification_key.json',
        url_circuit_config='https://raw.githubusercontent.com/aptos-labs/aptos-keyless-trusted-setup-contributions-jan-2025/107bc39ea0bdf8c76e63d189157d8bb6b8ff04da/circuit_config.yml',
        url_generate_witness_js='https://raw.githubusercontent.com/aptos-labs/aptos-keyless-trusted-setup-contributions-jan-2025/107bc39ea0bdf8c76e63d189157d8bb6b8ff04da/main_js_c60ae945e577295ac1a712391af1bcb337c584d2/generate_witness.js',
        url_main_wasm='https://github.com/aptos-labs/aptos-keyless-trusted-setup-contributions-jan-2025/raw/107bc39ea0bdf8c76e63d189157d8bb6b8ff04da/main_js_c60ae945e577295ac1a712391af1bcb337c584d2/main.wasm',
        url_witness_calculator_js='https://raw.githubusercontent.com/aptos-labs/aptos-keyless-trusted-setup-contributions-jan-2025/107bc39ea0bdf8c76e63d189157d8bb6b8ff04da/main_js_c60ae945e577295ac1a712391af1bcb337c584d2/witness_calculator.js'
    )

    force_symlink_dir(f'{res_root}/setup_2024_05', f'{res_root}/default')
    force_symlink_dir(f'{res_root}/setup_2025_01', f'{res_root}/new')

    eprint("Done.")

def run_dummy_setup():
    print("run_dummy_setup")
    print("TODO")
