from utils import eprint
import utils
from trusted_setup.prepare_setups import *

class TrustedSetup:
    def __init__(self, setup_root, url_prover_key, url_main_c, url_main_c_dat, url_vk, url_circuit_config, url_generate_witness_js, url_main_wasm, url_witness_calculator_js):
        self.setup_root=setup_root
        self.url_prover_key=url_prover_key
        self.url_main_c=url_main_c
        self.url_main_c_dat=url_main_c_dat
        self.url_vk=url_vk
        self.url_circuit_config=url_circuit_config
        self.url_generate_witness_js=url_generate_witness_js
        self.url_main_wasm=url_main_wasm
        self.url_witness_calculator_js=url_witness_calculator_js


res_root = utils.resources_dir_root()

default_setup = TrustedSetup(
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


new_setup = TrustedSetup(
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


def download_latest_setup():
    eprint("Downloading latest trusted setup...")

    download_setup(default_setup)
    download_setup(new_setup)

    eprint("Download finished. Creating symlinks...")
    force_symlink_dir(default_setup.setup_root, f'{res_root}/default')
    force_symlink_dir(new_setup.setup_root, f'{res_root}/new')

    eprint("Done.")


def download_latest_witness_gen_c():
    eprint("Downloading latest witness generation binaries (C)...")

    download_witness_gen_binaries_c(default_setup)
    download_witness_gen_binaries_c(new_setup)

    eprint("Download finished. Creating symlinks...")
    force_symlink_dir(default_setup.setup_root, f'{res_root}/default')
    force_symlink_dir(new_setup.setup_root, f'{res_root}/new')

    eprint("Done.")


def download_latest_witness_gen_wasm():
    eprint("Downloading latest witness generation binaries (wasm)...")

    download_witness_gen_binaries_wasm(default_setup)
    download_witness_gen_binaries_wasm(new_setup)

    eprint("Download finished. Creating symlinks...")
    force_symlink_dir(default_setup.setup_root, f'{res_root}/default')
    force_symlink_dir(new_setup.setup_root, f'{res_root}/new')

    eprint("Done.")

def run_dummy_setup():
    eprint("run_dummy_setup")
    eprint("Not yet implemented")
    exit(2)
