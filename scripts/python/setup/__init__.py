from utils import eprint
import utils
from setup.prepare_setups import *


class Setup:
    def __init__(self, root_dir):
        self.root_dir = root_dir

    def path(self):
        return self.root_dir

    def rm(self):
        shutil.rmtree(self.root_dir)

    def mkdir(self):
        self.root_dir.mkdir(parents=True, exist_ok=True)

    def prover_key(self):
        path = self.root_dir / "prover_key.zkey"
        if path.is_file():
            return path
        else:
            return None

    def verification_key(self):
        path = self.root_dir / "verification_key.json"
        if path.is_file():
            return path
        else:
            return None

    def circuit_config(self):
        path = self.root_dir / "circuit_config.yml"
        if path.is_file():
            return path
        else:
            return None

    def witness_gen_c(self):
        paths = [
                self.root_dir / "main_c",
                self.root_dir / "main_c.dat"
                ]
        for path in paths:
            if not path.is_file():
                return None
        return paths

    def witness_gen_wasm(self):
        paths = [
                self.root_dir / "generate_witness.js",
                self.root_dir / "witness_calculator.js",
                self.root_dir / "main.wasm"
                ]
        for path in paths:
            if not path.is_file():
                return None
        return paths


    def is_complete(self):
        return self.prover_key() and  \
               self.verification_key() and \
               self.circuit_config() and \
               ( self.witness_gen_c() or self.witness_gen_wasm() )


class SetupCeremony:
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


ceremonies_dir = utils.resources_dir_root() / 'ceremonies'

default_setup = SetupCeremony(
        setup_root=f'{ceremonies_dir}/setup_2024_05',
        url_prover_key='https://github.com/aptos-labs/aptos-keyless-trusted-setup-contributions-may-2024/raw/main/contributions/main_39f9c44b4342ed5e6941fae36cf6c87c52b1e17f_final.zkey',
        url_main_c='https://github.com/aptos-labs/devnet-groth16-keys/raw/master/main_c_cpp/main_c',
        url_main_c_dat='https://github.com/aptos-labs/devnet-groth16-keys/raw/master/main_c_cpp/main_c.dat',
        url_vk='https://raw.githubusercontent.com/aptos-labs/aptos-keyless-trusted-setup-contributions-may-2024/a26b171945fb2d0b08b015ef80dbca14e4916821/verification_key_39f9c44b4342ed5e6941fae36cf6c87c52b1e17f.json',
        url_circuit_config='https://raw.githubusercontent.com/aptos-labs/aptos-keyless-trusted-setup-contributions-may-2024/a26b171945fb2d0b08b015ef80dbca14e4916821/circuit_config.yml',
        url_generate_witness_js='https://github.com/aptos-labs/devnet-groth16-keys/raw/master/main_js/generate_witness.js',
        url_main_wasm='https://github.com/aptos-labs/devnet-groth16-keys/raw/master/main_js/main.wasm',
        url_witness_calculator_js='https://github.com/aptos-labs/devnet-groth16-keys/raw/master/main_js/witness_calculator.js'
        )


new_setup = SetupCeremony(
        setup_root=f'{ceremonies_dir}/setup_2025_01',
        url_prover_key='https://github.com/aptos-labs/aptos-keyless-trusted-setup-contributions-jan-2025/raw/107bc39ea0bdf8c76e63d189157d8bb6b8ff04da/contributions/main_final.zkey',
        url_main_c='https://github.com/aptos-labs/aptos-keyless-trusted-setup-contributions-jan-2025/raw/107bc39ea0bdf8c76e63d189157d8bb6b8ff04da/main_c_cpp_c60ae945e577295ac1a712391af1bcb337c584d2/main_c',
        url_main_c_dat='https://github.com/aptos-labs/aptos-keyless-trusted-setup-contributions-jan-2025/raw/107bc39ea0bdf8c76e63d189157d8bb6b8ff04da/main_c_cpp_c60ae945e577295ac1a712391af1bcb337c584d2/main_c.dat',
        url_vk='https://raw.githubusercontent.com/aptos-labs/aptos-keyless-trusted-setup-contributions-jan-2025/107bc39ea0bdf8c76e63d189157d8bb6b8ff04da/verification_key.json',
        url_circuit_config='https://raw.githubusercontent.com/aptos-labs/aptos-keyless-trusted-setup-contributions-jan-2025/107bc39ea0bdf8c76e63d189157d8bb6b8ff04da/circuit_config.yml',
        url_generate_witness_js='https://raw.githubusercontent.com/aptos-labs/aptos-keyless-trusted-setup-contributions-jan-2025/107bc39ea0bdf8c76e63d189157d8bb6b8ff04da/main_js_c60ae945e577295ac1a712391af1bcb337c584d2/generate_witness.js',
        url_main_wasm='https://github.com/aptos-labs/aptos-keyless-trusted-setup-contributions-jan-2025/raw/107bc39ea0bdf8c76e63d189157d8bb6b8ff04da/main_js_c60ae945e577295ac1a712391af1bcb337c584d2/main.wasm',
        url_witness_calculator_js='https://raw.githubusercontent.com/aptos-labs/aptos-keyless-trusted-setup-contributions-jan-2025/107bc39ea0bdf8c76e63d189157d8bb6b8ff04da/main_js_c60ae945e577295ac1a712391af1bcb337c584d2/witness_calculator.js'
        )


def download_ceremonies_for_releases(old_setup, new_setup, witness_gen):
    eprint("Downloading latest trusted setup...")

    download_setup(default_setup)
    download_setup(new_setup)

    eprint("Download finished. Creating symlinks...")
    force_symlink_dir(default_setup.setup_root, f'{ceremonies_dir}/default')
    force_symlink_dir(new_setup.setup_root, f'{ceremonies_dir}/new')

    if witness_gen == 'both':
        download_latest_witness_gen_wasm()
        download_latest_witness_gen_c()
    if witness_gen == 'wasm':
        download_latest_witness_gen_wasm()
    elif witness_gen == 'c':
        download_latest_witness_gen_c()

    eprint("Done.")


def download_latest_witness_gen_c():
    eprint("Downloading latest witness generation binaries (C)...")

    download_witness_gen_binaries_c(default_setup)
    download_witness_gen_binaries_c(new_setup)

    eprint("Download finished. Creating symlinks...")
    force_symlink_dir(default_setup.setup_root, f'{ceremonies_dir}/default')
    force_symlink_dir(new_setup.setup_root, f'{ceremonies_dir}/new')

    eprint("Done.")


def download_latest_witness_gen_wasm():
    eprint("Downloading latest witness generation binaries (wasm)...")

    download_witness_gen_binaries_wasm(default_setup)
    download_witness_gen_binaries_wasm(new_setup)

    eprint("Download finished. Creating symlinks...")
    force_symlink_dir(default_setup.setup_root, f'{ceremonies_dir}/default')
    force_symlink_dir(new_setup.setup_root, f'{ceremonies_dir}/new')

    eprint("Done.")



