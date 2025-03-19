from setup import cache
from datetime import datetime
import time
import shutil
import utils
from utils import eprint
import os
from pathlib import Path
import tempfile
import contextlib
import platform
from setup import Setup

PTAU_PATH=utils.resources_dir_root() / "powersOfTau28_hez_final_21.ptau"
PTAU_URL="https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_21.ptau"
PTAU_CHECKSUM="cdc7c94a6635bc91466d8c7d96faefe1d17ecc98a3596a748ca1e6c895f8c2b4"
SETUPS_DIR=utils.resources_dir_root() / "testing_setups"

def current_circuit_checksum():
    return utils.directory_checksum(utils.repo_root() / "circuit/templates")

def current_circuit_setup_path():
    return SETUPS_DIR / current_circuit_checksum()

def prepare_setups_dir():
    if not SETUPS_DIR.is_dir():
        SETUPS_DIR.mkdir(parents=True, exist_ok=True)
    utils.delete_contents_of_dir(SETUPS_DIR)

def download_ptau_file_if_needed():
    if PTAU_PATH.is_file():
        eprint("Powers-of-tau file found, skipping download.")
    else:
        eprint("Downloading powers-of-tau file...")
        utils.download_file(PTAU_URL, PTAU_PATH)

    eprint("Checking sha256sum of ptau file...")
    if utils.file_checksum(PTAU_PATH) != PTAU_CHECKSUM:
        eprint("WARNING: ptau file doesn't match expected sha256sum. Aborting.")
        exit(2)


def generate_c_witness_gen_binaries():
    eprint("Generating c witness gen binaries...")
    with tempfile.TemporaryDirectory() as temp_dir:
        with contextlib.chdir(temp_dir):
            eprint(temp_dir)
            shutil.copytree(utils.repo_root() / "circuit/templates", "./templates")
            with contextlib.chdir("templates"):
                eprint("Compiling circuit...")
                utils.manage_deps.add_cargo_to_path()
                start_time = time.time()
                utils.run_shell_command('circom -l . -l $(npm root -g) main.circom --r1cs --c')
                eprint("Compilation took %s seconds" % (time.time() - start_time))

                with contextlib.chdir("main_c_cpp"):
                    utils.run_shell_command("make")
                    shutil.move("main_c", current_circuit_setup_path())
                    shutil.move("main_c.dat", current_circuit_setup_path())



def c_witness_gen_present():
    (current_circuit_setup_path() / "main_c").is_file() and (current_circuit_setup_path() / "main_c.dat").is_file() 


def procure_testing_setup(ignore_cache):
    current_circuit_setup = Setup(current_circuit_setup_path())
    if current_circuit_setup.is_complete():
        eprint("Setup for the current circuit found. Skipping.")
        return
    else:
        eprint("prover key: " + str(current_circuit_setup.prover_key()))
        eprint("verification key: " + str(current_circuit_setup.verification_key()))
        eprint("circuit config: " + str(current_circuit_setup.circuit_config()))
        eprint("witness gen c: " + str(current_circuit_setup.witness_gen_c()))
        eprint("witness gen wasm: " + str(current_circuit_setup.witness_gen_wasm()))

    prepare_setups_dir()

    download_ptau_file_if_needed()

    if not ignore_cache:
        if cache.download_testing_setup_if_present():
            if platform.machine() == 'x86_64' and not c_witness_gen_present():
                eprint("You're on an x86_64 machine, but the cached setup doesn't contain c witness gen binaries. Going to generate now.")
                generate_c_witness_gen_binaries()
                cache.upload_current_circuit_setup()
            utils.force_symlink_dir(current_circuit_setup.path(), SETUP_DIR / "default")
            return

    current_circuit_setup.mkdir()
    shutil.copy(utils.repo_root() / "prover-service" / "circuit_config.yml", current_circuit_setup.path())

    with tempfile.TemporaryDirectory() as temp_dir:
        with contextlib.chdir(temp_dir):
            eprint(temp_dir)
            shutil.copytree(utils.repo_root() / "circuit/templates", "./templates")
            with contextlib.chdir("templates"):
                eprint("Compiling circuit...")
                utils.manage_deps.add_cargo_to_path()
                start_time = time.time()
                utils.run_shell_command('circom -l . -l $(npm root -g) main.circom --r1cs --wasm --sym')
                eprint("Compilation took %s seconds" % (time.time() - start_time))
                eprint("Starting setup now: " + datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
                start_time = time.time()
                utils.run_shell_command(f'. ~/.nvm/nvm.sh; snarkjs groth16 setup main.r1cs {PTAU_PATH} prover_key.zkey')
                eprint("Running setup took %s seconds" % (time.time() - start_time))
                eprint("Exporting verification key...")
                utils.run_shell_command(f'snarkjs zkey export verificationkey prover_key.zkey verification_key.json')

                
                shutil.move("prover_key.zkey", current_circuit_setup.path())
                shutil.move("verification_key.json", current_circuit_setup.path())
                shutil.move("main_js/generate_witness.js", current_circuit_setup.path())
                shutil.move("main_js/witness_calculator.js", current_circuit_setup.path())
                shutil.move("main_js/main.wasm", current_circuit_setup.path())

                if platform.machine() == 'x86_64':
                    generate_c_witness_gen_binaries()
                else:
                     eprint("Not on x86_64, so skipping generating c witness gen binaries.")

    if not current_circuit_setup.is_complete():
         eprint("ERROR: Circuit setup is not complete. Check the path below for problems.")
         eprint(current_circuit_setup.path())
         return


    utils.force_symlink_dir(current_circuit_setup.path(), SETUP_DIR / "default")
    cache.upload_current_circuit_setup()

    




