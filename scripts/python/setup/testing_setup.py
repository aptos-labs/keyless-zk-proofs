from setup import cache
from datetime import datetime
import time
import shutil
import utils
import os
from pathlib import Path
import tempfile
import contextlib
import platform

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
        print("Powers-of-tau file found, skipping download.")
    else:
        print("Downloading powers-of-tau file...")
        utils.download_file(PTAU_URL, PTAU_PATH)

    print("Checking sha256sum of ptau file...")
    if utils.file_checksum(PTAU_PATH) != PTAU_CHECKSUM:
        print("WARNING: ptau file doesn't match expected sha256sum. Aborting.")
        exit(2)


def generate_c_witness_gen_binaries():
    print("Generating c witness gen binaries...")
    with tempfile.TemporaryDirectory() as temp_dir:
        with contextlib.chdir(temp_dir):
            print(temp_dir)
            shutil.copytree(utils.repo_root() / "circuit/templates", "./templates")
            with contextlib.chdir("templates"):
                print("Compiling circuit...")
                utils.manage_deps.add_cargo_to_path()
                start_time = time.time()
                utils.run_shell_command('circom -l . -l $(npm root -g) main.circom --r1cs --c')
                print("Compilation took %s seconds" % (time.time() - start_time))

                with contextlib.chdir("main_c_cpp"):
                    utils.run_shell_command("make")
                    shutil.move("main_c", current_circuit_setup_path())
                    shutil.move("main_c.dat", current_circuit_setup_path())



def c_witness_gen_present():
    (current_circuit_setup_path() / "main_c").is_file() and (current_circuit_setup_path() / "main_c.dat").is_file() 


def procure_testing_setup(ignore_cache):
    if current_circuit_setup_path().is_dir():
        print("Setup for the current circuit found. Skipping.")
        return

    prepare_setups_dir()

    download_ptau_file_if_needed()

    if not ignore_cache:
        if cache.download_testing_setup_if_present():
            if platform.machine() == 'x86_64' and not c_witness_gen_present():
                print("You're on an x86_64 machine, but the cached setup doesn't contain c witness gen binaries. Going to generate now.")
                generate_c_witness_gen_binaries()
                cache.upload_current_circuit_setup()
            utils.force_symlink_dir(current_circuit_setup_path(), SETUP_DIR / "default")
            return

    shutil.copy(utils.repo_root() / "prover-service" / "circuit_config.yml", current_circuit_setup_path())

    with tempfile.TemporaryDirectory() as temp_dir:
        with contextlib.chdir(temp_dir):
            print(temp_dir)
            shutil.copytree(utils.repo_root() / "circuit/templates", "./templates")
            with contextlib.chdir("templates"):
                print("Compiling circuit...")
                utils.manage_deps.add_cargo_to_path()
                start_time = time.time()
                utils.run_shell_command('circom -l . -l $(npm root -g) main.circom --r1cs --wasm --sym')
                print("Compilation took %s seconds" % (time.time() - start_time))
                print("Starting setup now: " + datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
                start_time = time.time()
                utils.run_shell_command(f'. ~/.nvm/nvm.sh; snarkjs groth16 setup main.r1cs {PTAU_PATH} prover_key.zkey')
                print("Running setup took %s seconds" % (time.time() - start_time))
                print("Exporting verification key...")
                utils.run_shell_command(f'snarkjs zkey export verificationkey prover_key.zkey verification_key.json')
                shutil.move("prover_key.zkey", current_circuit_setup_path())
                shutil.move("verification_key.zkey", current_circuit_setup_path())
                shutil.move("main_js/generate_witness.js", current_circuit_setup_path())
                shutil.move("main_js/witness_calculator.js", current_circuit_setup_path())
                shutil.move("main_js/main.wasm", current_circuit_setup_path())

                if platform.machine() == 'x86_64':
                    generate_c_witness_gen_binaries()
                else:
                    print("Not on x86_64, so skipping generating c witness gen binaries.")



    utils.force_symlink_dir(current_circuit_setup_path(), SETUP_DIR / "default")
    

    cache.upload_current_circuit_setup()

    




