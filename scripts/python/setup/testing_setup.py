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

def repo_circuit_setup_path():
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
                    eprint("Compiling c witness generation binaries now: " + datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
                    start_time = time.time()
                    utils.run_shell_command("make")
                    shutil.move("main_c", repo_circuit_setup_path() / "main_c" )
                    shutil.move("main_c.dat", repo_circuit_setup_path() / "main_c.dat" )
                    eprint("Witness gen compilation took %s seconds" % (time.time() - start_time))

# idea: break into tasks that are "checkable"
# i.e., compile produces artifacts, just check if artifacts are already there in target dir
# every task happens in new tempdir

def procure_testing_setup(ignore_cache):
    # TODO should upload setup if it's not in gcs, even if it already exists locally
    repo_circuit_setup = Setup(repo_circuit_setup_path())
    if repo_circuit_setup.is_complete():
        eprint("Setup for the current circuit found.")
        if platform.machine() == 'x86_64' and not repo_circuit_setup.witness_gen_c():
            eprint("You're on an x86_64 machine, but the cached setup doesn't contain c witness gen binaries. Going to generate now.")
            generate_c_witness_gen_binaries()
            cache.upload_current_circuit_setup()
        elif not cache.current_circuit_blob_exists():
            eprint("Setup is not in cache, going to upload.")
            cache.upload_current_circuit_setup()
        repo_circuit_setup.set_current()
        return
    else:
        eprint("prover key: " + str(repo_circuit_setup.prover_key()))
        eprint("verification key: " + str(repo_circuit_setup.verification_key()))
        eprint("circuit config: " + str(repo_circuit_setup.circuit_config()))
        eprint("witness gen c: " + str(repo_circuit_setup.witness_gen_c()))
        eprint("witness gen wasm: " + str(repo_circuit_setup.witness_gen_wasm()))

    prepare_setups_dir()


    if not ignore_cache:
        if cache.download_testing_setup_if_present():
            if not repo_circuit_setup.is_complete():
                eprint("ERROR: setup downloaded from cloud has missing files. Aborting.")
                exit(2)
            if platform.machine() == 'x86_64' and not repo_circuit_setup.witness_gen_c():
                eprint("You're on an x86_64 machine, but the cached setup doesn't contain c witness gen binaries. Going to generate now.")
                generate_c_witness_gen_binaries()
                cache.upload_current_circuit_setup()
            repo_circuit_setup.set_current()
            return

    download_ptau_file_if_needed()

    repo_circuit_setup.mkdir()
    shutil.copy(utils.repo_root() / "prover-service" / "circuit_config.yml", repo_circuit_setup.path())

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

                
                shutil.move("prover_key.zkey", repo_circuit_setup.path())
                shutil.move("verification_key.json", repo_circuit_setup.path())
                shutil.move("main_js/generate_witness.js", repo_circuit_setup.path())
                shutil.move("main_js/witness_calculator.js", repo_circuit_setup.path())
                shutil.move("main_js/main.wasm", repo_circuit_setup.path())

                if platform.machine() == 'x86_64':
                    generate_c_witness_gen_binaries()
                else:
                     eprint("Not on x86_64, so skipping generating c witness gen binaries.")

    if not repo_circuit_setup.is_complete():
         eprint("ERROR: Circuit setup is not complete. Check the path below for problems.")
         eprint(repo_circuit_setup.path())
         return


    repo_circuit_setup.set_current()
    cache.upload_current_circuit_setup()

    




