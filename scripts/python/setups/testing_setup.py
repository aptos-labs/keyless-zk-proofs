from setups import cache
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
import setups

# "Constants" (i.e., fixed for duration of execution)
PTAU_PATH=utils.resources_dir_root() / "powersOfTau28_hez_final_21.ptau"
PTAU_URL="https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_21.ptau"
PTAU_CHECKSUM="cdc7c94a6635bc91466d8c7d96faefe1d17ecc98a3596a748ca1e6c895f8c2b4"
TESTING_SETUPS_DIR=utils.resources_dir_root() / "testing_setups"





def repo_circuit_checksum():
    return utils.directory_checksum(utils.repo_root() / "circuit/templates", ".circom")

def repo_circuit_setup_path():
    return TESTING_SETUPS_DIR / repo_circuit_checksum()

def require_ptau_file():
    if PTAU_PATH.is_file():
        eprint("Powers-of-tau file found at " + str(PTAU_PATH) + ", skipping download.")
    else:
        eprint("Downloading powers-of-tau file... (destination: " + str(PTAU_PATH) + ")")
        utils.download_file(PTAU_URL, PTAU_PATH)
        eprint("Finished downloading to " + str(PTAU_PATH) + ".")

    eprint("Checking sha256sum of ptau file...")
    if utils.file_checksum(PTAU_PATH) != PTAU_CHECKSUM:
        eprint("WARNING: ptau file at " + str(PTAU_PATH) + " doesn't match expected sha256sum. Aborting.")
        exit(2)

class TestingSetup(setups.Setup):
    def __init__(self):
        super().__init__(repo_circuit_setup_path())
        self._checksum = repo_circuit_checksum()


    def checksum(self):
        return self._checksum


    def compile_circuit(self):
        eprint("Compiling circuit...")
        shutil.copytree(utils.repo_root() / "circuit/templates", "./", dirs_exist_ok=True)
        utils.manage_deps.add_cargo_to_path()
        start_time = time.time()
        utils.run_shell_command('circom -l . -l $(. ~/.nvm/nvm.sh; npm root -g) main.circom --r1cs --wasm --c --sym')
        eprint("Compilation took %s seconds" % (time.time() - start_time))


    def run_setup(self):
        eprint("Starting setup now: " + datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        start_time = time.time()
        utils.run_shell_command(f'. ~/.nvm/nvm.sh; snarkjs groth16 setup main_c.r1cs {PTAU_PATH} prover_key.zkey')
        eprint("Running setup took %s seconds" % (time.time() - start_time))
        eprint("Exporting verification key...")
        utils.run_shell_command(f'snarkjs zkey export verificationkey prover_key.zkey verification_key.json')


    def compile_c_witness_gen_binaries(self):
        with contextlib.chdir("main_c_cpp"):
            eprint("Compiling c witness generation binaries now: " 
                   + datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            start_time = time.time()
            utils.run_shell_command("make")
            eprint("Witness gen compilation took %s seconds" % (time.time() - start_time))


    def install_artifacts(self):
        shutil.copy(utils.repo_root() / "prover-service" / "circuit_config.yml", self.path())
        shutil.move("prover_key.zkey", self.path())
        shutil.move("verification_key.json", self.path())
        shutil.move("main_c_js/generate_witness.js", self.path())
        shutil.move("main_c_js/witness_calculator.js", self.path())
        shutil.move("main_c_js/main_c.wasm", self.path() / "main.wasm")
        if platform.machine() == 'x86_64':
            shutil.move("main_c_cpp/main_c", self.path())
            shutil.move("main_c_cpp/main_c.dat", self.path())


    def c_witness_gen_from_scratch():
        eprint("Setup doesn't contain c witness gen binaries, and you are on x86-64. Going to compile them now.")
        with tempfile.TemporaryDirectory() as temp_dir:
            with contextlib.chdir(temp_dir):
                self.compile_circuit()
                self.compile_c_witness_gen_binaries()
                shutil.move("main_c_cpp/main_c", self.path())
                shutil.move("main_c_cpp/main_c.dat", self.path())


    def procure(self, ignore_cache=False):
        if self.is_complete():
            eprint("Setup for the current circuit found.")
            if platform.machine() == 'x86_64' and not self.witness_gen_c():
                self.c_witness_gen_from_scratch()
        else:
            if not ignore_cache and cache.download_blob_if_present(self.checksum(), TESTING_SETUPS_DIR) and self.is_complete():
                if platform.machine() == 'x86_64' and not self.witness_gen_c():
                    self.c_witness_gen_from_scratch()
            else:
                eprint("Deleting old testing setups...")
                utils.delete_contents_of_dir(TESTING_SETUPS_DIR)
                require_ptau_file()
                self.mkdir()

                with tempfile.TemporaryDirectory() as temp_dir:
                    with contextlib.chdir(temp_dir):
                        self.compile_circuit()
                        self.run_setup()
                        if platform.machine() == 'x86_64':
                            self.compile_c_witness_gen_binaries()
                        else:
                             eprint("Not on x86_64, so skipping generating c witness gen binaries.")
                        self.install_artifacts()


        
        if self.is_complete():
            self.set_default()
            self.set_new()
            if not cache.blob_exists(self.checksum()):
                eprint("Setup is not in cache, going to upload.")
                cache.upload_to_blob(self.checksum(), self.path())
        else:
            eprint("ERROR: Setup is missing required files. Something must have gone wrong. Check " + self.path() + ".")

                





