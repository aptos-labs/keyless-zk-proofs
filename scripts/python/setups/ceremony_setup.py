import os
import utils
import setups
from setups.gh_release import Releases

CEREMONIES_DIR = utils.resources_dir_root() / "ceremonies"

class CeremonySetup(setups.Setup): 
    def __init__(self, release_name):
        super().__init__(CEREMONIES_DIR / release_name)
        self.release_name = release_name


    def download(self, witness_gen_type):
        self.mkdir()

        assets = [
                "prover_key.zkey",
                "verification_key.json",
                "circuit_config.yml"
                ]
        if witness_gen_type == "c" or witness_gen_type == "both":
            assets += [
                    "main_c",
                    "main_c.dat"
                    ]

        if witness_gen_type == "wasm" or witness_gen_type == "both":
            assets += [
                    "generate_witness.js",
                    "witness_calculator.js",
                    "main.wasm"
                    ]

        releases = Releases()
        releases.download_and_install_release(release_name, self.path(), assets)


