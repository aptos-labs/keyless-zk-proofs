import os
import utils
import shutil
import setups
from setups.gh_release import Releases
import zipfile

CEREMONIES_DIR = utils.resources_dir_root() / "ceremonies"

class CeremonySetup(setups.Setup): 
    def __init__(self, release_name, repo="keyless-zk-proofs", auth_token=None):
        super().__init__(CEREMONIES_DIR / release_name)
        self.release_name = release_name
        self.repo = repo
        self.auth_token = auth_token

    def download(self, witness_gen_type):
        self.mkdir()

        assets = [
                "prover_key.zkey",
                "verification_key.json",
                "circuit_config.yaml"
                ]
        if witness_gen_type == "c" or witness_gen_type == "both":
            assets += [
                    "wgen_c.zip"
                    ]

        if witness_gen_type == "wasm" or witness_gen_type == "both":
            assets += [
                    "wgen_js.zip"
                    ]

        releases = Releases(self.repo, self.auth_token)
        releases.download_and_install_release(self.release_name, self.path(), assets)

        shutil.move(self.path() / "circuit_config.yaml", self.path() / "circuit_config.yml")
    
        if witness_gen_type == "c" or witness_gen_type == "both":
            with zipfile.ZipFile(self.path() / 'wgen_c.zip', 'r') as zip_ref:
                zip_ref.extractall(self.path())
            os.remove(self.path() / "wgen_c.zip")
            os.chmod(self.path() / "main_c", 0o744)

        if witness_gen_type == "wasm" or witness_gen_type == "both":
            with zipfile.ZipFile(self.path() / 'wgen_js.zip', 'r') as zip_ref:
                zip_ref.extractall(self.path())
            shutil.move(self.path() / "main_c.wasm", self.path() / "main.wasm")
            os.remove(self.path() / "wgen_js.zip")
