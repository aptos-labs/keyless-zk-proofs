from utils import eprint
import utils
import shutil
import typer

app = typer.Typer(no_args_is_help=True)

def current_setups_dir():
    return utils.resources_dir_root() / "current_setups"

class Setup:
    def __init__(self, root_dir):
        self.root_dir = root_dir

    def path(self):
        return self.root_dir

    def rm(self):
        shutil.rmtree(self.root_dir)

    def set_current(self):
        current_setups_dir().mkdir(parents=True, exist_ok=True)
        utils.force_symlink_dir(self.root_dir, current_setups_dir() / "default")
        utils.force_symlink_dir(self.root_dir, current_setups_dir() / "new")

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



from setups.ceremony_setup import CeremonySetup
from setups.testing_setup import TestingSetup



@app.command()
def download_ceremonies_for_releases(default_release, new_release, witness_gen_type='none'):
    """Download two ceremonies corresponding to `default` and `new` in the prover service, installing in RESOURCES_DIR. If RESOURCES_DIR is not set, uses the default location `~/.local/share/aptos-keyless`."""

    eprint("Deleting old ceremonies...")
    utils.delete_contents_of_dir(ceremony_setup.CEREMONIES_DIR)
    

    default_ceremony = CeremonySetup(default_release)
    new_ceremony = CeremonySetup(new_release)

    try:
        eprint("Downloading default ceremony...")
        default_ceremony.download(witness_gen_type)
        eprint("Downloading new ceremony...")
        new_ceremony.download(witness_gen_type)
        eprint("Finished downloading ceremonies.")
    except gh_release.ReleaseNotFound as rnf:
        eprint("ERROR: Release \"" + rnf.release_name + "\" not found.")
    except gh_release.ReleaseMissingRequiredAsset as ma:
        eprint("ERROR: Release \"" + ma.release_name + "\" is missing required asset \"" + ma.required_asset + "\".")





@app.command()
def procure_testing_setup(ignore_cache=False):
    """Get a (untrusted) setup corresponding to the current circuit in this repo for testing purposes. Assuming you are authenticated with gcloud cli, will attempt to load from the cache in google cloud storage. If you are not authenticated, or if a relevant setup doesn't yet exist, will generate a setup locally and attempt to upload to the cache."""


    testing_setup = TestingSetup()
    testing_setup.procure()



