from utils import eprint
import utils
import shutil
import typer
from typing_extensions import Annotated

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

    def set_default(self):
        current_setups_dir().mkdir(parents=True, exist_ok=True)
        utils.force_symlink_dir(self.root_dir, current_setups_dir() / "default")

    def set_new(self):
        current_setups_dir().mkdir(parents=True, exist_ok=True)
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
def download_ceremonies_for_releases(release_tag,
                                     repo: Annotated[str, typer.Option(help="A keyless-zk-proofs fork.")]='keyless-zk-proofs',
                                     witness_gen_type: Annotated[str, typer.Option(help="If set to 'wasm', 'c', or 'both', downloads the corresponding witness gen binaries.")]='none',
                                     auth_token: Annotated[str, typer.Option(help="Auth token to provide for the github API. Not necessary for normal use, but used during GH actions to avoid rate-limiting.")]=None):
    """Download the assets of a circuit release and install them in the correct place so that running `cargo test -p prover-service` will use this setup."""
    eprint("Deleting old ceremonies...")
    utils.delete_contents_of_dir(ceremony_setup.CEREMONIES_DIR)
    ceremony = CeremonySetup(release_tag, repo, auth_token)
    eprint("Downloading default ceremony...")
    ceremony.download(witness_gen_type)
    eprint("Finished downloading ceremonies.")
    ceremony.set_default()


@app.command()
def procure_testing_setup(ignore_cache=typer.Option(False, help="Build the setup from scratch regardless of whether it exists in the GCS cache.")):
    """
    Procure a (untrusted) setup corresponding to the current circuit in this repo for testing purposes. 

    Specifically, does the following:

    - Computes a hash of the circuit currently in the repo.

      - Note that currently this hash is computed from the circuit *source code*, not the R1CS file. This is because compiling the circuit itself takes a minute, and I don't want to wait one minute just to obtain an identifier for the circuit

    - Checks a google cloud storage GCS bucket (refer to this as the "cache" from now on) whether there is already a setup for this circuit.

    - If present in the cache, downloads it.

      - If the downloaded setup was built on an arm machine, it won't contain the C witness gen binaries. If the local machine is an x86-64 machine and the downloaded setup does not contain them, the script will build these C binaries and re-upload the setup.

    - If not present, compiles the circuit and witness gen binaries and runs a local (1-person) setup.

    - Installs the setup in the correct location, so that running `cargo test -p prover-service` will use this setup.
    
    - Uploads the setup to the cloud.

    ## Note:

    Right now, the GCS bucket requires being authenticated to GC with an Aptos account to use, since Stelian has not yet provided us with a bucket that allows for unauthenticated read access. So if you try to run this action without running `gcloud auth login --update-adc`, the script builds the setup locally and does not upload to the cache.
    """


    testing_setup = TestingSetup()
    testing_setup.procure()



