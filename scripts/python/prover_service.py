from utils import manage_deps
import utils
import typer

app = typer.Typer(no_args_is_help=True)

@app.command()
def install_deps():
    """install the dependencies for building and running the prover service."""
    manage_deps.install_deps(["pkg-config", "lld", "meson", "rust", "clang", "cmake", "make", "libyaml", "nasm", "gmp", "openssl"])
    
@app.command()
def add_envvars_to_profile():
    """Add the directory containing libtbb to LD_LIBRARY_PATH. Required for running the prover service and for running the prover service tests."""
    path = utils.repo_root() / "rust-rapidsnark/rapidsnark/build/subprojects/oneTBB-2022.0.0"
    utils.add_envvar_to_profile("LD_LIBRARY_PATH", "$LD_LIBRARY_PATH:" + str(path))
    utils.add_envvar_to_profile("DYLD_LIBRARY_PATH", "$DYLD_LIBRARY_PATH:" + str(path))
