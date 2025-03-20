from utils import manage_deps
import utils
from invoke import task

@task
def install_deps(c):
    """install the dependencies for building and running the prover service."""
    manage_deps.install_deps(["pkg-config", "lld", "meson", "rust", "clang", "cmake", "make", "libyaml", "nasm", "gmp", "openssl"])
    
@task
def add_envvars_to_profile(c):
    """Add the directory containing libtbb to LD_LIBRARY_PATH. Required for running the prover service and for running the prover service tests."""
    path = utils.repo_root() / "rust-rapidsnark/rapidsnark/build/subprojects/oneTBB-2022.0.0"
    utils.add_envvar_to_profile("LD_LIBRARY_PATH", "$LD_LIBRARY_PATH:" + str(path))
    utils.add_envvar_to_profile("DYLD_LIBRARY_PATH", "$DYLD_LIBRARY_PATH:" + str(path))
