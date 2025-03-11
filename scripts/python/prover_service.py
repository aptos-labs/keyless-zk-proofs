from utils import manage_deps
import utils

def install_deps():
    manage_deps.install_deps(["pkg-config", "lld", "meson", "rust", "clang", "cmake", "make", "libyaml", "nasm", "gmp", "openssl"])
    
def add_envvars_to_profile():
    path = utils.repo_root() + "/rust-rapidsnark/rapidsnark/build/subprojects/oneTBB-2022.0.0"
    utils.add_envvar_to_profile("LD_LIBRARY_PATH", "$LD_LIBRARY_PATH:" + path)
    utils.add_envvar_to_profile("DYLD_LIBRARY_PATH", "$DYLD_LIBRARY_PATH:" + path)
