import subprocess
import sys
from utils import eprint
import utils
import platform
import shutil
import os

def install_nvm():
    """Install NVM (Node Version Manager)."""
    utils.download_and_run_shell_script("https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.1/install.sh")

def install_node():
    """Install nvm, and then use it to install nodejs."""
    eprint("Installing node")
    install_nvm()
    utils.run_shell_command(". ~/.nvm/nvm.sh; nvm install node")
    eprint("Installation of node succeeded")

def install_circom():
    eprint("Installing circom")
    # de2212a7aa6a070c636cc73382a3deba8c658ad5 fixes a bug related to tag propagation
    # TODO: replace to v2.2.3 once released (because v2.2.2 has a bug related to tags, which we want to use)
    utils.cargo_install_from_git("https://github.com/iden3/circom", "de2212a7aa6a070c636cc73382a3deba8c658ad5")
    eprint("Installation of circom succeeded")

def install_circomlib():
    eprint("Installing circomlib")
    install_npm_package("circomlib@2.0.5")
    eprint("Installation of circomlib succeeded")

def install_snarkjs():
    eprint("Installing snarkjs")
    install_npm_package("snarkjs@0.7.5")
    eprint("Installation of snarkjs succeeded")

def install_rust():
    eprint("Checking for rustup...")
    if shutil.which("rustup"):
        eprint("Rustup installed.")
    else:
        eprint("Rustup not installed, installing...")
        utils.download_and_run_shell_script_with_opts(
                "https://sh.rustup.rs",
                "-y --default-toolchain stable"
                )
        eprint("Installation of rustup succeeded. Setting path environment variable...")

        add_cargo_to_path()

        eprint("Done.")


def add_cargo_to_path():
    if "CARGO_HOME" in os.environ:
        utils.add_envvar_to_profile("PATH", "$PATH:" + os.environ["CARGO_HOME"] + "/bin")
        os.environ['PATH'] += ":" + os.environ["CARGO_HOME"] + "/bin"
    else:
        utils.add_envvar_to_profile("PATH", "$PATH:" + os.path.expanduser("~/.cargo/bin"))
        os.environ['PATH'] += ":" + os.path.expanduser("~/.cargo/bin")

def install_npm_package(package):
    utils.run_shell_command(". ~/.nvm/nvm.sh; npm install -g " + package)

def platform_package_manager():
    if platform.system() == 'Linux':
        if shutil.which("apt-get"):
            return "apt-get"
        elif shutil.which("pacman"):
            return "pacman"
        else:
            eprint("Couldn't find a package manager. On linux, this script currently only supports apt-get (debian and ubuntu) and pacman (arch linux).")
            exit(2)
    elif platform.system() == 'Darwin':
        if shutil.which("brew"):
            return "brew"
        else:
            eprint("Couldn't find a package manager. On macos, this script requires brew. Please install it.")
            exit(2)
    else:
        eprint("System type " + platform.system() + " is not supported. This script currently only supports macos and linux.")
        exit(2)

    return "brew"


def run_platform_package_manager_command(package):
    package_manager = platform_package_manager()
    try:
        if package_manager == "brew":
            utils.run_shell_command("brew install " + package)
        elif package_manager == "pacman":
            utils.run_shell_command("pacman -S --needed --noconfirm " + package, as_root=True)
        elif package_manager == "apt-get":
            utils.run_shell_command("apt-get update", as_root=True)
            utils.run_shell_command("apt-get install -y " + package, as_root=True)
    except Exception as e:
        eprint("Installing " + package + " failed. Exception: ")
        eprint(e)
        eprint("Exiting.")
        exit(2)


def install_using_package_manager(name, package):
    eprint("Installing " + name)

    # package is either ...
    if type(package) is str:
        # ... a string, which means the package name is consistent across
        # all supported platforms, or ...
        run_platform_package_manager_command(package)
    elif type(package) is dict:
        # ... a dict, which specifies a platform-specific package name.
        if platform_package_manager() not in package:
            eprint("Don't know a way to install package " + package + " on the current distribution.")
            exit(2)
        platform_specific_package = package[platform_package_manager()]
        if platform_specific_package is None:
            # Sometimes a specific platform doesn't need to install the package, 
            # e.g. if it is already installed by default on this platform. We 
            # represent this by specifying None for this platform.
            eprint("The current system doesn't need to install " + name + ".")
        else:
            run_platform_package_manager_command(platform_specific_package)

    eprint("Done installing " + name)


# This dict defines the installation behavior for each dependency.
# - If dict[dep] is a function, calling that function should install the dep.
# - If dict[dep] is a string, this string is a package name which should be installed using
#   the system package manager.
# - If dict[dep] is a dict, this means that different platorm package managers have different
#   names for this dep, and the dict contains these platform-specific names.
deps_by_platform = {
        "node": install_node,
        "circom": install_circom,
        "circomlib": install_circomlib,
        "snarkjs": install_snarkjs,
        "meson": "meson",
        "rust": install_rust,
        "pkg-config": "pkg-config",
        "cmake": "cmake",
        "make": "make",
        "clang": {
            "brew": None,
            "pacman": "clang",
            "apt-get": "clang"
            },
        "nasm": "nasm",
        "lld": {
            "brew": None,
            "pacman": "lld",
            "apt-get": "lld"
            },
        "libyaml": {
            "brew": "libyaml",
            "pacman": "libyaml",
            "apt-get": "libyaml-dev"
            },
        "gmp": {
            "brew": "gmp",
            "pacman": "gmp",
            "apt-get": "libgmp-dev"
            },
        "openssl": {
            "brew": None,
            "pacman": "openssl",
            "apt-get": "libssl-dev"
            },
        "nlohmann-json": {
            "brew": "nlohmann-json",
            "pacman": "nlohmann-json",
            "apt-get": "nlohmann-json3-dev"
            }
        }


def install_dep(dep):
    if dep not in deps_by_platform:
        eprint("Dependency " + dep + " not recognized.")
        exit(2)
    handler = deps_by_platform[dep]

    # deps_by_platform[dep] is either ...
    if callable(handler):
        # ... a function, which means calling it should install the dep ...
        handler()
    else:
        # ... or is a string or dict specifying a name that the system package
        # manager should use to install the package. In that case, use the system
        # package manager.
        install_using_package_manager(dep, handler)


def install_deps(deps):
    for dep in deps:
        install_dep(dep)
