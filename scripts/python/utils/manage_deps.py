
def install_node():
    print("placeholder: installing node")

def install_circom():
    print("placeholder: installing circom")

def install_circomlib():
    print("placeholder: installing circomlib")

def install_snarkjs():
    print("placeholder: installing snarkjs")

def platform_package_manager():
    return "brew"

def install_using_package_manager(name, package):
    print("Installing " + name)

    

    print("Done installing " + name)



dep_by_platform = {
        "node": install_node,
        "circom": install_circom,
        "circomlib": install_circomlib,
        "snarkjs": install_snarkjs,
        "meson": "meson",
        "cmake": "cmake",
        "make": "make",
        "clang": "clang",
        "nasm": "nasm",
        "lld": {
            "brew": None,
            "pacman": "lld",
            "apt-get": "lld",
            },
        "libyaml": {
            "brew": "libyaml",
            "pacman": "libyaml",
            "apt-get": "libyaml-dev",
            }
        "gmp": {
            "brew": "gmp",
            "pacman": "gmp",
            "apt-get": "libgmp-dev",
            }
        "openssl": {
            "brew": None,
            "pacman": "openssl",
            "apt-get": "libssl-dev",
            }
        }


