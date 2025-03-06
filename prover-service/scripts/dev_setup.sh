#!/bin/bash

set -e


function add_to_profile_file {
  eval "$1"
  FOUND=$(grep -c "$1" <"${HOME}/$2" || true) # grep error return would kill the script.
  if [ "$FOUND" == "0" ]; then
    echo "$1" >>"${HOME}/$2"
    echo "Added '$1' to your profile ${HOME}/$2. Please restart your shell."
  fi
}

function add_to_profile {
  if [ "$SHELL" == "/bin/zsh" ]; then
    add_to_profile_file "$1" ".zprofile"
  elif [ "$SHELL" == "/bin/bash" ]; then
    add_to_profile_file "$1" ".profile"
  else
    echo "Couldn't detect the type of shell you are using. Please add the equivalent of this line to your shell:"
    echo $1
  fi
}


PACKAGE_MANAGER=
if [[ "$(uname)" == "Linux" ]]; then
  if command -v yum &>/dev/null; then
    PACKAGE_MANAGER="yum"
  elif command -v apt-get &>/dev/null; then
    PACKAGE_MANAGER="apt-get"
  elif command -v pacman &>/dev/null; then
    PACKAGE_MANAGER="pacman"
  elif command -v apk &>/dev/null; then
    PACKAGE_MANAGER="apk"
  elif command -v dnf &>/dev/null; then
    echo "WARNING: dnf package manager support is experimental"
    PACKAGE_MANAGER="dnf"
  else
    echo "Unable to find supported package manager (yum, apt-get, dnf, or pacman). Abort"
    exit 1
  fi
elif [[ "$(uname)" == "Darwin" ]]; then
  if command -v brew &>/dev/null; then
    PACKAGE_MANAGER="brew"
  else
    echo "Missing package manager Homebrew (https://brew.sh/). Abort"
    exit 1
  fi
else
  echo "Unknown OS. Abort."
  exit 1
fi



function install_rustup {

  # Install Rust
    echo "Installing Rust......"
  VERSION="$(rustup --version || true)"
  if [ -n "$VERSION" ]; then
      echo "Rustup is already installed, version: $VERSION"
  else
    curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain stable
    if [[ -n "${CARGO_HOME}" ]]; then
      PATH="${CARGO_HOME}/bin:${PATH}"
    else
      PATH="${HOME}/.cargo/bin:${PATH}"
    fi
  fi
}

if [[ $PACKAGE_MANAGER == "apt-get" ]]; then 
  sudo apt-get update
  sudo apt-get install -y pkg-config lld meson clang cmake make libyaml-dev nasm libgmp-dev libssl-dev
elif [[ $PACKAGE_MANAGER == "brew" ]]; then 
  brew install cmake meson libyaml nasm gmp
elif [[ $PACKAGE_MANAGER == "pacman" ]]; then 
  sudo pacman -S --needed pkg-config meson lld clang cmake make libyaml nasm gmp openssl
else
  echo "Unsupported platform. Currently this script only supports Arch, Ubuntu, Debian and macOS."
  exit 1
fi

install_rustup 

SCRIPT_DIR="$(pwd)"
add_to_profile "export DYLD_LIBRARY_PATH=\$DYLD_LIBRARY_PATH:$SCRIPT_DIR/rust-rapidsnark/rapidsnark/build/subprojects/oneTBB-2022.0.0"
add_to_profile "export LD_LIBRARY_PATH=\$LD_LIBRARY_PATH:$SCRIPT_DIR/rust-rapidsnark/rapidsnark/build/subprojects/oneTBB-2022.0.0"
