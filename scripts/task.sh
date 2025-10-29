#!/bin/bash

set -ex

SCRIPT_DIR=$(dirname "$0")

# Installs rustup if not already installed
function install_rustup {
  VERSION="$(rustup --version || true)"
  if [ -n "$VERSION" ]; then
    if [[ "${BATCH_MODE}" == "false" ]]; then
      echo "Rustup is already installed, version: $VERSION"
    fi
  else
    curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain stable
    if [[ -n "${CARGO_HOME}" ]]; then
      PATH="${CARGO_HOME}/bin:${PATH}"
    else
      PATH="${HOME}/.cargo/bin:${PATH}"
    fi
  fi
}

# Installs cargo-machete if not already installed
function install_cargo_machete {
  if ! command -v cargo-machete &>/dev/null; then
    cargo install cargo-machete --locked --version 0.7.0
  fi
}

# Installs cargo-sort if not already installed
function install_cargo_sort {
  if ! command -v cargo-sort &>/dev/null; then
    cargo install cargo-sort --locked --version 1.0.7
  fi
}

# Installs necessary dependencies
install_deps() {
  # Install python3 and curl if not present
  if ! command -v python3 > /dev/null || ! command -v curl > /dev/null; then
    OS=$(uname -s)
    case $OS in
      Linux*)
        if command -v apt-get > /dev/null; then
          if command -v sudo > /dev/null; then
            sudo apt-get update
            sudo apt-get install -y python3 python3-pip pipx curl
          else
            apt-get update
            apt-get install -y python3 python3-pip pipx curl
          fi
        elif command -v pacman > /dev/null; then
          if command -v sudo > /dev/null; then
            sudo pacman -Syu --noconfirm
            sudo pacman -S --needed --noconfirm python python-pip python-pipx curl
            pipx install invoke
          else
            pacman -Syu --noconfirm
            pacman -S --needed --noconfirm python python-pip python-pipx curl
          fi
        else
          >&2 echo "No suitable package manager found for Linux."
        fi
        ;;
      Darwin*)
        if command -v brew > /dev/null; then
          brew install python
        else
          >&2 echo "Homebrew is not installed. Install Homebrew to use this."
        fi
        ;;
      *)
        >&2 echo "Unsupported OS: $OS"
        ;;
    esac
    >&2 echo "Dependencies installation finished."
  fi

  # Install rustup
  install_rustup

  # Install cargo dependency tools
  install_cargo_machete
  install_cargo_sort
}

install_deps

if ! ls .venv &> /dev/null; then
  python3 -m venv .venv
fi
if ! .venv/bin/pip3 show google-cloud-storage typer &> /dev/null;  then
  .venv/bin/pip3 install google-cloud-storage typer &> /dev/null
fi

.venv/bin/python3 $SCRIPT_DIR/python/main.py "$@"


