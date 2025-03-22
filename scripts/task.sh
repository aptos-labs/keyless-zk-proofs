#!/bin/bash

set -e

SCRIPT_DIR=$(dirname "$0")

install_deps() {
  echo "Bootstrap: checking for python, pipx, curl and invoke..."
  if ! command -v python3 > /dev/null || ! command -v curl > /dev/null; then
    echo "Dependencies not all found, installing..."
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
          echo "No suitable package manager found for Linux."
        fi
        ;;
      Darwin*)
        if command -v brew > /dev/null; then
          brew install python
        else
          echo "Homebrew is not installed. Install Homebrew to use this."
        fi
        ;;
      *)
        echo "Unsupported OS: $OS"
        ;;
    esac
    echo "Dependencies installation finished."
  else
    echo "All dependencies found. Running script."
  fi
}

install_deps

if ! ls .venv 2>&1 > /dev/null; then
  python3 -m venv .venv
fi
if ! .venv/bin/pip3 show google-cloud-storage typer > /dev/null;  then
  .venv/bin/pip3 install google-cloud-storage typer > /dev/null
fi

.venv/bin/python3 $SCRIPT_DIR/python/main.py "$@"


