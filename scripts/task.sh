#!/bin/bash

set -e

SCRIPT_DIR=$(dirname "$0")

install_deps() {
  echo "Bootstrap: checking for python, pipx, curl and invoke..."
  if ! command -v python3 > /dev/null || ! command -v curl > /dev/null || ! ( command -v invoke > /dev/null || /bin/ls ~/.local/bin/invoke > /dev/null ); then
    echo "Dependencies not all found, installing..."
    OS=$(uname -s)
    case $OS in
      Linux*)
        if command -v apt-get > /dev/null; then
          if command -v sudo > /dev/null; then
            sudo apt-get update
            sudo apt-get install -y python3 python3-pip pipx curl
            pipx install invoke
          else
            apt-get update
            apt-get install -y python3 python3-pip pipx curl
            pipx install invoke
          fi
        elif command -v pacman > /dev/null; then
          if command -v sudo > /dev/null; then
            sudo pacman -Syu --noconfirm
            sudo pacman -S --needed --noconfirm python python-pip python-pipx curl
            pipx install invoke
          else
            pacman -Syu --noconfirm
            pacman -S --needed --noconfirm python python-pip python-pipx curl
            pipx install invoke
          fi
        else
          echo "No suitable package manager found for Linux."
        fi
        ;;
      Darwin*)
        if command -v brew > /dev/null; then
          brew install python
          pipx install invoke
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


python3 $SCRIPT_DIR/python/main.py "$@"


