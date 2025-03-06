#!/bin/bash

SCRIPT_DIR=$(dirname "$0")

install_python() {
    echo "Installing python if needed..."
    OS=$(uname -s)
    case $OS in
      Linux*)
        if command -v apt-get > /dev/null; then
          sudo apt-get update
          sudo apt-get install -y python3 
        elif command -v pacman > /dev/null; then
          sudo pacman -S --needed --noconfirm python 
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
    echo "python installation finished."
}

install_python
python3 $SCRIPT_DIR/python/main.py "$@"

