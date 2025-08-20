#!/usr/bin/sh

git clone https://github.com/Homebrew/brew homebrew

eval "$(homebrew/bin/brew shellenv)"
brew update --force --quiet
chmod -R go-w "$(brew --prefix)/share/zsh"

brew install ollama

OLLAMA_DEBUG=DEBUG OLLAMA_ORIGINS="*" OLLAMA_HOST=0.0.0.0:$PORT ollama serve

#./app
