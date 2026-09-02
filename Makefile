# tvault — see README.md
#
#   make bootstrap   one-shot setup: venv, native host, then create the vault
#
# Individual steps:
#   make setup       create .venv and install dependencies
#   make install     install the Chrome native messaging host + CLI launcher
#   make init        create the encrypted vault (prompts for a master password)
#   make path        print the line to add ~/.tvault/bin to your PATH
#   make test        unit + native-host integration tests
#   make e2e         drive the real CLI through a pty

VENV    := .venv
PY      := $(VENV)/bin/python
PYTHON  ?= python3
BIN     := $(HOME)/.tvault/bin

.PHONY: bootstrap setup install init path test e2e lint icons clean uninstall

bootstrap: setup install
	@echo
	@echo "Almost there. Two steps left:"
	@echo
	@echo "  1. make init          # create your vault"
	@echo "  2. load the extension at chrome://extensions (Load unpacked -> $(CURDIR)/extension)"
	@echo
	@$(MAKE) --no-print-directory path

$(PY):
	@echo "==> creating $(VENV)"
	@$(PYTHON) -m venv $(VENV)
	@$(PY) -m pip install --quiet --upgrade pip
	@$(PY) -m pip install --quiet -e .

setup: $(PY)
	@echo "==> dependencies installed"
	@$(PY) -c "import cryptography; print('    cryptography', cryptography.__version__)"

install: $(PY)
	@$(PY) -m tvault install-chrome

init: $(PY)
	@if [ -x "$(BIN)/tvault" ]; then "$(BIN)/tvault" init; else $(PY) -m tvault init; fi

path:
	@if echo "$$PATH" | tr ':' '\n' | grep -qx "$(BIN)"; then \
		echo "PATH already includes $(BIN)"; \
	else \
		echo "Add the CLI to your PATH:"; \
		echo "  echo 'export PATH=\"\$$HOME/.tvault/bin:\$$PATH\"' >> ~/.zshrc && exec zsh"; \
	fi

test: $(PY)
	@$(PY) -m unittest discover -s tests -v

e2e: $(PY)
	@$(PY) tests/e2e_cli.py

lint: $(PY)
	@$(PY) -m pip install --quiet pyflakes
	@$(PY) -m pyflakes tvault scripts tests && echo "pyflakes: clean"

icons: $(PY)
	@$(PY) scripts/genicons.py

uninstall: $(PY)
	@$(PY) -m tvault uninstall-chrome

clean:
	@find . -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true
	@echo "removed __pycache__ (the vault in ~/.tvault is untouched)"
