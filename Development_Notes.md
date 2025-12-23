# Development Notes

## Created a virtual environment for testing

Go to the repo root.

    cd ~/Development/home-net-inventory

 Tell pyenv to use the system installed version of Python. (For me, this was the brew-installed version 3.14.0.) This creates a file named .python-version with the contents of "system". This file should be committed to git.

    pyenv local system

Create a virtual environment named .venv.

    python3 -m venv .venv
    source .venv/bin/activate
    pip install -U pip
    pip install -e .

Confirm that the bottom status bar shows that the virtual environment with the correct version is displayed when editing a Python file.

Running "pip install -e ." created a home_net_inventory.egg-info directory. This directory should not be committed to git.
