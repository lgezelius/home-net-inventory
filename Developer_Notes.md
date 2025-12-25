# Developer Notes

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

Tests are in the /tests folder. To configure VS Code to run tests do the following:

- Press ⌘⇧P and type "Python: Configure Tests"
- Choose:
  - pytest (pytest framework)
  - directory containing the tests: tests

## Tests

To run test from the shell. First create a virtual environment (.venv) and then run:

    pytest -q

### Coverage Reports

First install coverage, if that hasn't be done before.

    pip install coverage # if not already installed

Now run the run and view the coverage report in the shell.

    coverage run -m pytest
    coverage report -m

Or run and view the coverage report in a browser.

    coverage html
    open htmlcov/index.html

## Make

The pyproject.toml engines optional dependencies for development / CI.

- Developers / CI

        pip install -e '.[dev]'
        make test
        make cov

- Production / Docker

        pip install .
