#! /bin/bash

# Set installation mode
# ---------------------------------------------------------------------------- #
if [ "$#" -eq 1 ] && [ "$1" == "local" ];
then
    echo "[+] BARF: Local installation..."
    # Install solvers
    # ------------------------------------------------------------------------ #
    ./install-solvers.sh local

    # Install Capstone
    # ------------------------------------------------------------------------ #
    temp_dir=dependencies

    rm -rf $temp_dir
    mkdir $temp_dir
    cd $temp_dir

    CAPSTONE_DOWNLOAD_URL="https://pypi.python.org/packages/source/c/capstone/capstone-3.0.4.tar.gz"

    wget $CAPSTONE_DOWNLOAD_URL
    tar xfz capstone-3.0.4.tar.gz
    rm -f capstone-3.0.4.tar.gz

    cd capstone-3.0.4/
    python setup.py install --user

    cd ../..
    rm -rf $temp_dir

    # Install BARF
    # ------------------------------------------------------------------------ #
    python setup.py install --user
else
    echo "[+] BARF: System installation..."
    # Install solvers
    # ------------------------------------------------------------------------ #
    ./install-solvers.sh

    # Install BARF
    # ------------------------------------------------------------------------ #
    sudo python setup.py install
fi
