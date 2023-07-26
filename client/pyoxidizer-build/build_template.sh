#!/bin/bash
# -*- coding: UTF8 -*-

python3 -m pip install pyoxidizer

# symblinks don't work with the build, so let's copy important files
cp -r ../../pupy/agent lib/pupy/
cp -r ../../pupy/network lib/pupy/

pyoxidizer build --release
cp ./build/x86_64-unknown-linux-gnu/release/install/pyoxydizer_pupy ~/.pupy/payload_templates/pupyx86-310.lin

