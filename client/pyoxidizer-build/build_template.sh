#!/bin/bash
# -*- coding: UTF8 -*-

python3 -m pip install pyoxidizer

# so let's copy important files necessary for the build
cp -r ../../pupy/agent lib/pupy/
cp -r ../../pupy/network lib/pupy/
cp -r ../../pupy/library_patches_py3 .

docker run -ti -v $(pwd):/pupy --rm n1nj4sec/pyoxidizer-builder:linux-x86_64 /bin/bash -c 'export PATH="/build/python/bin:$PATH"; cd /pupy; python3 -m pip install pyoxidizer; pyoxidizer build --release'

strip -s build/x86_64-unknown-linux-gnu/release/install/pyoxydizer_pupy
echo "saving built template to ~/.pupy/payload_templates/ ..."
mkdir -p ~/.pupy/payload_templates
cp ./build/x86_64-unknown-linux-gnu/release/install/pyoxydizer_pupy ~/.pupy/payload_templates/pupyx86-310.lin


# not working, missing msvc on windows
#docker run --rm -v $(pwd):/opt/win/drive_c/tools/pupy -ti wine 'set PATH=%PATH%;C:\\Program Files\\PyOxidizer && C: && cd C:\\tools\\pupy && pyoxidizer build --release'
