#!/usr/bin/env python

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import argparse
import subprocess
import os
import sys
import errno
import tempfile
import tarfile
import hashlib

if sys.version_info.major == 3:
    from urllib.request import urlopen
else:
    from urllib2 import urlopen

PODMAN_IMAGE = 'pupy-python2-image'
PODMAN_CONTAINER = 'pupy-'

TEMPLATES = {
    'linux32': 'sources-linux',
    'linux64': 'sources-linux',
    'linux-armhf': 'sources-linux',
    'android': 'android_sources',
    'windows': 'sources'
}

default_local_bin_location = os.path.expanduser('~/.local/bin/')
ROOT = os.path.abspath(os.path.dirname(__file__))

parser = argparse.ArgumentParser(prog="create-workspace.py")
parser.add_argument(
    '-G', '--pupy-git-folder',
    default=ROOT, help='Path to pupy git'
)

templates_args = parser.add_mutually_exclusive_group()
templates_args.add_argument(
    '-NC', '--do-not-compile-templates',
    action='store_true', default=False,
    help='Do not compile payload templates'
)

templates_args.add_argument(
    '-C', '--compile-templates',
    default='linux32,linux64,windows',
    help='Compile specified templates (default: linux32,linux64,windows)'
)

templates_args.add_argument(
    '-DG', '--download-templates-from-github-releases',
    action='store_true', default=False,
    help='Do not compile payload templates and download latest '
    'templates from travis-ci automatic build'
)

parser.add_argument(
    '-P', '--podman', action='store_true',
    help='Use podman instead of docker and virtualenv'
)

parser.add_argument(
    '-R', '--images-repo', default='alxchk',
    help='Use non-default toolchains repo (Use "local" to '
    'build all the things on your PC'
)

parser.add_argument(
    '-B', '--bin-path', default=default_local_bin_location,
    help='Store pupy launch wrapper to this folder (default={})'.format(
        default_local_bin_location)
)

parser.add_argument('workdir', help='Location of workdir')

_REQUIRED_PROGRAMS = {
    'podman': (
        ['podman', 'info'],
        'Podman either is is not installed or not configured.\n'
        'Installation: https://podman.io/getting-started/installation'
    ),
    'docker': (
        ['docker', 'info'],
        'Docker either is not installed or not configured.\n'
        'Installation: https://docs.docker.com/install/'
    ),
    'git': (
        ['git', '--help'],
        'Install git (example: sudo apt-get install git)'
    )
}

_REQUIRED_ABIS = {
    'vsyscall32': (
        ('/proc/sys/abi/vsyscall32', int, 1),
        'You may need to have vsyscall enabled:\n'
        '~> sudo sysctl -w abi.vsyscall32=1'
    )
}


def check_programs(programs):
    messages = []

    for program in programs:
        args, message = _REQUIRED_PROGRAMS[program]

        try:
            with open(os.devnull, 'w') as devnull:
                subprocess.check_call(args, stdout=devnull)
        except subprocess.CalledProcessError:
            messages.append(message)

    return messages


def check_abis(abis):
    messages = []

    for abi in abis:
        (filepath, content_type, required_value), message = _REQUIRED_ABIS[abi]
        try:
            if content_type(
                    open(filepath, 'r').read().strip()) != required_value:
                messages.append(message)
        except OSError:
            messages.append(message)

    return messages


def check_modules(modules):
    messages = []

    for module in modules:
        try:
            __import__(module)
        except ImportError:
            messages.append(
                'Missing python module: {}'.format(module)
            )

    return messages


def get_repo_origin(git_folder):
    return subprocess.check_output([
        'git', 'remote', 'get-url', 'origin'
    ], cwd=git_folder)


def update_repo(git_folder):
    return subprocess.check_output([
        'git', 'submodule', 'update', '--init', '--recursive'
    ], cwd=git_folder)


def get_rev(git_folder):
    return subprocess.check_output([
        'git', 'rev-parse', 'HEAD'
    ], cwd=git_folder)


def get_changed_files(git_folder, prev_ref, current_ref='HEAD'):
    return subprocess.check_output([
        'git', 'diff', '--name-only', prev_ref, current_ref
    ], cwd=git_folder).split()


def build_templates(git_folder, docker_repo, orchestrator, templates):
    print("[+] Compile templates: {}".format(templates))

    if docker_repo.lower().strip() == 'local':
        docker_repo = ''

    repo = ''

    if docker_repo:
        repo = docker_repo + '/'
    elif orchestrator == 'podman':
        repo = 'localhost' + '/'

    for template in templates:
        container_name = 'build-pupy-' + template

        try:
            with open(os.devnull, 'w') as devnull:
                subprocess.check_call([
                    orchestrator, 'inspect', container_name
                ], stdout=devnull)
        except subprocess.CalledProcessError:
            print("[+] Build {}: Create container {}".format(
                template, container_name))

            subprocess.check_call([
                orchestrator, 'create',
                '--name=' + container_name,
                '--mount', 'type=bind,src=' + git_folder +
                ',target=/build/workspace/project',
                repo + 'tc-' + template,
                'client/' + TEMPLATES[template] + '/build-docker.sh'
            ])

        print("[+] Build {} using {}".format(template, container_name))
        subprocess.check_call([
            orchestrator, 'start', '-a', container_name
        ])


def fetch_templates(workdir, git_folder):
    origin = get_repo_origin(git_folder)

    if 'n1nj4sec/pupy' not in origin:
        print(
            "[!] There are no prebuild templates, "
            "you must build them manually"
        )

        return False

    download_link = "https://github.com/n1nj4sec/pupy" \
        "/releases/download/latest/payload_templates.txz"

    print("downloading payload_templates from {}".format(download_link))

    with tempfile.NamedTemporaryFile() as tmpf:
        response = urlopen(download_link)
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            tmpf.write(chunk)

        tmpf.flush()
        tmpf.seek(0)

        tarfile.TarFile(fileobj=tmpf).extractall(workdir)

    return True


def make_pupysh_wrapper(workdir, git_folder, orchestrator):
    pass


def makedirs_p(dirpath):
    try:
        os.makedirs(dirpath)
    except OSError as e:
        if e.errno == errno.EEXIST:
            pass
        else:
            raise


def initialize_workdir(workdir):
    for dirname in ('crypto', 'data', 'bin'):
        makedirs_p(os.path.join(workdir, dirname))


def create_virtualenv(workdir, git_path, orchestrator=None, templates=[]):
    import virtualenv

    virtualenv.create_environment(workdir)

    print("[+] Update pip version ...")
    subprocess.check_call([
        os.path.join(workdir, 'bin', 'pip'),
        'install',
        '--upgrade', 'pip'
    ], cwd=workdir)

    print("[+] Install dependencies")
    subprocess.check_call([
        os.path.join(workdir, 'bin', 'pip'),
        'install',
        '-r', 'requirements.txt'
    ], cwd=os.path.join(git_path, 'pupy'))

    shell_commands = [
        'exec bin/python -OB {}/pupy/pupysh.py --workdir {} "$@"'.format(
            repr(git_path), repr(workdir)
        )
    ]

    update_commands = [
        'set -xe',
        'cd {}'.format(git_path),
        'prev_ref=`git rev-parse HEAD`',
        'git pull --recurse-submodules=yes --autostash --rebase',
        'if (git diff --name-only $prev_ref HEAD | grep client/ >/dev/null)'
        'then',
    ]

    if orchestrator and templates:
        for target in templates:
            update_commands.extend([
                'echo "[+] Rebuilding templates for {}"'.format(target),
                '{} start -a build-pupy-{}'.format(orchestrator, target)
            ])
    else:
        update_commands.extend([
            'echo "[-] You must update templates manually"'
        ])

    update_commands.extend([
        'fi'
    ])

    return shell_commands, update_commands


def create_podman_env(workdir, git_path, templates=[]):
    print("[+] Build podman image ({})".format(PODMAN_IMAGE))

    podman_build_command = [
        'podman', 'build',
        '-t', PODMAN_IMAGE,
        '-f', 'conf/Dockerfile.podman',
        os.path.join(git_path, 'pupy')
    ]

    subprocess.check_call(podman_build_command)

    container_name = PODMAN_CONTAINER + hashlib.sha1(
        workdir.encode('ascii') + b'\0' + git_path.encode('ascii')
    ).hexdigest()[:4]

    print("[+] Create podman container ({})".format(container_name))

    podman_create_command = [
        'podman', 'create',
        '--hostname=pupy', '--network=host',
        '--name='+container_name,
        '--interactive', '--tty',
        '--mount', 'type=bind,src=' + os.path.join(
                git_path, 'pupy') + ',target=/pupy',
        '--mount', 'type=bind,src=' + workdir + ',target=/project',
        PODMAN_IMAGE
    ]

    subprocess.check_call(podman_create_command)

    shell_commands = [
        'exec podman start -a ' + container_name
    ]

    update_commands = [
        'set -xe',
        'cd {}'.format(git_path),
        'prev_ref=`git rev-parse HEAD`',
        'git pull --recurse-submodules=yes --autostash --rebase',
        'echo "[+] Update podman environment"',
        ' '.join(repr(x) for x in podman_build_command),
        'podman kill ' + container_name + ' || true',
        'podman rm ' + container_name,
        ' '.join(repr(x) for x in podman_create_command),
        'if (git diff --name-only $prev_ref HEAD | grep client/ >/dev/null)',
        'then',
    ]

    if templates:
        for target in templates:
            update_commands.extend([
                'echo "[+] Rebuilding templates for {}"'.format(target),
                'podman start -a build-pupy-{}'.format(target)
            ])
    else:
        update_commands.extend([
            'echo "[-] You must update templates manually"'
        ])

    update_commands.extend([
        'fi'
    ])

    return shell_commands, update_commands


def main():
    args = parser.parse_args()

    required_programs = {'git'}
    required_modules = set()
    required_abis = set()

    orchestrator = 'docker'

    if sys.version_info.major == 3 and not args.podman:
        sys.exit(
            "Python 3 is not supported. If your can't or don't want"
            " to install python 2 to the system, "
            "use podman or docker-compose.\n"
            "If you have podman configured, use -P flag."
        )

    if args.podman:
        orchestrator = 'podman'

        required_programs.add(orchestrator)
    else:
        required_modules.add('virtualenv')

    if not args.do_not_compile_templates:
        required_abis.add('vsyscall32')
        if not args.podman:
            required_programs.append('docker')

    workdir = os.path.abspath(args.workdir)

    if not os.path.isfile(
            os.path.join(args.pupy_git_folder, 'create-workspace.py')):
        sys.exit('{} is not pupy project folder'.format(
            args.pupy_git_folder))

    if os.path.isdir(workdir) and os.listdir(workdir):
        sys.exit('{} is not empty'.format(workdir))

    git_folder = os.path.abspath(args.pupy_git_folder)

    print("[+] Git repo at {}".format(git_folder))

    messages = []

    messages.extend(
        check_programs(required_programs)
    )

    messages.extend(
        check_abis(required_abis)
    )

    messages.extend(
        check_modules(required_modules)
    )

    if messages:
        sys.exit('\n'.join(messages))

    update_repo(git_folder)

    templates = []

    if not args.do_not_compile_templates:
        templates.extend(
            set(
                template.lower().strip() for template in
                args.compile_templates.split(',')
            )
        )

        build_templates(
            git_folder, args.images_repo,
            'podman' if args.podman else 'docker',
            templates
        )

    print("[+] Create workdir")
    makedirs_p(workdir)

    shell_cmds = []
    update_cmds = []

    if args.podman:
        shell_cmds, update_cmds = create_podman_env(
            workdir, git_folder, templates
        )
    else:
        shell_cmds, update_cmds = create_virtualenv(
            workdir, git_folder, orchestrator, templates
        )

    if args.download_templates_from_github_releases:
        fetch_templates(workdir, git_folder)

    print("[+] Initialize workdir")
    initialize_workdir(workdir)

    wrappers = ("pupysh", "pupygen")

    print("[+] Create {} wrappers".format(','.join(wrappers)))

    pupysh_update_path = os.path.join(workdir, 'bin', 'pupysh-update')
    pupysh_path = os.path.join(workdir, 'bin', 'pupysh')

    with open(pupysh_path, 'w') as pupysh:
        pupysh.write(
            '\n'.join([
                '#!/bin/sh',
            ] + shell_cmds + [''])
        )

        os.chmod(pupysh_path, 0o755)

    with open(pupysh_update_path, 'w') as pupysh:
        pupysh.write(
            '\n'.join([
                '#!/bin/sh',
            ] + update_cmds + [''])
        )

        os.chmod(pupysh_update_path, 0o755)

    if args.bin_path:
        bin_path = os.path.abspath(args.bin_path)
        print("[+] Store symlink to pupysh to {}".format(bin_path))

        if not os.path.isdir(bin_path):
            os.makedirs(bin_path)

        for src, sympath in (
            (
                pupysh_path, 'pupysh'
            ), (
                pupysh_update_path, 'pupysh-update'
            )
        ):
            sympath = os.path.join(bin_path, sympath)

            if os.path.islink(sympath):
                os.unlink(sympath)

            elif os.path.exists(sympath):
                sys.exit(
                    "[-] File at {} already exists and not symlink".format(
                        sympath))

            os.symlink(src, sympath)

        if bin_path not in os.environ['PATH']:
            print("[-] {} is not in your PATH!".format(bin_path))
        else:
            print("[I] To execute pupysh:")
            print("~ > pupysh")
            print("[I] To update:")
            print("~ > pupysh-update")

    else:
        print("[I] To execute pupysh:")
        print("~ > {}".format(pupysh_path))
        print("[I] To update:")
        print("~ > {}".format(pupysh_update_path))


if __name__ == '__main__':
    main()
