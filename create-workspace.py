#!/usr/bin/env python

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from __future__ import print_function
import argparse
import subprocess
import os
import sys
import errno
import tempfile
import tarfile
import hashlib
import shutil
import resource

if sys.version_info.major > 2:
    from urllib.request import urlopen
else:
    from urllib2 import urlopen

ENV_IMAGE = 'pupy-python2-env'
ENV_CONTAINER = 'pupy-'

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

parser.add_argument(
    '-E', '--environment', choices=['virtualenv', 'docker', 'podman'],
    default='virtualenv', help='The way to organize workspace bottle'
)

parser.add_argument(
    '-N', '--network', default='host',
    help='Network type for docker/podman. Default is host'
)

parser.add_argument(
    '-P', '--persistent', default=False, action='store_true',
    help='Do not remove docker/podman build image'
)

parser.add_argument(
    '-S', '--squash', default=False, action='store_true',
    help='Use --squash feature (podman/docker)'
)

parser.add_argument(
    '-R', '--images-repo', default='alxchk',
    help='Use non-default toolchains repo (Use "local" to '
    'build all the things on your PC'
)

parser.add_argument(
    '-T', '--image-tag', default='latest', help='Image tag'
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

_ESCAPE = (
    '"', '$', '`', '\\'
)


def shstr(string):
    if not any(esc in string for esc in _ESCAPE):
        return string

    result = ['"']

    for char in string:
        if char in _ESCAPE:
            result.append('\\')
        result.append(char)

    result.append('"')
    return ''.join(result)


def shjoin(args):
    return ' '.join(shstr(string) for string in args)


def get_place_digest(*args):
    return hashlib.sha1(
        b'\0'.join(
            arg.encode('ascii') for arg in args
        )
    ).hexdigest()[:4]


def check_programs(programs, available=False):
    messages = []
    ok = []

    for program in programs:
        args, message = _REQUIRED_PROGRAMS[program]

        try:
            with open(os.devnull, 'w') as devnull:
                subprocess.check_call(args, stdout=devnull)

            ok.append(program)
        except (OSError, subprocess.CalledProcessError):
            messages.append(message)

    if available:
        return ok
    else:
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


    print("[+] Pupy at {}".format(pupy))

    if not args.do_not_compile_templates:
        print("[+] Compile common templates")
        env = os.environ.copy()
        if args.docker_repo:
            env['REPO'] = args.docker_repo

def get_rev(git_folder):
    return subprocess.check_output([
        'git', 'rev-parse', 'HEAD'
    ], cwd=git_folder)

    print("[+] Create VirtualEnv environment")

def get_changed_files(git_folder, prev_ref, current_ref='HEAD'):
    return subprocess.check_output([
        'git', 'diff', '--name-only', prev_ref, current_ref
    ], cwd=git_folder).split()


def build_templates(
        git_folder, docker_repo, orchestrator, templates, tag, persistent):
    print("[+] Compile templates: {}".format(templates))

    if docker_repo.lower().strip() == 'local':
        docker_repo = ''

    repo = ''

    if docker_repo:
        repo = docker_repo + '/'
    elif orchestrator == 'podman':
        repo = 'localhost' + '/'

    update_commands = []

    for template in templates:
        container_name = 'build-pupy-' + template + '-' + get_place_digest(
            git_folder
        )

        create_template = False

        try:
            with open(os.devnull, 'w') as devnull:
                subprocess.check_call([
                    orchestrator, 'inspect', container_name
                ], stdout=devnull, stderr=devnull)
        except subprocess.CalledProcessError:
            create_template = True

        if create_template:
            print("[+] Build {} using {} (create)".format(
                template, container_name))

            args = [
                orchestrator, 'run'
            ]

            if not persistent:
                args.append('--rm')

            args.extend([
                '--name=' + container_name,
                '--ulimit', 'nofile=65535:65535',
                '--security-opt', 'label=disable',
                '--mount', 'type=bind,src=' + git_folder +
                ',target=/build/workspace/project',
                repo + 'tc-' + template + ':' + tag,
                'client/' + TEMPLATES[template] + '/build-docker.sh'
            ])

            try:
                subprocess.check_call(args, stderr=subprocess.STDOUT)
            except subprocess.CalledProcessError as e:
                if e.returncode == 139 and template == 'linux64':
                    print("[!] Likely you must to enable vsyscall=emulate")

                raise

            if persistent:
                update_commands.append(
                    orchestrator + ' start -a ' + shstr(container_name)
                )
            else:
                update_commands.append(shjoin(args))

        else:
            print("[+] Build {} using {} (existing)".format(
                template, container_name))

            try:
                subprocess.check_call([
                    orchestrator, 'start', '-a', container_name
                ], stderr=subprocess.STDOUT)
            except subprocess.CalledProcessError as e:
                if e.returncode == 139 and template == 'linux64':
                    print("[!] Likely you must to enable vsyscall=emulate")

                raise

            update_commands.append(
                orchestrator + ' start -a ' + shstr(container_name)
            )

    return update_commands


def make_pupysh_wrapper(workdir, git_folder, orchestrator):
    pass


def makedirs_p(dirpath):
    try:
        os.makedirs(args.workdir)
    except OSError as e:
        if e.errno == errno.EEXIST:
            pass
        else:
            raise


def initialize_workdir(workdir, gitdir):
    for dirname in ('crypto', 'data', 'bin', 'config'):
        makedirs_p(os.path.join(workdir, dirname))

    shutil.copy(
        os.path.join(
            gitdir, 'pupy', 'conf', 'pupy.conf.docker'
        ),
        os.path.join(
            workdir, 'config', 'pupy.conf'
        )
    )


def create_virtualenv(workdir, git_path, orchestrator=None, templates=[]):
    import virtualenv

    virtualenv.create_environment(workdir)

    print("[+] Update pip version ...")
    subprocess.check_call([
        os.path.join(workdir, 'bin', 'pip'),
        'install',
        '--upgrade', 'pip'
    ], cwd=workdir, stderr=subprocess.STDOUT)

    print("[+] Install dependencies")
    subprocess.check_call([
        os.path.join(workdir, 'bin', 'pip'),
        'install', '--no-use-pep517',
        '-r', 'requirements.txt'
    ], cwd=os.path.join(git_path, 'pupy'), stderr=subprocess.STDOUT)

    shell_commands = [
        'exec {1}/bin/python -OB {0}/pupy/pupysh.py --workdir {1} "$@"'.format(
            shstr(git_path), shstr(workdir)
        )
    ]

    update_commands = [
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
                '{} start -a build-pupy-{}-{}'.format(
                    orchestrator, target,
                    get_place_digest(git_path)
                )
            ])
    else:
        update_commands.extend([
            'echo "[-] You must update templates manually"'
        ])

    subprocess.check_call([
        os.path.abspath(os.path.join(workdir, 'bin', 'pip')),
        'install', '--upgrade', '--force-reinstall',
        'pycryptodome'
    ], cwd=os.path.join(pupy, 'pupy'))

    if args.download_templates_from_github_releases:
        download_link="https://github.com/n1nj4sec/pupy/releases/download/latest/payload_templates.txz"
        print("downloading payload_templates from {}".format(download_link))
        subprocess.check_call(["wget", "-O", "payload_templates.txz", download_link], cwd=os.path.join(pupy))
        print("extracting payloads ...")
        subprocess.check_call(["tar", "xf", "payload_templates.txz", "-C", "pupy/"], cwd=os.path.join(pupy))
        

    wrappers=["pupysh", "pupygen"]
    print("[+] Create {} wrappers".format(','.join(wrappers)))

    pupysh_update_path = os.path.join(workdir, 'bin', 'pupysh-update')
    pupysh_paths=[]
    for script in wrappers:
        pupysh_path = os.path.join(workdir, 'bin', script)
        pupysh_paths.append(pupysh_path)

        with open(pupysh_path, 'w') as pupysh:
            wa = os.path.abspath(workdir)
            print('#!/bin/sh', file=pupysh)
            print('cd {}'.format(wa), file=pupysh)
            print('exec bin/python -B {} "$@"'.format(
                os.path.join(pupy, 'pupy', script+'.py')), file=pupysh)

        os.chmod(pupysh_path, 0o755)

    with open(pupysh_update_path, 'w') as pupysh_update:
        wa = os.path.abspath(workdir)
        print('#!/bin/sh', file=pupysh_update)
        print('set -e', file=pupysh_update)
        print('echo "[+] Update pupy repo"', file=pupysh_update)
        print('cd {}; git pull --recurse-submodules'.format(pupy), file=pupysh_update)
        print('echo "[+] Update python dependencies"', file=pupysh_update)
        print('source {}/bin/activate; cd pupy; pip install --upgrade -r requirements.txt'.format(
            workdir), file=pupysh_update)
        if not args.do_not_compile_templates:
            print('echo "[+] Recompile templates"', file=pupysh_update)
            for target in ('windows', 'linux32', 'linux64'):
                print('echo "[+] Build {}"'.format(target), file=pupysh_update)
                print('docker start -a build-pupy-{}'.format(target), file=pupysh_update)
        print('echo "[+] Update completed"', file=pupysh_update)

    os.chmod(pupysh_update_path, 0o755)


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
        print("~ > {}".format(pupysh_paths[0]))
        print("[I] To update:")
        print("~ > {}".format(pupysh_update_path))


if __name__ == '__main__':
    main()
