from pupylib.PupyModule import config, PupyModule, PupyArgumentParser
from pupylib.PupyCompleter import remote_path_completer
from pupylib.PupyOutput import Table, Line, List, MultiPart
from modules.lib import size_human_readable, file_timestamp
from argparse import REMAINDER

from magic import Magic

__class_name__="FStat"

@config(cat='admin', compat=['windows', 'linux'])
class FStat(PupyModule):
    '''Show a bit more info about file path. ACLs/Caps/Owner for now'''

    dependencies = {
        'all': [
            'pupyutils', 'fsutils', 'fsutils_ext'
        ],
        'windows': ['junctions', 'ntfs_streams'],
        'linux': ['xattr', 'posix1e', 'prctl', '_prctl']
    }

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog='stat', description=cls.__doc__)
        cls.arg_parser.add_argument(
            'path', type=str, nargs=REMAINDER,
            help='path of a specific file', completer=remote_path_completer)

    def run(self, args):
        getfilesec = self.client.remote('fsutils_ext', 'getfilesec')

        path = ' '.join(args.path)

        try:
            sec = getfilesec(path)
        except Exception, e:
            self.error(' '.join(x for x in e.args if type(x) in (str, unicode)))
            return

        ctime, atime, mtime, size, owner, group, header, mode, extra = sec

        owner_id, owner_name, owner_domain = owner
        group_id, group_name, group_domain = group

        magic = ''
        if header:
            with Magic() as libmagic:
                magic = libmagic.id_buffer(header)

        default = {
            'Created': file_timestamp(ctime, time=True),
            'Accessed': file_timestamp(atime, time=True),
            'Modified': file_timestamp(mtime, time=True),
            'Size': '{} ({})'.format(size_human_readable(size), size),
            'Owner': '{}{} ({})'.format(
                owner_domain+'\\' if owner_domain else '',
                owner_name,
                owner_id
            ),
            'Group': '{}{} ({})'.format(
                group_domain+'\\' if group_domain else '',
                group_name,
                group_id
            ),
            'Mode': mode,
        }

        infos = []

        infos.append(Table([
            {'Property': p, 'Value': default[p]} for p in (
                'Created', 'Accessed', 'Modified',
                'Size', 'Owner', 'Group', 'Mode'
            )
        ], ['Property', 'Value'], legend=False))

        if magic:
            infos.append('Magic: {}'.format(magic))

        for extra, values in extra.iteritems():
            if type(values) in (list, tuple):
                infos.append(List(values, caption=extra))
            else:
                infos.append(Line(extra+':', values))

        self.log(MultiPart(infos))
