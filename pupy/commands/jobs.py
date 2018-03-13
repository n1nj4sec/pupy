# -*- encoding: utf-8 -*-

from pupylib.PupyModule import PupyArgumentParser
from pupylib.PupyOutput import Error, Success, Table

usage  = "Manage Jobs"
parser = PupyArgumentParser(prog='jobs', description=usage)

killjob = parser.add_mutually_exclusive_group()
killjob.add_argument('-k', '--kill', metavar='<job_id>', help="print the job current output before killing it")
killjob.add_argument('-K', '--kill-no-output', metavar='<job_id>', help="kill job without printing output")
parser.add_argument('-l', '--list', action='store_true', help="list jobs")
parser.add_argument('-p', '--print-output', metavar='<job_id>', help="print a job output")

def do(server, handler, config, modargs):
    if modargs.kill:
        j = server.get_job(modargs.kill)
        handler.display(Success(j.result_summary()))
        finished = j.is_finished()

        if finished:
            j.stop()
            handler.display(Success('Job closed'))

        else:
            j.interrupt()
            j.stop()
            handler.display(Success('Job killed'))

        self.pupsrv.del_job(modargs.kill)
        del j

    elif modargs.kill_no_output:
        j = self.pupsrv.get_job(modargs.kill_no_output)
        finished = j.is_finished()
        if finished:
            j.stop()
            handler.display('Job closed')
        else:
            j.interrupt(wait=False)
            j.stop()
            handler.display(Success('Job killed'))
        server.del_job(modargs.kill_no_output)
        del j

    elif modargs.print_output:
        j = server.get_job(modargs.print_output)
        handler.display(j.result_summary())

    elif modargs.list:
        if server.jobs:
            dictable = []

            for k,v in self.pupsrv.jobs.iteritems():
                dictable.append({
                    'id':k,
                    'job':str(v),
                    'status': 'finished' if v.is_finished() else 'running',
                    'clients_nb': str(v.get_clients_nb()),
                })

            handler.display(Table(dictable, ['id', 'job', 'clients_nb','status']))
        else:
            handler.display(Error('No jobs are currently running'))
