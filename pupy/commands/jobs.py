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
        handler.summary(j)
        finished = j.is_finished()

        if finished:
            server.del_job(j.jid)
            handler.display(Success('Job closed'))

        else:
            j.interrupt()
            j.stop()
            handler.display(Success('Job killed'))

        server.del_job(modargs.kill)
        del j

    elif modargs.kill_no_output:
        j = server.get_job(modargs.kill_no_output)
        finished = j.is_finished()
        if finished:
            server.del_job(j.jid)
            handler.display('Job closed')
        else:
            j.interrupt()
            j.stop()
            handler.display(Success('Job killed'))
        server.del_job(modargs.kill_no_output)
        del j

    elif modargs.print_output:
        j = server.get_job(modargs.print_output)
        handler.summary(j)

    elif modargs.list:
        if server.jobs:
            dictable = []

            for jid,job in server.jobs.iteritems():
                dictable.append({
                    'id':jid,
                    'job':str(job),
                    'status': 'finished' if job.is_finished() else 'running',
                    'clients': len(job)
                })

            handler.display(Table(dictable, ['id', 'job', 'clients', 'status']))
        else:
            handler.display(Error('No jobs are currently running'))
