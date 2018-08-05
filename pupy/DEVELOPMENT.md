# INTRO

This document created to note right-way to solve some typical problems 
which may occur during development modules for pupy. Right now it missess a lot of details
which should be added with time.

# Overview

Pupy is client/server software. Both client and server written using Python of same version.
This is [limitation][1] of RPyC library which is used for RPC between client and server.

Both client and server sharing same modificated RPyC library (ver. 3.4.4). Pupy _will not_ work with recent 
RPyC library (>= 4.0.0).

Server expected to be executed on Linux. Client (in theory) may be executed on any platform
where python works (even strange ones like jython).
Realworld set of platforms is limited with platforms supported by [psutil][2] library.

Tier 1 OSes are Linux and Windows.

Pupy also can work on Android and MacOS with significant limitations.

# Architecture

**Please note that this section pretty much incomplete.**

The core of pupy is RPyC library, so pupy follows [architecture][3]. There is no much sense
to duplicate RPyC documentation, so it's worth to read it first.

Here are some _very brief_ description of used abstractions.

## Both sides.

1. **PupyConnection**. Defines high-level lifecycle of connection stream. At this level RPyC commands marshalled to [brine][4] messages. **PupyConnection** takes care about proper sequencing, messages handling, timeouts ets. **PupyConnection** called transparently during access to proxy methods. Thus responsible to handle *blocking* during remote calls.
	Implementation can be found at [network/lib/connection.py](network/lib/connection.py)
2. **PupyChannel**. Defines high-level control of reading/sending messages. At this level previously marshalled messages enveloped, possibly compressed and passed to the stream. **PupyChannel** responsible for reading/sending data from/to **PupyConnection**.
	Implementation can be found at [network/lib/streams/PupySocketStream.py](network/lib/streams/PupySocketStream.py)

3. **TransportConf**. Defines the set of techniques which are used to perform and establish communication.
	Configs can be found at [network/transports](network/transports). 
	_TransportConf_ defines combination of network+transport+session layer (OBFS over TCP/UDP/whatever over IP) and 
	 presentation layer (KEX, encryption, etc). 
4. **BasePupyTransport**. Defines how data will be transformed during.
	**BasePupyTransport** implementation can be found at [network/lib/base.py](network/lib/base.py).
	Dependencies and implementations of all transports can be found 
	at [network/lib/transports](network/lib/transports). 
5. **TransportWrapper**. Subclass of **BasePupyTransport**. Provides ability to chain transports. Thus it's possible
	to pass data from one **BasePupyTransport** to another. Example: RSA+AES over OBFS.
	Implementation can be found at [network/lib/base.py](network/lib/base.py).
6. **PupyUDPSocketStream**, **PupySocketStream**.
   These are two main classes to handle actual communication. _Stream_ classes provides abstract communication channel, which connects two sides.

Here is high-level overview of handling remote calls in pupy. Please note that process is **different** from standard RPyC. The reason was handling of recursive nested calls.

```python
a = some_remote_object.data
```

1. [**BaseNetref**][5] dereference call.
2. [**PupyConnection**][6] sync request.
3. [**Connection**][7] marshalling using Brine.
4. [**PupyChannel**][8] envelop marshaled message and [submit][9] to transport abstraction.
5. [**TransportWrapper**][10] or **BasePupyTransport** transforms the data. The last item in chain - _Stream_ 
   [(**PupyUDPSocketStream**, **PupySocketStream**)][11].
6. [**PupyConnection**][22] blocks until request processed and completed.

Client's actions are more complex.

0. [**PupyConnection**][13] executed somewhere in separate thread until EOF.
1. **PupyConnection** continiously [expect][14] enveloped messages from remote side using blocking call to 
   [**PupyChannel**][14] reader.
2. [**TransportWrapper**][10] or **BasePupyTransport** transforms the incoming data .
3. [**PupyChannel**][15] request data until full message available.
4. [**PupyConnection**][16] unpacks received data using _Brine_ and [schedule][17] processing.
5. [**SyncRequestDispatchQueue**][18] is special abstraction which either create a thread to process request, 
   or use empty one. The only criteria to create separate thread is [wait time][19]. In case task was not acquired
   during some time, new thread will be created to process the query. 
6. [**SyncRequestDispatchQueue**][20] calls RPyC [handler][21] according to unpacked message and args.
7. [**PupyConnection**][6] sync request.
8. [**Connection**][7] marshalling using Brine.
9. [**PupyChannel**][8] envelop marshaled message and [submit][9] to transport abstraction.
10. [**TransportWrapper**][10] or **BasePupyTransport** transforms the data. The last item in chain - _Stream_ 
   [(**PupyUDPSocketStream**, **PupySocketStream**)][11].

Server response handling:

0. [**PupyConnection**][13] executed somewhere in separate thread until EOF.
1. **PupyConnection** continiously [expect][14] enveloped messages from remote side using blocking call to 
   [**PupyChannel**][14] reader.
2. [**TransportWrapper**][10] or **BasePupyTransport** transforms the incoming data .
3. [**PupyChannel**][15] request data until full message available.
4. [**PupyConnection**][16] unpacks received data using _Brine_ and [process][23] response.
5. [**PupyConnection**][24] unblocks RPC call. 
6. [**PupyConnection**][25] return call result.

## Server side.

Pupy server (pupysh.py) contains from two major parts:

1. Client interaction part (RPyC server). Implementation can be found at
   [pupylib/PupyServer.py](pupylib/PupyServer.py). **PupyServer** handles 
   _jobs_, _modules_, _listeners_, _clients_.
2. User interaction part (TUI), so called **handler**. Currently there is only one implementation - 
   Console TUI for Linux. Implementation can be found at [pupylib/PupyCmd.py](pupylib/PupyCmd.py).
   Handler's role to establish interaction with user.
   
## Client side.

1. **Launcher**. Iterator which generates sockets with established connections.
   All registered launchers can be found at [network/conf.py](network/conf.py).
   Implementations can be found ad [network/lib/launchers](network/lib/launchers).
2. Client implementation can be found at [pp.py](pp.py).

# Extending Pupy

## Overview

Currently there are two things which can be extended.

1. **Modules**. Commands which applied to connected clients. Example: ``run ls``. 
2. **Commands**. Generic commands which can be executed outside clients context. Example: ``sessions``.

In case your new extensions works with server internals and can work without any
connected client - you shoud use **Commands**. 

## Commands

All things you type in pupysh passed threw **commands** abstraction. Clients control goes threw **run** command. 
Other commands like **sessions**, **config**, **exit** controls server state.

To implement new command you should write and place python file to [commands](commands). All the logic behind
the management of this set of files can be found at [commands/__init__.py](commands/__init__.py).

Here is an example of simple command - [commands/tag.py](commands/tag.py). This command maintains tag list for clients by client node ID.

```python
# -*- encoding: utf-8 -*-

from pupylib.PupyModule import PupyArgumentParser
from pupylib.PupyOutput import Table

## Required variable. Used in help output
usage  = "Assign tag to current session"

## Required variable. Used to create parser, which will parse arguments
parser = PupyArgumentParser(prog='tag', description=usage)
parser.add_argument('-a', '--add', metavar='tag', nargs='+', help='Add tags')
parser.add_argument('-r', '--remove', metavar='tag', nargs='+', help='Remove tags')
parser.add_argument('-w', '--write-project', action='store_true',
                        default=False, help='save config to project folder')
parser.add_argument('-W', '--write-user', action='store_true',
                        default=False, help='save config to user folder')

## Required function. Actual work done here
## server - PupyServer object
## handler - Handler object (Right now - PupyCmd)
## config - PupyConfig object
## modargs - parsed arguments

def do(server, handler, config, modargs):
    data = []

	## Get currently selected clients
    clients = server.get_clients(handler.default_filter)

    if not clients:
        return

    for client in clients:
		## Get current tags
        tags = config.tags(client.node())

        if modargs.remove:
            tags.remove(*modargs.remove)

        if modargs.add:
            tags.add(*modargs.add)

        data.append({
            'ID': client.node(),
            'TAGS': tags
        })

	## Save new values
    config.save(
        project=modargs.write_project,
        user=modargs.write_user
    )

	## Display table with tags
    handler.display(Table(data))
```

**Important**. Please do not use _print_, _sys.write_ or any other functions to display text. Do use handler
object for that. Do not preformat or colorize your text manually - do use **PupyOutput** text hints.

## Modules

**Modules** - special commands to execute some action on one or group of clients. **Modules** executed using
[**run**](commands/run.py) command. **Module** should be subclass of [**PupyModule**](pupylib/PupyModule.py).

To properly operate **module** should specify (or leave default values) for set of important [properties][26].

1. **qa**. Specify the robustness of the module. ``QA_STABLE`` - module verified and reliable. 
``QA_UNSTABLE`` - minor issues exists. ``QA_DANGEROUS`` - you can lost your client with high probability.
2. **io**. Required properties of TUI window. ``REQUIRE_NOTHING`` - module does not require interaction with user.
Module will output information all at once or by set of logicaly finished messages. ``REQUIRE_STREAM`` - 
module will output unknown amount of information with chunks which can be logically unfinished.
``REQUIRE_REPL`` - module requires REPL (Read–eval–print loop). ``REQUIRE_TERMINAL`` - module requires fully 
interactive raw TTY terminal. In case you are not 100% sure what to use, you should use default 
value - ``REQUIRE_NOTHING``.
3. **dependencies**. Describes which libraries(**packages**) should be uploaded to client. This value should be set
either to _list_ or _dict_. In case **dependencies** has _list_ value, this set of dependenceis will be applied to
clients executed on all platforms. If different dependencies should be specified according to client's OS _dict_
should be used. In this case the key will be OS (_linux_, _windows_, _android_ etc) and value will be the list of
dependencies.
4. **compatible_systems**. The set of OS (_linux_, _windows_, _android_ etc) which supports this module. Also can
be specified using keyword **compat** of **@config** decorator.

Module should also implement at least two methods:

1. **init_argparse**. *Class-method* which is used to parse arguments. Please note that this method 
**can not use any state**. **init_argparse** should initialize *Class-variable* arg_parser.
2. **run**. Entry point of module. Takes **args** _dict_ which is return value of **arg_parser** which is 
generated by **init_argparse**.

Here is an example of simple module - [modules/pwd.py](modules/pwd.py). 

```python
# -*- coding: utf-8 -*-
from pupylib.PupyModule import config, PupyArgumentParser, PupyModule


### Required variable. Specify the main class of module. In this case - pwd
__class_name__="pwd"

### @config decorator in this case used to specify category.
@config(cat="admin")
class pwd(PupyModule):
    """ Get current working dir """
    is_module=False

	### Initialize empty argparser
    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog="pwd", description=cls.__doc__)

    def run(self, args):
        try:
			### Cache remote function
            getcwd = self.client.remote('os', 'getcwdu', False)
			### Execute remote function and show result
            self.success(getcwd())
        except Exception, e:
            self.error(' '.join(x for x in e.args if type(x) in (str, unicode)))
```

## Important

Please do not use _print_, _sys.write_ or any other functions to display text. Do use built-in functions
for that.

1. **log**. Show regular message.
2. **error**. Show error message.
3. **warning**. Show warning message.
4. **success**. Show success message.
5. **info**. Show info message.
6. **newline**. Submit delemiter.
7. **table**. Output table. Args: **data** - dict. Key - column name, Value - column value.
  **header** - _list_ of the column names which will be shown in the specified order.
  **caption** - Table caption.

Do not preformat or colorize your text manually - do use [**PupyOutput**](pupylib/PupyOutput.py) text hints.
[**PupyCmd**](pupylib/PupyCmd.py) uses [**hint_to_text**][27] function to render hints to terminal commands.

Use [**self.client.remote**][28] to cache function. The reason - each dereference cost 1-2 request-response 
pairs **every time**. You will not have issues on localhost, but on realworld slow channel you will have
several seconds of latency even with simples module, like the one in example. 
[**self.client.remote**][28] maintains internal cache will invalidates only on **load_package -f** command.

Prototype: ```def remote(self, module, function=None, need_obtain=True)```

1. **module**. String name of required module (like 'os' or 'os.path'). Classess are not allowed.
In case other args are omitted, will return NetRef to the remote module with specified name. 
In case **function** is *None* (default), **need_obtain** argument is ignored.
2. **function**. String name of required function (like 'abspath' in 'os.path' module). Classess are not 
allowed. Will return wrapper to required function.
3. **need_obtain**. In case **function** was specified and **need_obtain** is *True* result
   will also transparently marshal arguments using msgpack. Result will also be transparently unmarshal with
   msgpack. **need_obtain** should be set to *False* in case classess or other mutable references will be 
   passed or expected to be returned.

Do not use any special logic in case you want to run module in background (while connection established). 
Just run module with *-b* argument.

In case some task should be executed independently from connection, **Task** abstraction should be used.
Nice examples of **Task** can be found at [modules/keylogger.py](modules/keylogger.py), 
[packages/windows/all/pupwinutils/keylogger.py](packages/windows/all/pupwinutils/keylogger.py) and
[modules/psh.py](modules/psh.py), [packages/windows/all/powershell.py](packages/windows/all/powershell.py).

Do care about interruptions and cleanup. There are plenty of reasons why things can go wrong.

Template for interruptions.

```python
class NiceModule(PupyModule):
	### Placeholder for terminate Event
	terminate = None
	terminated = None
	
	def run(self, args):
		self.terminated = Event()
	
		def on_data(data):
			if not self.terminated.is_set():
				self.success(data)
			
		def on_error(data):
			if not self.terminated.is_set():
				self.on_error(data)
	
		def on_completion():
			self.terminated.set()
	
		create_thread = self.client.remote('nicemodule', 'create_thread', False)
		self.terminate = do(on_data, on_error, on_completion)
		
		self.terminate.wait()
		
	def interrupt(self):
		if not self.terminated.is_set():
			self.warning('Force interrupt')
			if self.terminate:
				self.terminate()
	
		self.terminated.set()
```

In case resources which can not be cleaned up by GC were allocated during task you should use 
**self.client.conn.register_local_cleanup** and/or **self.client.conn.register_remote_cleanup**.
Example can be found at [modules/forward.py](modules/forward.py).

Try to reduce RPC calls as much as possible. Do not use netrefs to classes if possible.
Do not use RPC with iterators. If it's not possible to use **self.client.remote** with 
**need_obtain** do use **obtain** directly.

[1]: http://rpyc.readthedocs.io/en/latest/install.html#cross-interpreter-compatibility
[2]: https://psutil.readthedocs.io
[3]: http://rpyc.readthedocs.io/en/latest/tutorial/tut3.html
[4]: http://rpyc.readthedocs.io/en/latest/api/core_brine.html
[5]: https://github.com/tomerfiliba/rpyc/blob/8a4291aed88fd2eb92c77ec9494915bc683b485f/rpyc/core/netref.py#L160
[6]: https://github.com/alxchk/pupy/blob/77036220fe7f4324d692ff33a07dbb42f0815804/pupy/network/lib/connection.py#L300
[7]: https://github.com/tomerfiliba/rpyc/blob/8a4291aed88fd2eb92c77ec9494915bc683b485f/rpyc/core/protocol.py#L278
[8]: https://github.com/alxchk/pupy/blob/77036220fe7f4324d692ff33a07dbb42f0815804/pupy/network/lib/streams/PupySocketStream.py#L131
[9]: https://github.com/alxchk/pupy/blob/77036220fe7f4324d692ff33a07dbb42f0815804/pupy/network/lib/streams/PupySocketStream.py#L188
[10]: https://github.com/alxchk/pupy/blob/77036220fe7f4324d692ff33a07dbb42f0815804/pupy/network/lib/base.py#L220
[11]: https://github.com/alxchk/pupy/blob/77036220fe7f4324d692ff33a07dbb42f0815804/pupy/network/lib/streams/PupySocketStream.py#L328
[12]: https://github.com/alxchk/pupy/blob/77036220fe7f4324d692ff33a07dbb42f0815804/pupy/network/lib/streams/PupySocketStream.py#L338
[13]: https://github.com/alxchk/pupy/blob/77036220fe7f4324d692ff33a07dbb42f0815804/pupy/network/lib/connection.py#L501
[14]: https://github.com/alxchk/pupy/blob/77036220fe7f4324d692ff33a07dbb42f0815804/pupy/network/lib/connection.py#L579
[15]: https://github.com/alxchk/pupy/blob/77036220fe7f4324d692ff33a07dbb42f0815804/pupy/network/lib/streams/PupySocketStream.py#L75
[16]: https://github.com/alxchk/pupy/blob/77036220fe7f4324d692ff33a07dbb42f0815804/pupy/network/lib/connection.py#L603
[17]: https://github.com/alxchk/pupy/blob/77036220fe7f4324d692ff33a07dbb42f0815804/pupy/network/lib/connection.py#L619
[18]: https://github.com/alxchk/pupy/blob/77036220fe7f4324d692ff33a07dbb42f0815804/pupy/network/lib/connection.py#L61
[19]: https://github.com/alxchk/pupy/blob/77036220fe7f4324d692ff33a07dbb42f0815804/pupy/network/lib/connection.py#L180
[20]: https://github.com/alxchk/pupy/blob/77036220fe7f4324d692ff33a07dbb42f0815804/pupy/network/lib/connection.py#L104
[21]: https://github.com/tomerfiliba/rpyc/blob/8a4291aed88fd2eb92c77ec9494915bc683b485f/rpyc/core/protocol.py#L594
[22]: https://github.com/alxchk/pupy/blob/77036220fe7f4324d692ff33a07dbb42f0815804/pupy/network/lib/connection.py#L305
[23]: https://github.com/alxchk/pupy/blob/77036220fe7f4324d692ff33a07dbb42f0815804/pupy/network/lib/connection.py#L623
[24]: https://github.com/alxchk/pupy/blob/77036220fe7f4324d692ff33a07dbb42f0815804/pupy/network/lib/connection.py#L390
[25]: https://github.com/alxchk/pupy/blob/77036220fe7f4324d692ff33a07dbb42f0815804/pupy/network/lib/connection.py#L347
[26]: https://github.com/alxchk/pupy/blob/77036220fe7f4324d692ff33a07dbb42f0815804/pupy/pupylib/PupyModule.py#L317
[27]: https://github.com/alxchk/pupy/blob/77036220fe7f4324d692ff33a07dbb42f0815804/pupy/pupylib/utils/term.py#L266
[28]: https://github.com/alxchk/pupy/blob/77036220fe7f4324d692ff33a07dbb42f0815804/pupy/pupylib/PupyClient.py#L221
