# -*- coding: UTF8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

import pyaudio

FORMAT = pyaudio.paInt16
CHANNELS = 2
RATE = 44100
CHUNK = 1024

def record_iter(total=10, chunk=5):
    try:
        audio = pyaudio.PyAudio()

        stream = audio.open(format=FORMAT, channels=CHANNELS,
        rate=RATE, input=True,
        frames_per_buffer=CHUNK)
        print "recording..."
        for k in range(0, int(int(total)/int(chunk))):
            data=b""
            for j in range(0, int(chunk)):
                for i in range(0, int(RATE / CHUNK * 1)):
                    data += stream.read(CHUNK)
            yield (audio.get_sample_size(FORMAT), CHANNELS, RATE, data)
        print "finished recording"
    finally:
        stream.stop_stream()
        stream.close()
        audio.terminate()

