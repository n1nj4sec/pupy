#!/usr/bin/env python
# -*- coding: UTF8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
from jnius import autoclass
import time

__all__=["speak"]

def speak(text, lang='US'):
    """ use the text to speach API to speak text out loud :-) """
    Locale = autoclass('java.util.Locale')
    PythonActivity = autoclass('org.renpy.android.PythonService')
    TextToSpeech = autoclass('android.speech.tts.TextToSpeech')
    tts = TextToSpeech(PythonActivity.mService, None)
    time.sleep(0.1) #dirty but avoid implementing TextToSpeech.OnInitListener
    try:
        if lang is not None:
            if lang in ['CANADA', 'CANADA_FRENCH', 'CHINA', 'CHINESE', 'ENGLISH', 'FRANCE', 'FRENCH', 'GERMAN', 'GERMANY', 'ITALIAN', 'ITALY', 'JAPAN', 'JAPANESE', 'KOREA', 'KOREAN', 'PRC', 'PRIVATE_USE_EXTENSION', 'ROOT', 'SIMPLIFIED_CHINESE', 'TAIWAN', 'TRADITIONAL_CHINESE', 'UK', 'UNICODE_LOCALE_EXTENSION', 'US']:
                error_codes={-1:'LANG_MISSING_DATA', -2:'LANG_NOT_SUPPORTED'}
                ret=tts.setLanguage(getattr(Locale,lang))
                if ret in error_codes:
                    raise Exception("Error in setLanguage: %s for lang: %s"%(error_codes[ret],lang))
            else:
                raise Exception("no such locale : %s"%lang)
        #ref. http://developer.android.com/reference/android/speech/tts/TextToSpeech.html
        ret=tts.speak(str(text), TextToSpeech.QUEUE_FLUSH, None)
        for i in range(0,10):
            time.sleep(0.1)
        while tts.isSpeaking():
            time.sleep(0.1)
        if ret == TextToSpeech.LANG_MISSING_DATA:
            raise Exception("Error: LANG_MISSING_DATA")
        return ret
    finally:
        tts.shutdown()


