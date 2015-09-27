"""VideoCapture.py

by Markus Gritsch <gritsch@iue.tuwien.ac.at>

"""

import vidcap
from PIL import Image, ImageFont, ImageDraw
import time, string

default_textpos = 'bl' # t=top, b=bottom;   l=left, c=center, r=right
textcolor = 0xffffff
shadowcolor = 0x000000

def now():
    """Returns a string containing the current date and time.

    This function is used internally by VideoCapture to generate the timestamp
    with which a snapshot can optionally be marked.

    """
    weekday = ('Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun')
    #weekday = ('Mo', 'Di', 'Mi', 'Do', 'Fr', 'Sa', 'So')
    #weekday = ('-', '-', '-', '-', '-', '-', '-')
    y, m, d, hr, min, sec, wd, jd, dst = time.localtime(time.time())
    return '%s:%s:%s %s %s.%s.%s' % (string.zfill(hr, 2), string.zfill(min, 2), string.zfill(sec, 2), weekday[wd], d, m, y)

class Device:
    """Create instances of this class which will then represent video devices.

    For the lifetime of the instance, the device is blocked, so it can not be
    used by other applications (which is quite normal Windows behavior).
    If you want to access the device from another program, you have to delete
    the instance first (e.g. del cam).

    """
    def __init__(self, devnum=0, showVideoWindow=0):
        """devnum:  VideoCapture enumerates the available video capture devices
                    on your system.  If you have more than one device, specify
                    the desired one here.  The device number starts from 0.

           showVideoWindow: 0 ... do not display a video window (the default)
                            1 ... display a video window

                            Mainly used for debugging, since the video window
                            can not be closed or moved around.

        """
        self.dev = vidcap.new_Dev(devnum, showVideoWindow)
        self.normalfont = ImageFont.load_path('helvetica-10.pil')
        self.boldfont = ImageFont.load_path('helvB08.pil')
        self.font = None

    def displayPropertyPage(self):
        """deprecated

        Use the methods displayCaptureFilterProperties() and
        displayCapturePinProperties() instead.

        """
        print 'WARNING: displayPropertyPage() is deprecated.'
        print '         Use displayCaptureFilterProperties() and displayCapturePinProperties()'
        print '         instead!'
        self.dev.displaypropertypage()

    def displayCaptureFilterProperties(self):
        """Displays a dialog containing the property page of the capture filter.

        For VfW drivers you may find the option to select the resolution most
        likele here.

        """
        self.dev.displaycapturefilterproperties()

    def displayCapturePinProperties(self):
        """Displays a dialog containing the property page of the capture pin.

        For WDM drivers you may find the option to select the resolution most
        likele here.

        """
        self.dev.displaycapturepinproperties()

    def setResolution(self, width, height):
        """Sets the capture resolution. (without dialog)

        (contributed by Don Kimber <kimber@fxpal.com>)

        """
        self.dev.setresolution(width, height)

    def getDisplayName(self):
        """ Gets the Windows "friendly name" for the device (for example "Microsoft LifeCam VX-1000")

        (contributed by Jeremy Mortis (mortis@tansay.ca)
        """
        return self.dev.getdisplayname()

    def getBuffer(self):
        """Returns a string containing the raw pixel data.

        You probably don't want to use this function, but rather getImage() or
        saveSnapshot().

        """
        return self.dev.getbuffer()

    def getImage(self, timestamp=0, boldfont=0, textpos=default_textpos):
        """Returns a PIL Image instance.

        timestamp:  0 ... no timestamp (the default)
                    1 ... simple timestamp
                    2 ... timestamp with shadow
                    3 ... timestamp with outline

        boldfont:   0 ... normal font (the default)
                    1 ... bold font

        textpos:    The position of the timestamp can be specified by a string
                    containing a combination of two characters.  One character
                    must be either t or b, the other one either l, c or r.

                    t ... top
                    b ... bottom

                    l ... left
                    c ... center
                    r ... right

                    The default value is 'bl'

        """
        if timestamp:
            #text = now()
            text = time.asctime(time.localtime(time.time()))
        buffer, width, height = self.getBuffer()
        if buffer:
            im = Image.fromstring('RGB', (width, height), buffer, 'raw', 'BGR', 0, -1)
            if timestamp:
                if boldfont:
                    self.font = self.boldfont
                else:
                    self.font = self.normalfont
                tw, th = self.font.getsize(text)
                tw -= 2
                th -= 2
                if 't' in textpos:
                    y = -1
                elif 'b' in textpos:
                    y = height - th - 2
                else:
                    raise ValueError, "textpos must contain exactly one out of 't', 'b'"
                if 'l' in textpos:
                    x = 2
                elif 'c' in textpos:
                    x = (width - tw) / 2
                elif 'r' in textpos:
                    x = (width - tw) - 2
                else:
                    raise ValueError, "textpos must contain exactly one out of 'l', 'c', 'r'"
                draw = ImageDraw.Draw(im)
                if timestamp == 2: # shadow
                    draw.text((x+1, y), text, font=self.font, fill=shadowcolor)
                    draw.text((x, y+1), text, font=self.font, fill=shadowcolor)
                    draw.text((x+1, y+1), text, font=self.font, fill=shadowcolor)
                else:
                    if timestamp >= 3: # thin border
                        draw.text((x-1, y), text, font=self.font, fill=shadowcolor)
                        draw.text((x+1, y), text, font=self.font, fill=shadowcolor)
                        draw.text((x, y-1), text, font=self.font, fill=shadowcolor)
                        draw.text((x, y+1), text, font=self.font, fill=shadowcolor)
                    if timestamp == 4: # thick border
                        draw.text((x-1, y-1), text, font=self.font, fill=shadowcolor)
                        draw.text((x+1, y-1), text, font=self.font, fill=shadowcolor)
                        draw.text((x-1, y+1), text, font=self.font, fill=shadowcolor)
                        draw.text((x+1, y+1), text, font=self.font, fill=shadowcolor)
                draw.text((x, y), text, font=self.font, fill=textcolor)
            return im

    def saveSnapshot(self, filename, timestamp=0, boldfont=0, textpos=default_textpos, **keywords):
        """Saves a snapshot to the harddisk.

        The filetype depends on the filename extension.  Everything that PIL
        can handle can be specified (foo.jpg, foo.gif, foo.bmp, ...).

        filename:   String containing the name of the resulting file.

        timestamp:  see getImage()

        boldfont:   see getImage()

        textpos:    see getImage()

        Additional keyword arguments can be give which are just passed to the
        save() method of the Image class.  For example you can specify the
        compression level of a JPEG image by quality=75 (which is the default
        value anyway).

        """
        self.getImage(timestamp, boldfont, textpos).save(filename, **keywords)

if __name__ == '__main__':
    import shutil
    #shutil.copy('VideoCapture.py', 'C:\Python20\Lib')
    #shutil.copy('VideoCapture.py', 'C:\Python21\Lib')
    #shutil.copy('VideoCapture.py', 'C:\Python22\Lib')
    #shutil.copy('VideoCapture.py', 'C:\Python23\Lib')
    #shutil.copy('VideoCapture.py', 'C:\Python24\Lib')
    #shutil.copy('VideoCapture.py', 'C:\Python25\Lib')
    cam = Device(devnum=0)
    #~ #cam.displayPropertyPage() ## deprecated
    #~ #cam.displayCaptureFilterProperties()
    #~ #cam.displayCapturePinProperties()
    #~ #cam.setResolution(768, 576) ## PAL
    #~ #cam.setResolution(352, 288) ## CIF
    #~ cam.saveSnapshot('test.jpg', quality=75, timestamp=3, boldfont=1)
    print "Friendly name: ", cam.getDisplayName()
