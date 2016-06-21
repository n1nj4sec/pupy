import os
import re

#https://stackoverflow.com/questions/1035340/reading-binary-file-in-python-and-looping-over-each-byte
def bytes_from_file(filename, chunksize=8192):
    if os.path.isfile(filename) and os.access(filename, os.R_OK):
        with open(filename, "rb") as f:
            while True:
                chunk = f.read(chunksize)
                if chunk:
                    yield chunk
                    #for b in chunk:
                        #yield b
                else:
                    f.close()
                    break

def scan_files(fpath, ftype, fstring = ""):
    if ftype == "extension":
        if fpath.endswith(fext):
            print fpath

    elif ftype == "string":
        for b in bytes_from_file(fpath):
            if re.findall('\\b' + fstring + '\\b', b, flags=re.IGNORECASE):
                print fpath
                break

    elif ftype == "mix":
        if fpath.endswith(fext):
            for b in bytes_from_file(fpath):
                if re.findall('\\b' + fstring + '\\b', b, flags=re.IGNORECASE):
                    print fpath
                    break

def run(checkdir, dirdepth, ftype, fext, fstring):
    #https://stackoverflow.com/questions/3964681/find-all-files-in-directory-with-extension-txt-in-python
    if dirdepth == "traverse":
        for root, dirs, files in os.walk(checkdir):
            fpath = os.path.join(root, file)
            for file in files:
                scan_files(fpath, ftype, fstring)
    elif dirdepth == "current":
        for file in os.listdir(checkdir):
            fpath = os.path.join(checkdir, file)
            scan_files(fpath, ftype, fstring)

if __name__ == '__main__':

    checkdir = "C:\\"
    dirdepth = "current"
    ftype = "string"
    fext = ".exe"
    fstring = "find"

    run(checkdir, dirdepth, ftype, fext, fstring)
