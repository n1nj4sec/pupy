from rpyc.utils.classic import upload
import base64
import tempfile
import gzip
import StringIO
import subprocess
import os

ROOT=os.path.abspath(os.path.join(os.path.dirname(__file__),"..", "..", ".."))

def execute_powershell_script(module, content, function):
    template = open(os.path.join(ROOT, "modules", "lib", "utils", "upload_powershell_script_template.ps1"), 'r').read()
    
    # compress the content of the script to upload
    out = StringIO.StringIO()
    with gzip.GzipFile(fileobj=out, mode="w") as f:
      f.write(content)

    # encode the gzip content in base64
    encoded = base64.b64encode(out.getvalue())

    # replace meta data from the template
    template = template.replace('[BASE64]', encoded)
    template = template.replace('[FUNCTION_NAME]', function)
    
    output = ""
    # execute of the powershell script in memory if the size is lower of the max size
    if len(template) < 32710:
        module.success("Executing the powershell code on memory")
        cmd = []
        cmd.append('powershell.exe')
        cmd.append('/c')
        cmd.append(template)
        output = module.client.conn.modules.subprocess.check_output(cmd, stderr=subprocess.STDOUT, stdin=subprocess.PIPE, universal_newlines=True)
    else:
        tf = tempfile.NamedTemporaryFile()
        f = open(tf.name, 'w')
        f.write(template)
        f.close()
        
        remoteTempFolder = module.client.conn.modules['os.path'].expandvars("%TEMP%")
        tfName = tf.name.split(os.sep)
        tfName = tfName[len(tfName)-1]
        
        module.success("Uploading powershell code to: %s\%s.ps1" % (remoteTempFolder, tfName))
        upload(module.client.conn, tf.name, module.client.conn.modules['os.path'].join(remoteTempFolder, '%s.ps1' % tfName))

        module.success("Executing the powershell code")
        output = module.client.conn.modules.subprocess.check_output("PowerShell.exe -ExecutionPolicy Bypass -File %s.ps1"%(module.client.conn.modules['os.path'].join(remoteTempFolder, tfName)), stderr=subprocess.STDOUT, stdin=subprocess.PIPE, shell = True)
        
        module.success("Removing the powershell code")
        module.client.conn.modules.subprocess.check_output("cmd.exe del %s.ps1" % (module.client.conn.modules['os.path'].join(remoteTempFolder, tfName)), stderr=subprocess.STDOUT, stdin=subprocess.PIPE, shell = True)

    return output