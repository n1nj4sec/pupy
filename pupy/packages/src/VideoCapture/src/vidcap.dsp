# Microsoft Developer Studio Project File - Name="vidcap" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

CFG=vidcap - Win32 Python20
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE
!MESSAGE NMAKE /f "vidcap.mak".
!MESSAGE
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE
!MESSAGE NMAKE /f "vidcap.mak" CFG="vidcap - Win32 Python20"
!MESSAGE
!MESSAGE Possible choices for configuration are:
!MESSAGE
!MESSAGE "vidcap - Win32 Python20" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "vidcap - Win32 Python21" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "vidcap - Win32 Python22" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "vidcap - Win32 Python23" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "vidcap - Win32 Python24" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "vidcap - Win32 Python25" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "vidcap - Win32 Python20"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "vidcap___Win32_Python20"
# PROP BASE Intermediate_Dir "vidcap___Win32_Python20"
# PROP BASE Ignore_Export_Lib 0
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Python20"
# PROP Intermediate_Dir "Python20"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MD /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "VPDCAP_EXPORTS" /YX /FD /c
# ADD CPP /nologo /MD /W3 /GX /O2 /I "c:\PYTHON20\INCLUDE" /I "c:\DXSDK\include" /I "c:\DXSDK\samples\Multimedia\DirectShow\BaseClasses" /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "VPDCAP_EXPORTS" /YX /FD /c
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x809 /d "NDEBUG"
# ADD RSC /l 0x809 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 python20.lib strmiids.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /machine:I386 /out:"Release/vidcap.pyd"
# SUBTRACT BASE LINK32 /map /nodefaultlib
# ADD LINK32 c:\DXSDK\samples\Multimedia\DirectShow\BaseClasses\Release\STRMBASE.lib strmiids.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /machine:I386 /nodefaultlib:"libcmt" /out:"Python20/vidcap.pyd" /libpath:"c:\PYTHON20\LIBS" /libpath:"c:\DXSDK\lib"
# SUBTRACT LINK32 /pdb:none
# Begin Custom Build
TargetPath=.\Python20\vidcap.pyd
InputPath=.\Python20\vidcap.pyd
SOURCE="$(InputPath)"

"c:\Python20\DLLs\vidcap.pyd" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(TargetPath) "c:\python20\DLLs"

# End Custom Build

!ELSEIF  "$(CFG)" == "vidcap - Win32 Python21"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "vidcap___Win32_Python21"
# PROP BASE Intermediate_Dir "vidcap___Win32_Python21"
# PROP BASE Ignore_Export_Lib 0
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Python21"
# PROP Intermediate_Dir "Python21"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MD /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "VPDCAP_EXPORTS" /YX /FD /c
# ADD CPP /nologo /MD /W3 /GX /O2 /I "c:\PYTHON21\INCLUDE" /I "c:\DXSDK\include" /I "c:\DXSDK\samples\Multimedia\DirectShow\BaseClasses" /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "VPDCAP_EXPORTS" /YX /FD /c
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x809 /d "NDEBUG"
# ADD RSC /l 0x809 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 python20.lib strmiids.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /machine:I386 /out:"Release/vidcap.pyd"
# SUBTRACT BASE LINK32 /map /nodefaultlib
# ADD LINK32 c:\DXSDK\samples\Multimedia\DirectShow\BaseClasses\Release\STRMBASE.lib strmiids.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /machine:I386 /nodefaultlib:"libcmt" /out:"Python21/vidcap.pyd" /libpath:"c:\PYTHON21\LIBS" /libpath:"c:\DXSDK\lib"
# SUBTRACT LINK32 /pdb:none /nodefaultlib
# Begin Custom Build
TargetPath=.\Python21\vidcap.pyd
InputPath=.\Python21\vidcap.pyd
SOURCE="$(InputPath)"

"c:\Python21\DLLs\vidcap.pyd" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(TargetPath) "c:\python21\DLLs"

# End Custom Build

!ELSEIF  "$(CFG)" == "vidcap - Win32 Python22"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "vidcap___Win32_Python22"
# PROP BASE Intermediate_Dir "vidcap___Win32_Python22"
# PROP BASE Ignore_Export_Lib 0
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Python22"
# PROP Intermediate_Dir "Python22"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MD /W3 /GX /O2 /I "c:\PYTHON22\INCLUDE" /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "VPDCAP_EXPORTS" /YX /FD /c
# ADD CPP /nologo /MD /W3 /GX /O2 /I "c:\PYTHON22\INCLUDE" /I "c:\DXSDK\include" /I "c:\DXSDK\samples\Multimedia\DirectShow\BaseClasses" /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "VPDCAP_EXPORTS" /YX /FD /c
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x809 /d "NDEBUG"
# ADD RSC /l 0x809 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 strmiids.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /machine:I386 /out:"Python21/vidcap.pyd" /libpath:"c:\PYTHON21\LIBS"
# SUBTRACT BASE LINK32 /pdb:none
# ADD LINK32 c:\DXSDK\samples\Multimedia\DirectShow\BaseClasses\Release\STRMBASE.lib strmiids.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /machine:I386 /nodefaultlib:"libcmt" /out:"Python22/vidcap.pyd" /libpath:"c:\PYTHON22\LIBS" /libpath:"c:\DXSDK\lib"
# SUBTRACT LINK32 /pdb:none /nodefaultlib
# Begin Custom Build
TargetPath=.\Python22\vidcap.pyd
InputPath=.\Python22\vidcap.pyd
SOURCE="$(InputPath)"

"c:\Python22\DLLs\vidcap.pyd" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(TargetPath) "c:\python22\DLLs"

# End Custom Build

!ELSEIF  "$(CFG)" == "vidcap - Win32 Python23"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "vidcap___Win32_Python23"
# PROP BASE Intermediate_Dir "vidcap___Win32_Python23"
# PROP BASE Ignore_Export_Lib 0
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Python23"
# PROP Intermediate_Dir "Python23"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MD /W3 /GX /O2 /I "c:\PYTHON23\INCLUDE" /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "VPDCAP_EXPORTS" /YX /FD /c
# ADD CPP /nologo /MD /W3 /GX /O2 /I "c:\PYTHON23\INCLUDE" /I "c:\DXSDK\include" /I "c:\DXSDK\samples\Multimedia\DirectShow\BaseClasses" /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "VPDCAP_EXPORTS" /YX /FD /c
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x809 /d "NDEBUG"
# ADD RSC /l 0x809 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 strmiids.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /machine:I386 /out:"Python23/vidcap.pyd" /libpath:"c:\PYTHON23\LIBS"
# SUBTRACT BASE LINK32 /pdb:none
# ADD LINK32 c:\DXSDK\samples\Multimedia\DirectShow\BaseClasses\Release\STRMBASE.lib strmiids.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /machine:I386 /nodefaultlib:"libcmt" /out:"Python23/vidcap.pyd" /libpath:"c:\PYTHON23\LIBS" /libpath:"c:\DXSDK\lib"
# SUBTRACT LINK32 /pdb:none
# Begin Custom Build
TargetPath=.\Python23\vidcap.pyd
InputPath=.\Python23\vidcap.pyd
SOURCE="$(InputPath)"

"c:\Python23\DLLs\vidcap.pyd" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(TargetPath) "c:\python23\DLLs"

# End Custom Build

!ELSEIF  "$(CFG)" == "vidcap - Win32 Python24"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "vidcap___Win32_Python24"
# PROP BASE Intermediate_Dir "vidcap___Win32_Python24"
# PROP BASE Ignore_Export_Lib 0
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Python24"
# PROP Intermediate_Dir "Python24"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MD /W3 /GX /O2 /I "c:\PYTHON24\INCLUDE" /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "VPDCAP_EXPORTS" /YX /FD /c
# ADD CPP /nologo /MD /W3 /GX /O2 /I "c:\PYTHON24\INCLUDE" /I "c:\DXSDK\include" /I "c:\DXSDK\samples\Multimedia\DirectShow\BaseClasses" /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "VPDCAP_EXPORTS" /YX /FD /c
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x809 /d "NDEBUG"
# ADD RSC /l 0x809 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 strmiids.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /machine:I386 /out:"Python24/vidcap.pyd" /libpath:"c:\PYTHON24\LIBS"
# SUBTRACT BASE LINK32 /pdb:none
# ADD LINK32 c:\DXSDK\samples\Multimedia\DirectShow\BaseClasses\Release\STRMBASE.lib strmiids.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /machine:I386 /nodefaultlib:"libcmt" /out:"Python24/vidcap.pyd" /libpath:"c:\PYTHON24\LIBS" /libpath:"c:\DXSDK\lib"
# SUBTRACT LINK32 /pdb:none
# Begin Custom Build
TargetPath=.\Python24\vidcap.pyd
InputPath=.\Python24\vidcap.pyd
SOURCE="$(InputPath)"

"c:\Python24\DLLs\vidcap.pyd" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(TargetPath) "c:\python24\DLLs"

# End Custom Build

!ELSEIF  "$(CFG)" == "vidcap - Win32 Python25"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "vidcap___Win32_Python25"
# PROP BASE Intermediate_Dir "vidcap___Win32_Python25"
# PROP BASE Ignore_Export_Lib 0
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Python25"
# PROP Intermediate_Dir "Python25"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MD /W3 /GX /O2 /I "c:\PYTHON25\INCLUDE" /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "VPDCAP_EXPORTS" /YX /FD /c
# ADD CPP /nologo /MD /W3 /GX /O2 /I "c:\PYTHON25\INCLUDE" /I "c:\DXSDK\include" /I "c:\DXSDK\samples\Multimedia\DirectShow\BaseClasses" /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "VPDCAP_EXPORTS" /YX /FD /c
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x809 /d "NDEBUG"
# ADD RSC /l 0x809 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 strmiids.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /machine:I386 /out:"Python25/vidcap.pyd" /libpath:"c:\PYTHON25\LIBS"
# SUBTRACT BASE LINK32 /pdb:none
# ADD LINK32 c:\DXSDK\samples\Multimedia\DirectShow\BaseClasses\Release\STRMBASE.lib strmiids.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /machine:I386 /nodefaultlib:"libcmt" /out:"Python25/vidcap.pyd" /libpath:"c:\PYTHON25\LIBS" /libpath:"c:\DXSDK\lib"
# SUBTRACT LINK32 /pdb:none
# Begin Custom Build
TargetPath=.\Python25\vidcap.pyd
InputPath=.\Python25\vidcap.pyd
SOURCE="$(InputPath)"

"c:\Python25\DLLs\vidcap.pyd" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(TargetPath) "c:\python25\DLLs"

# End Custom Build

!ENDIF

# Begin Target

# Name "vidcap - Win32 Python20"
# Name "vidcap - Win32 Python21"
# Name "vidcap - Win32 Python22"
# Name "vidcap - Win32 Python23"
# Name "vidcap - Win32 Python24"
# Name "vidcap - Win32 Python25"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=.\vidcapmodule.cpp
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# End Group
# Begin Group "Resource Files"

# PROP Default_Filter "ico;cur;bmp;dlg;rc2;rct;bin;rgs;gif;jpg;jpeg;jpe"
# End Group
# End Target
# End Project
