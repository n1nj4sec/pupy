#Author: @bobsecq
#Contributor(s):

from jnius import autoclass, cast

def getAllAps():
    '''
    Returns all applications installed [{'packageName':packageName, 'sourceDir':sourceDirectory}, etc]
    '''
    infos = []
    pythonService = autoclass("org.renpy.android.PythonService")
    PackageManager= autoclass("android.content.pm.PackageManager")
    activity = cast("android.app.Service", pythonService.mService)
    pm = activity.getPackageManager()
    packages = pm.getInstalledApplications(PackageManager.GET_META_DATA)
    for appNb in range(packages.size()):
        appInfo = packages.get(appNb)
        packageName = appInfo.packageName
        sourceDir = appInfo.sourceDir
        dataDir  = appInfo.dataDir
        processName = appInfo.processName
        publicSourceDir = appInfo.publicSourceDir
        sharedLibraryFiles = appInfo.sharedLibraryFiles
        packagePerms = pm.getPackageInfo(appInfo.packageName, PackageManager.GET_PERMISSIONS)
        requestedPermissions = packagePerms.requestedPermissions
        permissions = []
        if requestedPermissions is not None:
            for i in range(len(requestedPermissions)):
                permissions.append(requestedPermissions[i])
        infos.append({"packageName":packageName,
            "sourceDir":sourceDir,
            "dataDir":dataDir,
            "processName":processName,
            "publicSourceDir":publicSourceDir,
            "sharedLibraryFiles":sharedLibraryFiles,
            "permissions":permissions,
            })
    return infos
