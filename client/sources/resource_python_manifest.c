
#ifdef _WIN64
	const char resource_python_manifest[]="<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n"
"<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">\n"
"<trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">\n"
"<security>\n"
"<requestedPrivileges>\n"
"<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>\n"
"</requestedPrivileges>\n"
"</security>\n"
"</trustInfo>\n"
"<dependency>\n"
"<dependentAssembly>\n"
"<assemblyIdentity type=\"win32\" name=\"Microsoft.VC90.CRT\" version=\"9.0.21022.8\" processorArchitecture=\"amd64\" publicKeyToken=\"1fc8b3b9a1e18e3b\"></assemblyIdentity>\n"
"</dependentAssembly>\n"
"</dependency>\n"
"</assembly>\n";
#else
	const char resource_python_manifest[]="<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n"
"<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">\n"
"<trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">\n"
"<security>\n"
"<requestedPrivileges>\n"
"<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>\n"
"</requestedPrivileges>\n"
"</security>\n"
"</trustInfo>\n"
"<dependency>\n"
"<dependentAssembly>\n"
"<assemblyIdentity type=\"win32\" name=\"Microsoft.VC90.CRT\" version=\"9.0.21022.8\" processorArchitecture=\"x86\" publicKeyToken=\"1fc8b3b9a1e18e3b\"></assemblyIdentity>\n"
"</dependentAssembly>\n"
"</dependency>\n"
"</assembly>\n";
#endif

