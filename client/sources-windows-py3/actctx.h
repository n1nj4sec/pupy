#include <windows.h>
#include <stdio.h>
#include <olectl.h>

#include <assert.h>
// Windows "Activation Context" work:
// Our .pyd extension modules are generally built without a manifest (ie,
// those included with Python and those built with a default distutils.
// This requires we perform some "activation context" magic when loading our
// extensions.  In summary:
// * As our DLL loads we save the context being used.
// * Before loading our extensions we re-activate our saved context.
// * After extension load is complete we restore the old context.
// As an added complication, this magic only works on XP or later - we simply
// use the existence (or not) of the relevant function pointers from kernel32.
// See bug 4566 (http://python.org/sf/4566) for more details.
#ifdef __cplusplus
extern "C" {
#endif

typedef BOOL (WINAPI * PFN_GETCURRENTACTCTX)(HANDLE *);
typedef BOOL (WINAPI * PFN_ACTIVATEACTCTX)(HANDLE, ULONG_PTR *);
typedef BOOL (WINAPI * PFN_DEACTIVATEACTCTX)(DWORD, ULONG_PTR);
typedef BOOL (WINAPI * PFN_ADDREFACTCTX)(HANDLE);
typedef BOOL (WINAPI * PFN_RELEASEACTCTX)(HANDLE);

// locals and function pointers for this activation context magic.
extern HANDLE PyWin_DLLhActivationContext;
extern PFN_GETCURRENTACTCTX pfnGetCurrentActCtx;
extern PFN_ACTIVATEACTCTX pfnActivateActCtx;
extern PFN_DEACTIVATEACTCTX pfnDeactivateActCtx;
extern PFN_ADDREFACTCTX pfnAddRefActCtx;
extern PFN_RELEASEACTCTX pfnReleaseActCtx;

void _MyLoadActCtxPointers();
ULONG_PTR _My_ActivateActCtx();
void _My_DeactivateActCtx(ULONG_PTR cookie);

#ifdef __cplusplus
}
#endif
