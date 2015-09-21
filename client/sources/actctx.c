#include "actctx.h"

HANDLE PyWin_DLLhActivationContext=NULL;
PFN_GETCURRENTACTCTX pfnGetCurrentActCtx=NULL;
PFN_ACTIVATEACTCTX pfnActivateActCtx=NULL;
PFN_DEACTIVATEACTCTX pfnDeactivateActCtx=NULL;
PFN_ADDREFACTCTX pfnAddRefActCtx=NULL;
PFN_RELEASEACTCTX pfnReleaseActCtx=NULL;

ULONG_PTR _My_ActivateActCtx()
{
	ULONG_PTR ret = 0;
	if (PyWin_DLLhActivationContext && pfnActivateActCtx)
		if (!(*pfnActivateActCtx)(PyWin_DLLhActivationContext, &ret)) {
			ret = 0; // no promise the failing function didn't change it!
		}
	return ret;
}

void _My_DeactivateActCtx(ULONG_PTR cookie)
{
	if (cookie && pfnDeactivateActCtx)
		if (!(*pfnDeactivateActCtx)(0, cookie)){}
}

