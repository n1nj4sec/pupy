#include "stdafx.h"

// vidcapmodule.cpp
// by Markus Gritsch <gritsch@iue.tuwien.ac.at>

// code plugged together from
// http://www.python.org/doc/current/ext/ext.html
// and
// http://msdn.microsoft.com/library/default.asp?url=/library/en-us/dx8_c/directx_cpp/htm/howtowriteacaptureapplication.asp
// http://msdn.microsoft.com/library/default.asp?url=/library/en-us/dx8_c/directx_cpp/htm/usingthesamplegrabber.asp
// http://msdn.microsoft.com/library/default.asp?url=/library/en-us/dx8_c/directx_cpp/htm/playcapsample.asp
// http://msdn.microsoft.com/library/default.asp?url=/library/en-us/dx8_c/directx_cpp/htm/displayingafilterspropertypages.asp


#include "Python.h"

#include <dshow.h>
//#include <qedit.h>  // Sample Grabber, Null Renderer  
#include "qedit.h"  // Deprecated and no longer included in the Windows SDK
#include <mtype.h> // DirectShow Base Classes - FreeMediaType(), DeleteMediaType()

static PyObject *VidcapError;

//staticforward PyTypeObject Dev_Type; // does not work for Python 2.3 anymore
extern PyTypeObject Dev_Type; // suggested by Jon Schneider <jon@jschneider.net>


typedef struct {
    PyObject_HEAD

    IGraphBuilder         *ob_pGraph;
    ICaptureGraphBuilder2 *ob_pBuilder;
    IBaseFilter           *ob_pSrc;
    ISampleGrabber        *ob_pGrab;
    IMediaControl         *ob_pControl;

    int devnum;
    int showVideoWindow;
    IPropertyBag	  *ob_pPropBag;

} DevObject;


static void
cleanup(DevObject *self)
{
    if (self->ob_pControl != NULL)
        self->ob_pControl->Stop();

    if (self->ob_pControl != NULL)
        self->ob_pControl->Release();
    //self->ob_pControl = NULL;
    if (self->ob_pGrab != NULL)
        self->ob_pGrab->Release();
    //self->ob_pGrab = NULL;
    if (self->ob_pSrc != NULL)
        self->ob_pSrc->Release();
    //self->ob_pSrc = NULL;
    if (self->ob_pBuilder != NULL)
        self->ob_pBuilder->Release();
    //self->ob_pBuilder = NULL;
    if (self->ob_pGraph != NULL)
        self->ob_pGraph->Release();
    //self->ob_pGraph = NULL;
    if (self->ob_pPropBag != NULL)
	self->ob_pPropBag->Release();	
    //self->ob_pPropBag = NULL;
}


static bool
initialize(DevObject *self)
{
    HRESULT hr;


    // Creating the Required Components
    // ================================

    // Create the filter graph.
    hr = CoCreateInstance(CLSID_FilterGraph, NULL, CLSCTX_INPROC,
                          IID_IGraphBuilder, (void **)&self->ob_pGraph);
    if (FAILED(hr))
    {
        PyErr_SetString(VidcapError, "Creation of the filter graph failed.");
        cleanup(self);
        return FALSE;
    }

    // Create the capture graph builder.
    hr = CoCreateInstance(CLSID_CaptureGraphBuilder2, NULL, CLSCTX_INPROC,
                          IID_ICaptureGraphBuilder2, (void **)&self->ob_pBuilder);
    if (FAILED(hr))
    {
        PyErr_SetString(VidcapError, "Creation of the capture graph builder failed.");
        cleanup(self);
        return FALSE;
    }

    hr = self->ob_pBuilder->SetFiltergraph(self->ob_pGraph);
    if (FAILED(hr))
    {
        PyErr_SetString(VidcapError, "Setting the filter graph for the capture graph builder failed.");
        cleanup(self);
        return FALSE;
    }


    // Selecting a Capture Device
    // ==========================

    // Create the system device enumerator.
    ICreateDevEnum *pDevEnum = NULL;
    hr = CoCreateInstance(CLSID_SystemDeviceEnum, NULL, CLSCTX_INPROC,
                          IID_ICreateDevEnum, (void **)&pDevEnum);
    if (FAILED(hr))
    {
        PyErr_SetString(VidcapError, "Creation of the system device enumerator failed.");
        cleanup(self);
        return FALSE;
    }

    // Create an enumerator for video capture devices.
    IEnumMoniker *pClassEnum = NULL;
    hr = pDevEnum->CreateClassEnumerator(CLSID_VideoInputDeviceCategory, &pClassEnum, 0);
    pDevEnum->Release();
    if (hr != S_OK) // fix by Jonathan Viney <jonathan@bluewire.net.nz> "doing FAILED(hr) isn't a good enough check"
    {
        PyErr_SetString(VidcapError, "Creation of the enumerator for video capture devices failed.");
        cleanup(self);
        return FALSE;
    }

    ULONG cFetched;
    IMoniker *pMoniker = NULL;
    for (int i=0; i <= self->devnum; i++)
    {
        if (pClassEnum->Next(1, &pMoniker, &cFetched) != S_OK)
        {
            PyErr_SetString(VidcapError, "The device with the specified device number does not exist.");
            pClassEnum->Release();
            cleanup(self);
            return FALSE;
        }
    }
    pClassEnum->Release();

    // Bind the moniker to a filter object.
    if (self->ob_pSrc == NULL)
    {
        hr = pMoniker->BindToObject(0, 0, IID_IBaseFilter, (void**)&self->ob_pSrc);
        if (FAILED(hr))
        {
            PyErr_SetString(VidcapError, "Binding the moniker to a filter object failed.");
            cleanup(self);
            return FALSE;
        }
    }

	// Obtain friendly name for Moniker
	// http://msdn.microsoft.com/en-us/library/windows/desktop/dd407292%28v=vs.85%29.aspx   
	
    hr = pMoniker->BindToStorage(0, 0, IID_IPropertyBag, (void **)&self->ob_pPropBag);
    if (FAILED(hr))
    {
        PyErr_SetString(VidcapError, "Fetching the moniker property bag failed.");
        cleanup(self);
        return FALSE;
    }
    pMoniker->Release();
	
    // Now add the capture filter to the graph
    hr = self->ob_pGraph->AddFilter(self->ob_pSrc, L"VideoCapture");
    if (FAILED(hr))
    {
        PyErr_SetString(VidcapError, "Adding the capture filter to the filter graph failed.\n              Device maybe not connected or already in use.");
        cleanup(self);
        return FALSE;
    }


    // Adding the Sample Grabber to the Filter Graph
    // =============================================

    IBaseFilter     *pF = NULL;
    AM_MEDIA_TYPE   mt;

    hr = CoCreateInstance(CLSID_SampleGrabber, NULL, CLSCTX_INPROC,
                          IID_IBaseFilter, (LPVOID *)&pF);
    if (FAILED(hr))
    {
        PyErr_SetString(VidcapError, "Creation of the sample grabber failed.");
        cleanup(self);
        return FALSE;
    }

    hr = pF->QueryInterface(IID_ISampleGrabber, (void **)&self->ob_pGrab);
    if (FAILED(hr))
    {
        PyErr_SetString(VidcapError, "Sample grabber interface could not be found.");
        cleanup(self);
        return FALSE;
    }

    hr = self->ob_pGraph->AddFilter(pF, L"Grabber");
    if (FAILED(hr))
    {
        PyErr_SetString(VidcapError, "Adding the sample grabber to the filter graph failed.");
        cleanup(self);
        return FALSE;
    }

    ZeroMemory(&mt, sizeof(AM_MEDIA_TYPE));
    mt.majortype = MEDIATYPE_Video;
    mt.subtype = MEDIASUBTYPE_RGB24;
    mt.formattype = FORMAT_VideoInfo;
    hr = self->ob_pGrab->SetMediaType(&mt);
    if (FAILED(hr))
    {
        PyErr_SetString(VidcapError, "Setting the media type of the sample grabber failed.");
        cleanup(self);
        return FALSE;
    }

/*    IBaseFilter *pNullRenderer = NULL;
    hr = CoCreateInstance(CLSID_NullRenderer, NULL, CLSCTX_INPROC,
                          IID_IBaseFilter, (LPVOID *)&pNullRenderer);
    hr = self->ob_pGraph->AddFilter(pNullRenderer, L"Nuller");
*/

    // Rendering the Streams
    // =====================

    hr = self->ob_pBuilder->RenderStream(
            &PIN_CATEGORY_CAPTURE, // changed from ..._PREVIEW to ..._CAPTURE
            &MEDIATYPE_Video,
            self->ob_pSrc, // src
            pF,            // via
            NULL           // dest ; or pNullRenderer
        );
    if (FAILED(hr))
    {
        PyErr_SetString(VidcapError, "Capture Graph could not be created.");
        cleanup(self);
        return FALSE;
    }

    pF->Release();
    //pNullRenderer->Release();


    // Controlling a Capture Graph
    // ===========================

    if (!self->showVideoWindow)
    {
        IVideoWindow *pWindow;

        hr = self->ob_pGraph->QueryInterface(IID_IVideoWindow, (void **)&pWindow);
        if (FAILED(hr))
        {
            PyErr_SetString(VidcapError, "Video Window interface could not be found.");
            cleanup(self);
            return FALSE;
        }

        hr = pWindow->put_AutoShow(OAFALSE);
        if (FAILED(hr))
        {
            PyErr_SetString(VidcapError, "Video Window hiding failed.");
            cleanup(self);
            return FALSE;
        }

        pWindow->Release();
    }

    hr = self->ob_pGraph->QueryInterface(IID_IMediaControl, (void **)&self->ob_pControl);
    if (FAILED(hr))
    {
        PyErr_SetString(VidcapError, "Media control interface could not be found.");
        cleanup(self);
        return FALSE;
    }


    hr = self->ob_pGrab->SetBufferSamples(TRUE);
    if (FAILED(hr))
    {
        PyErr_SetString(VidcapError, "Setting up buffering of samples failed.");
        cleanup(self);
        return FALSE;
    }

    // Set up one-shot mode.
    hr = self->ob_pGrab->SetOneShot(FALSE);
    if (FAILED(hr))
    {
        PyErr_SetString(VidcapError, "Setting up non-one-shot mode of the sample grabber failed.");
        cleanup(self);
        return FALSE;
    }

    //self->ob_pSrc->SetSyncSource(NULL); // Turn off the reference clock.

/*
    Once the filtergraph was started, the resolution of my webcam can not be changed.
    Workaround: So it is started in Dev_getbuffer() (fixme: xxx)
    This is only an intermediate solution, since this way changing the solution works
    only if no snapshot has already been taken.

    Update 18.9.2003: Seems to work now since
            teardown(self); //xxx                   Better *do* teardown and
                        initialize(self); //xxx         initialize for my Webcam.
        have been inserted into Dev_displaycapturefilterproperties().
*/
/*    
    hr = self->ob_pControl->Run(); // Run the graph.
    if (FAILED(hr)) // The graph is preparing to run, but some filters have
    {               // not completed the transition to a running state.
        OAFilterState pfs;
        hr = self->ob_pControl->GetState(6000, &pfs);
        if (FAILED(hr))
        {
            switch (hr)
            {
            case VFW_S_STATE_INTERMEDIATE:
                PyErr_SetString(VidcapError, "Running the capture graph failed (filter graph still in transition).");
                break;
            case VFW_S_CANT_CUE:
                PyErr_SetString(VidcapError, "Running the capture graph failed (cannot cue data).");
                break;
            case E_FAIL:
                PyErr_SetString(VidcapError, "Running the capture graph failed (failure).");
                break;
            default:
                PyErr_SetString(VidcapError, "UNKNOWN CASE!!");
            }
            return NULL;
        }
    }
*/

    return TRUE;
}


static DevObject *
newDevObject(PyObject *args)
{
    DevObject *self;
    self = PyObject_New(DevObject, &Dev_Type);
    if (self == NULL)
        return NULL;

    if (!PyArg_ParseTuple(args, "ii:newDev", &self->devnum, &self->showVideoWindow))
        return NULL;

    self->ob_pGraph   = NULL;
    self->ob_pBuilder = NULL;
    self->ob_pSrc     = NULL;
    self->ob_pGrab    = NULL;
    self->ob_pControl = NULL;
	self->ob_pPropBag    = NULL;

    if (initialize(self))
        return self;
    else
        return NULL;
}


static void
Dev_dealloc(DevObject *self)
{
    cleanup(self);

    PyObject_Del(self);
}


static void
teardown(DevObject *self)
{
    if (self->ob_pControl != NULL)
        self->ob_pControl->Stop();

    if (self->ob_pControl != NULL)
        self->ob_pControl->Release();
    self->ob_pControl = NULL;
    if (self->ob_pGrab != NULL)
        self->ob_pGrab->Release();
    self->ob_pGrab = NULL;
    // don't touch self->ob_pSrc
    if (self->ob_pBuilder != NULL)
        self->ob_pBuilder->Release();
    self->ob_pBuilder = NULL;
    if (self->ob_pGraph != NULL)
        self->ob_pGraph->Release();
    self->ob_pGraph = NULL;
	if (self->ob_pPropBag != NULL)
		self->ob_pPropBag->Release();	
	self->ob_pPropBag = NULL;
}

/*
// Tear down everything downstream of a given filter
static void
NukeDownstream(DevObject *self, IBaseFilter *pf)
{
    //DbgLog((LOG_TRACE,1,TEXT("Nuking...")));

    IPin *pP, *pTo;
    ULONG u;
    IEnumPins *pins = NULL;
    PIN_INFO pininfo;
    HRESULT hr = pf->EnumPins(&pins);
    pins->Reset();
    while(hr == NOERROR) {
        hr = pins->Next(1, &pP, &u);
        if(hr == S_OK && pP) {
            pP->ConnectedTo(&pTo);
            if(pTo) {
                hr = pTo->QueryPinInfo(&pininfo);
                if(hr == NOERROR) {
                    if(pininfo.dir == PINDIR_INPUT) {
                        NukeDownstream(self, pininfo.pFilter);
                        self->ob_pGraph->Disconnect(pTo);
                        self->ob_pGraph->Disconnect(pP);
                        self->ob_pGraph->RemoveFilter(pininfo.pFilter);
                    }
                    pininfo.pFilter->Release();
                }
                pTo->Release();
            }
            pP->Release();
        }
    }
    if(pins)
        pins->Release();
}
*/

static PyObject *
Dev_displaypropertypage(DevObject *self, PyObject *args)
{
    MessageBox(NULL,
               TEXT("displayPropertyPage() is deprecated.\nUse displayCaptureFilterProperties() and displayCapturePinProperties() instead!"),
               TEXT("VideoCapture Warning"), 
			   MB_OK | MB_ICONWARNING | MB_TASKMODAL);

    HRESULT hr;
    hr = self->ob_pControl->Stop(); //xxx
    if (FAILED(hr))
    {
        PyErr_SetString(VidcapError, "Stopping the capture graph failed.");
        return NULL;
    }
    //NukeDownstream(self, self->ob_pSrc);

    ISpecifyPropertyPages *pProp;
    hr = self->ob_pSrc->QueryInterface(IID_ISpecifyPropertyPages, (void **)&pProp);
    if (SUCCEEDED(hr))
    {
        // Get the filter's name and IUnknown pointer.
        FILTER_INFO FilterInfo;
        self->ob_pSrc->QueryFilterInfo(&FilterInfo);
        IUnknown *pFilterUnk;
        self->ob_pSrc->QueryInterface(IID_IUnknown, (void **)&pFilterUnk);

        HWND topwindow = GetTopWindow(NULL);
        // Show the page.
        CAUUID caGUID;
        pProp->GetPages(&caGUID);
        pProp->Release();
        OleCreatePropertyFrame(
            topwindow,              // Parent window
            0, 0,                   // xoffset, yoffset
            FilterInfo.achName,     // Caption for the dialog box
            1,                      // Number of objects (just the filter)
            &pFilterUnk,            // Array of object pointers.
            caGUID.cElems,          // Number of property pages
            caGUID.pElems,          // Array of property page CLSIDs
            0,                      // Locale identifier
            0, NULL                 // Reserved
        );

        // Clean up.
        pFilterUnk->Release();
        FilterInfo.pGraph->Release();
        CoTaskMemFree(caGUID.pElems);

        teardown(self); //xxx
        if (initialize(self))
        {
            Py_INCREF(Py_None);
            return Py_None;
        }
        else
        {
            return NULL;
        }
    }
    else
    {
        PyErr_SetString(VidcapError, "Querying the filter for its property pages failed.");
        return NULL;
    }
}


static PyObject *
Dev_displaycapturefilterproperties(DevObject *self, PyObject *args)
{
    bool everything_ok = false;

    HRESULT hr;
    hr = self->ob_pControl->Stop();

    ISpecifyPropertyPages *pSpec;
    CAUUID cauuid;
    hr = self->ob_pSrc->QueryInterface(IID_ISpecifyPropertyPages,
                                       (void **)&pSpec);
    if(hr == S_OK) {
        hr = pSpec->GetPages(&cauuid);
        if(hr == S_OK && cauuid.cElems > 0) {
            teardown(self); //xxx                   Better *do* teardown and
            initialize(self); //xxx         initialize for my Webcam.
            hr = OleCreatePropertyFrame(GetTopWindow(NULL), 0, 0, NULL, 1,
                                        (IUnknown **)&self->ob_pSrc, cauuid.cElems,
                                        (GUID *)cauuid.pElems, 0, 0, NULL);
            everything_ok = true;
            CoTaskMemFree(cauuid.pElems);
        }
        pSpec->Release();
    }

    if (everything_ok)
    {
        teardown(self); //xxx
        if (initialize(self))
        {
            Py_INCREF(Py_None);
            return Py_None;
        }
        else
        {
            return NULL;
        }
    }
    else
    {
        PyErr_SetString(VidcapError, "Querying the capture filter for its property pages failed.");
        return NULL;
    }
}


static PyObject *
Dev_displaycapturepinproperties(DevObject *self, PyObject *args)
{
    bool everything_ok = false;

    HRESULT hr;
    hr = self->ob_pControl->Stop();

    IAMStreamConfig *pSC;
    hr = self->ob_pBuilder->FindInterface(&PIN_CATEGORY_CAPTURE,
                                          &MEDIATYPE_Interleaved, self->ob_pSrc,
                                          IID_IAMStreamConfig, (void **)&pSC);
    if(hr != S_OK)
        hr = self->ob_pBuilder->FindInterface(&PIN_CATEGORY_CAPTURE,
                                              &MEDIATYPE_Video, self->ob_pSrc,
                                              IID_IAMStreamConfig, (void **)&pSC);
    if(hr == S_OK){
        ISpecifyPropertyPages *pSpec;
        CAUUID cauuid;
        hr = pSC->QueryInterface(IID_ISpecifyPropertyPages,
                                 (void **)&pSpec);
        if(hr == S_OK) {
            hr = pSpec->GetPages(&cauuid);
            if(hr == S_OK && cauuid.cElems > 0) {
                    //teardown(self); //xxx                 Better do *not* teardown and
                                //initialize(self); //xxx       initialize for my TV-card.
                hr = OleCreatePropertyFrame(GetTopWindow(NULL), 0, 0, NULL, 1,
                                            (IUnknown **)&pSC, cauuid.cElems,
                                            (GUID *)cauuid.pElems, 0, 0, NULL);
                everything_ok = true;
                CoTaskMemFree(cauuid.pElems);
            }
            pSpec->Release();
        }
        pSC->Release();
    }

    if (everything_ok)
    {
        teardown(self); //xxx
        if (initialize(self))
        {
            Py_INCREF(Py_None);
            return Py_None;
        }
        else
        {
            return NULL;
        }
    }
    else
    {
        PyErr_SetString(VidcapError, "Querying the capture pin for its property pages failed.");
        return NULL;
    }
}

// contributed by Jeremy Mortis <mortis@tansay.ca>
static PyObject *
Dev_getdisplayname(DevObject *self, PyObject *args)
{	
	HRESULT hr;
    VARIANT varName;
    VariantInit(&varName);
	if (self->ob_pPropBag == NULL) 
	{
		PyErr_SetString(VidcapError, "No device properties available.");
        return NULL;
    }

    hr = self->ob_pPropBag->Read(L"FriendlyName", &varName, 0);
    if (FAILED(hr))
    {
		PyErr_SetString(VidcapError, "Unable to obtain display name.");
        return NULL;
    }

	char buffer[100];
	wcstombs(buffer, varName.bstrVal, 100);

    PyObject *value;
    value = Py_BuildValue("s", buffer);

    VariantClear(&varName);

    return value;
}

// contributed by Don Kimber <kimber@fxpal.com>
static PyObject *
Dev_setresolution(DevObject *self, PyObject *args)
{
    HRESULT hr;
    int     width, height;
    char*   errStr = NULL;
    bool everything_ok = false;

    if (!PyArg_ParseTuple(args, "ii:newDev", &width, &height))
        return NULL;


    hr = self->ob_pControl->Stop();

    IAMStreamConfig *pSC;

//  pSC->SetFormat(pmt);

    hr = self->ob_pBuilder->FindInterface(&PIN_CATEGORY_CAPTURE,
                                          &MEDIATYPE_Interleaved, self->ob_pSrc,
                                          IID_IAMStreamConfig, (void **)&pSC);
    if(hr != S_OK)
        hr = self->ob_pBuilder->FindInterface(&PIN_CATEGORY_CAPTURE,
                                              &MEDIATYPE_Video, self->ob_pSrc,
                                              IID_IAMStreamConfig, (void **)&pSC);
    if(hr == S_OK){
        AM_MEDIA_TYPE* pmt;
        hr = pSC->GetFormat(&pmt);
        if (hr == S_OK) {
            if (pmt->formattype == FORMAT_VideoInfo) {
                VIDEOINFOHEADER *pVih = reinterpret_cast<VIDEOINFOHEADER*>(pmt->pbFormat);
                pVih->bmiHeader.biWidth=width;
                pVih->bmiHeader.biHeight=height;
                hr = pSC->SetFormat(pmt);
                if (hr == S_OK)
                    everything_ok = true;
                else {
                    errStr = "Cannot set capture resolution.";
                }
            }
            else {
                errStr = "Cannot query capture format.";
            }
            DeleteMediaType(pmt);
        }
        pSC->Release();
    }

    if (everything_ok) {
        teardown(self); //xxx
        if (initialize(self))
        {
            Py_INCREF(Py_None);
            return Py_None;
        }
        else
        {
            PyErr_SetString(VidcapError, "Problem after setting the capture resolution.");
            return NULL;
        }
    }
    else {
        if (errStr == NULL)
            errStr = "Setting the capture resolution failed.";
        PyErr_SetString(VidcapError, errStr);
        return NULL;
    }
}


static PyObject *
Dev_getbuffer(DevObject *self, PyObject *args)
{
    HRESULT hr;

    AM_MEDIA_TYPE MediaType;
    hr = self->ob_pGrab->GetConnectedMediaType(&MediaType);
    if (FAILED(hr))
    {
        PyErr_SetString(VidcapError, "Getting the sample grabber's connected media type failed.");
        return NULL;
    }

    // Get a pointer to the video header.
    VIDEOINFOHEADER *pVideoHeader = (VIDEOINFOHEADER*)MediaType.pbFormat;

    long size   = pVideoHeader->bmiHeader.biSizeImage;
    long width  = pVideoHeader->bmiHeader.biWidth;
    long height = pVideoHeader->bmiHeader.biHeight;

    // Free the format block
    //FreeMediaType(MediaType); // this would need the DirectShow Base Classes
    CoTaskMemFree(MediaType.pbFormat);

    // Allocate memory.
    //void *buffer = malloc(size);
    void *buffer = PyMem_Malloc(size);
    if (!buffer)
    {
        PyErr_NoMemory();
        return NULL;
    }

    hr = self->ob_pControl->Run(); // fixme: xxx
    // Copy the image into the buffer.
    while (true)
    {
        hr = self->ob_pGrab->GetCurrentBuffer(&size, (long *)buffer);
        if (hr == VFW_E_WRONG_STATE)
            Sleep(100);
        else
            break;
    }
    if (FAILED(hr))
    {
        switch (hr)
        {
        case E_INVALIDARG:
            PyErr_SetString(VidcapError, "Getting the sample grabber's current buffer failed (Samples are not being buffered).");
            break;
        case E_POINTER:
            PyErr_SetString(VidcapError, "Getting the sample grabber's current buffer failed (NULL pointer argument).");
            break;
        case VFW_E_NOT_CONNECTED:
            PyErr_SetString(VidcapError, "Getting the sample grabber's current buffer failed (The filter is not connected).");
            break;
        case VFW_E_WRONG_STATE:
            PyErr_SetString(VidcapError, "Getting the sample grabber's current buffer failed (The filter did not buffer a sample yet).");
            break;
        default:
            PyErr_SetString(VidcapError, "UNKNOWN CASE!!");
        }
        PyMem_Free(buffer);
        return NULL;
    }

    // Return the buffer.
    PyObject *value;
    value = Py_BuildValue("(s#,l,l)", buffer, size, width, height);

    //free(buffer);
    PyMem_Free(buffer);

    return value;
}


static PyMethodDef Dev_methods[] = {
    {"displaypropertypage",             (PyCFunction)Dev_displaypropertypage,               METH_VARARGS},
    {"displaycapturefilterproperties",  (PyCFunction)Dev_displaycapturefilterproperties,    METH_VARARGS},
    {"displaycapturepinproperties",     (PyCFunction)Dev_displaycapturepinproperties,       METH_VARARGS},
    {"getdisplayname",                  (PyCFunction)Dev_getdisplayname,                    METH_VARARGS},
    {"setresolution",                   (PyCFunction)Dev_setresolution,                     METH_VARARGS},
    {"getbuffer",                       (PyCFunction)Dev_getbuffer,                         METH_VARARGS},
    {NULL,                              NULL}           /* sentinel */
};


static PyObject *
Dev_getattr(DevObject *self, char *name)
{
    return Py_FindMethod(Dev_methods, (PyObject *)self, name);
}


statichere PyTypeObject Dev_Type = {
    /* The ob_type field must be initialized in the module init function
     * to be portable to Windows without using C++. */
    PyObject_HEAD_INIT(NULL)
    0,                        /*ob_size*/
    "Dev",                    /*tp_name*/
    sizeof(DevObject),        /*tp_basicsize*/
    0,                        /*tp_itemsize*/
    /* methods */
    (destructor)Dev_dealloc,  /*tp_dealloc*/
    0,                        /*tp_print*/
    (getattrfunc)Dev_getattr, /*tp_getattr*/
    (setattrfunc)0,           /*tp_setattr*/
    0,                        /*tp_compare*/
    0,                        /*tp_repr*/
    0,                        /*tp_as_number*/
    0,                        /*tp_as_sequence*/
    0,                        /*tp_as_mapping*/
    0,                        /*tp_hash*/
};


static PyObject *
vidcap_new_Dev(PyObject *self, PyObject *args)
{
    DevObject *rv;

    rv = newDevObject(args);
    if ( rv == NULL )
        return NULL;
    return (PyObject *)rv;
}


static PyMethodDef vidcap_methods[] = {
    {"new_Dev", vidcap_new_Dev, METH_VARARGS},
    {NULL,      NULL}        /* Sentinel */
};


extern "C"

/* platform independent */
#ifdef MS_WIN32
__declspec(dllexport)
#endif

void
initvidcap(void)
{
    Dev_Type.ob_type = &PyType_Type;

    PyObject *m, *d;

    m = Py_InitModule("vidcap", vidcap_methods);
    d = PyModule_GetDict(m);
    VidcapError = PyErr_NewException("vidcap.Error", NULL, NULL);
    PyDict_SetItemString(d, "error", VidcapError);

    HRESULT hr;

    // Initialize COM.
    hr = CoInitialize(NULL);
    if (FAILED(hr))
    {
        PyErr_SetString(VidcapError, "Initialization of COM failed.");
        return;
    }

    // Register Release COM at exit.
    if ( Py_AtExit( (void (__cdecl *)(void))CoUninitialize ) )
    {
        PyErr_SetString(VidcapError, "Registering CoUninitialize at exit failed.");
        CoUninitialize();
        return;
    }
}

