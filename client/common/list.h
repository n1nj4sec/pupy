/*!
 * @file list.h
 * @brief Declarations for functions that operate on lists.
 */
#ifndef _METERPRETER_LIB_LIST_H
#define _METERPRETER_LIB_LIST_H

#ifdef _WIN32
#include <windows.h>
#define os_mutex_t CRITICAL_SECTION
#define OSMutexInit(mutex) InitializeCriticalSection(mutex)
#define OSMutexLock(mutex) EnterCriticalSection(mutex)
#define OSMutexUnlock(mutex) LeaveCriticalSection(mutex)
#define OSMutexDestroy(mutex) DeleteCriticalSection(mutex)
#else
#include <pthread.h>
#define os_mutex_t pthread_mutex_t 
#define OSMutexInit(mutex) pthread_mutex_init(mutex, NULL)
#define OSMutexLock(mutex) pthread_mutex_lock(mutex)
#define OSMutexUnlock(mutex) pthread_mutex_unlock(mutex)
#define OSMutexDestroy(mutex) pthread_mutex_destroy(mutex)
#ifndef TRUE
#define BOOL int
#define TRUE 1
#define FALSE 0
#endif
#endif

/*! @brief Container struct for data the lives in a list. */
typedef struct _NODE
{
    struct _NODE * next;  ///< Pointer to the next node in the list.
    struct _NODE * prev;  ///< Pointer to the previous node in the list.
    void *data;          ///< Reference to the data in the list node.
} NODE, *PNODE;

/*! @brief Container structure for a list instance. */
typedef struct _LIST
{
    NODE * start;   ///< Pointer to the first node in the list.
    NODE * end;     ///< Pointer to the last node in the list.
    unsigned int count;    ///< Count of elements in the list.
    os_mutex_t lock;    ///< Reference to the list's synchronisation lock.
} LIST, *PLIST;

typedef BOOL (*PLISTENUMCALLBACK)(void * pState, void * pData);

LIST * list_create(void);
void list_destroy(PLIST pList);
unsigned int list_count(PLIST pList);
void * list_get(PLIST pList, unsigned int index);
BOOL list_add(PLIST pList, void * data);
BOOL list_remove(PLIST pList, void * data);
BOOL list_delete(PLIST pList, unsigned int index);
BOOL list_push(PLIST pList, void * data);
void * list_pop(PLIST pList);
void * list_shift(PLIST pList);
BOOL list_enumerate(PLIST pList, PLISTENUMCALLBACK pCallback, void * pState);

#endif
