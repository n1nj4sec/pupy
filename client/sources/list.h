/*!
 * @file list.h
 * @brief Declarations for functions that operate on lists.
 */
#ifndef _METERPRETER_LIB_LIST_H
#define _METERPRETER_LIB_LIST_H

/*! @brief Container struct for data the lives in a list. */
typedef struct _NODE
{
	struct _NODE * next;  ///< Pointer to the next node in the list.
	struct _NODE * prev;  ///< Pointer to the previous node in the list.
	LPVOID data;          ///< Reference to the data in the list node.
} NODE, *PNODE;

/*! @brief Container structure for a list instance. */
typedef struct _LIST
{
	NODE * start;   ///< Pointer to the first node in the list.
	NODE * end;     ///< Pointer to the last node in the list.
	DWORD count;    ///< Count of elements in the list.
	LOCK * lock;    ///< Reference to the list's synchronisation lock.
} LIST, *PLIST;

typedef BOOL (*PLISTENUMCALLBACK)(LPVOID pState, LPVOID pData);

LIST * list_create(VOID);
VOID list_destroy(PLIST pList);
DWORD list_count(PLIST pList);
LPVOID list_get(PLIST pList, DWORD index);
BOOL list_add(PLIST pList, LPVOID data);
BOOL list_remove(PLIST pList, LPVOID data);
BOOL list_delete(PLIST pList, DWORD index);
BOOL list_push(PLIST pList, LPVOID data);
LPVOID list_pop(PLIST pList);
LPVOID list_shift(PLIST pList);
BOOL list_enumerate(PLIST pList, PLISTENUMCALLBACK pCallback, LPVOID pState);

#endif
