/*!
 * @file list.h
 * @brief Declarations for functions that operate on lists.
 */
#ifndef _METERPRETER_LIB_LIST_H
#define _METERPRETER_LIB_LIST_H

#include <pthread.h>
#include <stdbool.h>

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
    pthread_mutex_t lock;    ///< Reference to the list's synchronisation lock.
} LIST, *PLIST;

typedef bool (*PLISTENUMCALLBACK)(void * pState, void * pData);

LIST * list_create(void);
void list_destroy(PLIST pList);
unsigned int list_count(PLIST pList);
void * list_get(PLIST pList, unsigned int index);
bool list_add(PLIST pList, void * data);
bool list_remove(PLIST pList, void * data);
bool list_delete(PLIST pList, unsigned int index);
bool list_push(PLIST pList, void * data);
void * list_pop(PLIST pList);
void * list_shift(PLIST pList);
bool list_enumerate(PLIST pList, PLISTENUMCALLBACK pCallback, void * pState);

#endif
