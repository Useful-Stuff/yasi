#include "stdafx.h"
#include "taskinfo.h"
#include "stdlib.h"
#include "memory.h"

LIST_ENTRY task_list;
CRITICAL_SECTION task_list_lock;


FORCEINLINE
VOID
InitializeListHead(
                   __out PLIST_ENTRY ListHead
                   )
{
    ListHead->Flink = ListHead->Blink = ListHead;
}

__checkReturn
BOOLEAN
FORCEINLINE
IsListEmpty(
            __in const LIST_ENTRY * ListHead
            )
{
    return (BOOLEAN)(ListHead->Flink == ListHead);
}

FORCEINLINE
BOOLEAN
RemoveEntryList(
                __in PLIST_ENTRY Entry
                )
{
    PLIST_ENTRY Blink;
    PLIST_ENTRY Flink;

    Flink = Entry->Flink;
    Blink = Entry->Blink;
    Blink->Flink = Flink;
    Flink->Blink = Blink;
    return (BOOLEAN)(Flink == Blink);
}

FORCEINLINE
PLIST_ENTRY
RemoveHeadList(
               __inout PLIST_ENTRY ListHead
               )
{
    PLIST_ENTRY Flink;
    PLIST_ENTRY Entry;

    Entry = ListHead->Flink;
    Flink = Entry->Flink;
    ListHead->Flink = Flink;
    Flink->Blink = ListHead;
    return Entry;
}



FORCEINLINE
PLIST_ENTRY
RemoveTailList(
               __inout PLIST_ENTRY ListHead
               )
{
    PLIST_ENTRY Blink;
    PLIST_ENTRY Entry;

    Entry = ListHead->Blink;
    Blink = Entry->Blink;
    ListHead->Blink = Blink;
    Blink->Flink = ListHead;
    return Entry;
}


FORCEINLINE
VOID
InsertTailList(
               __inout PLIST_ENTRY ListHead,
               __inout __drv_aliasesMem PLIST_ENTRY Entry
               )
{
    PLIST_ENTRY Blink;

    Blink = ListHead->Blink;
    Entry->Flink = ListHead;
    Entry->Blink = Blink;
    Blink->Flink = Entry;
    ListHead->Blink = Entry;
}


FORCEINLINE
VOID
InsertHeadList(
               __inout PLIST_ENTRY ListHead,
               __inout __drv_aliasesMem PLIST_ENTRY Entry
               )
{
    PLIST_ENTRY Flink;

    Flink = ListHead->Flink;
    Entry->Flink = Flink;
    Entry->Blink = ListHead;
    Flink->Blink = Entry;
    ListHead->Flink = Entry;
}


task_node* create_task_node()
{
    task_node* node;

    node = (task_node*)malloc(sizeof(task_node));
    memset(node, 0, sizeof(task_node));
    InitializeListHead(&(node->event_list));
    InitializeCriticalSection(&(node->event_list_lock));
    node->event_nofity = CreateEvent(NULL, FALSE, FALSE, NULL);
    node->force_quit = false;
    node->event_count = 0;
    node->callback = NULL;
    node->thread_id = 0;
    return node;
}

void delete_task_node(task_node* node)
{
    event_node *event;
    if( !node )
        return;
    EnterCriticalSection(&(node->event_list_lock));
    while( (event=fetch_event_head(node)) != NULL ){
        free(event->item);
        delete_event_node(event);
    }
    LeaveCriticalSection(&(node->event_list_lock));
    node->force_quit = true;
    SetEvent(node->event_nofity);
    CloseHandle(node->event_nofity);
    DeleteCriticalSection(&(node->event_list_lock));
    free(node);
}

event_node* create_event_node(taskitem* item)
{
    event_node* node;
    node = (event_node*)malloc(sizeof(event_node));
    memset(node, 0, sizeof(event_node));
    node->item = item;
    node->notify = CreateEvent(NULL, FALSE, FALSE, NULL);
    node->process_id = GetCurrentProcessId();
    node->thread_id = GetCurrentThreadId();
    return node;
}

void delete_event_node(event_node* node)
{
    if( !node )
        return;
    free(node->item);
    free(node);
}

void insert_event_head(task_node* task, event_node* node)
{
    if( !task || !node )
        return;

    EnterCriticalSection(&(task->event_list_lock));
    InsertHeadList(&(task->event_list), &(node->node));
    task->event_count++;
    LeaveCriticalSection(&(task->event_list_lock));
    SetEvent(task->event_nofity);
}

void insert_event_tail(task_node* task, event_node* node)
{
    if( !task || !node )
        return;

    EnterCriticalSection(&(task->event_list_lock));
    InsertTailList(&(task->event_list), &(node->node));
    task->event_count++;
    LeaveCriticalSection(&(task->event_list_lock));
    SetEvent(task->event_nofity);

}

event_node* fetch_event_head(task_node* task)
{
    event_node* node = NULL;
    PLIST_ENTRY entry;
    if( !task )
        return NULL;
    EnterCriticalSection(&(task->event_list_lock));
    if( IsListEmpty(&(task->event_list) ) ){
        LeaveCriticalSection(&(task->event_list_lock));
        return NULL;
    }
    entry = RemoveHeadList(&(task->event_list) );
    node = (event_node*)CONTAINING_RECORD(entry, event_node, node);
    task->event_count--;
    LeaveCriticalSection(&(task->event_list_lock));
    return node;

}

event_node* fetch_event_tail(task_node* task)
{
    event_node* node = NULL;
    PLIST_ENTRY entry;
    if( !task )
        return NULL;
    EnterCriticalSection(&(task->event_list_lock));
    if( IsListEmpty(&(task->event_list) ) ){
        LeaveCriticalSection(&(task->event_list_lock));
        return NULL;
    }
    entry = RemoveTailList(&(task->event_list) );
    node = (event_node*)CONTAINING_RECORD(entry, event_node, node);
    task->event_count--;
    LeaveCriticalSection(&(task->event_list_lock));
    return node;
}

void insert_task(task_node* task)
{
    EnterCriticalSection(&(task_list_lock));
    InsertTailList(&(task_list), &(task->node) );
    LeaveCriticalSection(&(task_list_lock));
}


void remove_task(task_node* task)
{
    EnterCriticalSection(&(task_list_lock));
    RemoveEntryList(&(task->node));
    LeaveCriticalSection(&(task_list_lock));
}