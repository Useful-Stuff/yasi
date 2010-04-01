#pragma once

#ifdef WIN32
#include "windows.h"
#else
#error "not implement"
#endif

#include "../tasks.h"

extern LIST_ENTRY task_list;
extern CRITICAL_SECTION task_list_lock;


typedef struct _task_node
{
    LIST_ENTRY event_list;
    CRITICAL_SECTION event_list_lock; 
    HANDLE event_nofity;
    bool force_quit;
    u32 event_count;
    task_notify_routine callback;
    u32 thread_id;
    LIST_ENTRY node;
}task_node;

typedef struct _event_node
{
    taskitem* item;
    u32 process_id;
    u32 thread_id;
    HANDLE notify;
    LIST_ENTRY node;
}event_node;

task_node* create_task_node();
void delete_task_node(task_node* node);


event_node* create_event_node(taskitem* item);
void delete_event_node(event_node* node);
void insert_event_head(task_node* task, event_node* node);
void insert_event_tail(task_node* task, event_node* node);
event_node* fetch_event_head(task_node* task);
event_node* fetch_event_tail(task_node* task);

void insert_task(task_node* task);
void remove_task(task_node* task);
task_api taskitem* create_taskitem(u32 msg, u8* buf, u32 length);



VOID InitializeListHead(  __out PLIST_ENTRY ListHead );
VOID InitializeListHead( __out PLIST_ENTRY ListHead );
BOOLEAN IsListEmpty( __in const LIST_ENTRY * ListHead );
BOOLEAN RemoveEntryList( __in PLIST_ENTRY Entry );
PLIST_ENTRY RemoveHeadList( __inout PLIST_ENTRY ListHead );
PLIST_ENTRY RemoveTailList( __inout PLIST_ENTRY ListHead );
VOID InsertTailList( __inout PLIST_ENTRY ListHead, __inout __drv_aliasesMem PLIST_ENTRY Entry );
VOID InsertHeadList( __inout PLIST_ENTRY ListHead, __inout __drv_aliasesMem PLIST_ENTRY Entry );