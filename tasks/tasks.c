// tasks.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "taskinfo.h"
#include "stdlib.h"
u32 ref_count = 0;

static DWORD WINAPI ThreadProc(LPVOID pParam)
{
    task_node* node = (task_node*)pParam;
    u32 event_count = 0;
    event_node* event = NULL;

    while ( true ){
        if( InterlockedExchangeAdd(&(node->force_quit), 0 ) == true )
            break;
        event = fetch_event_head(node);
        if( event == NULL ){
            WaitForSingleObject(node->event_nofity, INFINITE);
        }else{
            if( node->callback ){
                node->callback(event->item);
            }
            SetEvent(event->notify);
            delete_event_node(event);
        }
    }
    remove_task(node);
    delete_task_node(node);
    return 0;
}

task_api void init_lib()
{
    if( InterlockedExchangeAdd(&ref_count, 1) == 0 ){
        InitializeListHead(&(task_list));
        InitializeCriticalSection(&(task_list_lock));
    }
}

task_api void uninit_lib()
{
    if( InterlockedExchangeAdd(&ref_count, -1) == 1 ){
        DeleteCriticalSection(&(task_list_lock));
    }
}

task_api u32 create_task_queue(task_notify_routine func)
{
    task_node* node = create_task_node();
    HANDLE thread_handle;
    DWORD  thread_id = 0;

    node->callback = func;
    thread_handle = (HANDLE)CreateThread(NULL,	// Security attributes
        0,	// stack
        ThreadProc,	// Thread proc
        (PVOID)node,	// Thread param
        CREATE_SUSPENDED,	// creation mode
        &thread_id);	// Thread ID

    if ( NULL != thread_handle && INVALID_HANDLE_VALUE != thread_handle )
    {
        node->thread_id = thread_id;
        insert_task(node);
        ResumeThread( thread_handle );
        CloseHandle(thread_handle);
        return (u32)node;
    }
    else
    {
        return 0;
    }	
}

task_api bool destroy_task_queue(u32 qid)
{
    task_node* node = (task_node*)qid;
    if( qid == 0 )
        return false;
    InterlockedExchange(&(node->force_quit), true);
    SetEvent(node->event_nofity);
    return true;
}

task_api taskitem* create_taskitem(u32 msg, u8* buf, u32 length)
{
    taskitem* item = (taskitem*)malloc(sizeof(taskitem));
    item->buf = buf;
    item->msg = msg;
    item->length = length;
    return item;
}

task_api bool post_event(u32 qid, taskitem* item)
{
    task_node* node = (task_node*)qid;
    event_node* event = create_event_node(item);
    insert_event_tail(node, event);
    return true;
}

task_api bool send_event(u32 qid, taskitem* item)
{
    task_node* node = (task_node*)qid;
    event_node* event = create_event_node(item);
    if( node->thread_id == event->thread_id ){
        if( node->callback ){
            node->callback(event->item);
        }
        delete_event_node(event);
    }else{
        insert_event_head(node, event);
        WaitForSingleObject(event->notify, INFINITE);
    }
    return true;
}


