#pragma once



#ifndef PROCESS_TASK
#define PROCESS_TASK    0
#define THREAD_TASK     1
#else
#define THREAD_TASK     (PROCESS_TASK == 0)
#endif

#ifndef DWORD
#define DWORD unsigned long
#endif

#ifndef u8
#define u8 unsigned char
#endif

#ifndef u16
#define u16 unsigned short
#endif

#ifndef u32
#define u32 unsigned long
#endif

#ifndef u64
#define u64 unsigned long long
#endif

#ifndef bool
#define bool int
#endif

#ifndef true
#define true (1==1)
#endif

#ifndef false
#define false (1==0)
#endif

#define task_api __declspec(dllexport)


typedef struct _taskitem
{
    u32 msg;
    u8* buf;
    u32 length;
}taskitem;


#ifdef __cplusplus
extern "C" {
#endif

    typedef u32 (*task_notify_routine)(taskitem* event);
    task_api void init_lib();
    task_api void uninit_lib();
    task_api u32 create_task_queue(task_notify_routine func);
    task_api bool destroy_task_queue(u32 qid);
    task_api taskitem* create_taskitem(u32 msg, u8* buf, u32 length);
    task_api bool post_event(u32 qid, taskitem* event);
    task_api bool send_event(u32 qid, taskitem* event);

#ifdef __cplusplus
}
#endif