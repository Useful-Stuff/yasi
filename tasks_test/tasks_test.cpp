// tasks_test.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "../tasks.h"
#include "stdlib.h"
#include "time.h"
#include "windows.h"

u32 get_wait_tick()
{
    srand(time(NULL));
    int i = rand()%3000;
    return i;
}

u32 task_process(taskitem* event)
{
    static int count = 0;
    printf("[proc] wait %04d thread %04d\n", count, GetCurrentThreadId());
    if( count == 0 )
        Sleep(5000);
    count++;
    return 0;
}

int _tmain(int argc, _TCHAR* argv[])
{
    init_lib();
    u32 qid = create_task_queue(task_process);

    for( int index = 0 ; index < 1000; index++ ){
        printf("[send] send %04d thread %04d\n", index, GetCurrentThreadId());
        taskitem* item = create_taskitem(0, NULL, 0);
        send_event(qid, item);
    }

    system("pause");
    uninit_lib();
	return 0;
}

