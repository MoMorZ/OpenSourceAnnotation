/*
* Tencent is pleased to support the open source community by making Libco available.

* Copyright (C) 2014 THL A29 Limited, a Tencent company. All rights reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License"); 
* you may not use this file except in compliance with the License. 
* You may obtain a copy of the License at
*
*	http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, 
* software distributed under the License is distributed on an "AS IS" BASIS, 
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
* See the License for the specific language governing permissions and 
* limitations under the License.
*/

#ifndef __CO_ROUTINE_INNER_H__

#include "co_routine.h"
#include "coctx.h"
struct stCoRoutineEnv_t;
struct stCoSpec_t {
    void* value;
};

/**
 * @brief 共享栈结构
 * 
 */
struct stStackMem_t {
    stCoRoutine_t* occupy_co; // 正在使用该共享栈的协程
    int stack_size; // 栈大小
    char* stack_bp; //stack_buffer + stack_size 栈底指针
    char* stack_buffer; // 栈顶指针
};

/**
 * @brief 共享栈管理结构
 * 
 */
struct stShareStack_t {
    unsigned int alloc_idx; // 正在使用的共享栈的 id
    int stack_size; // 共享栈的大小，指数组的大小
    int count; // 共享栈的个数
    stStackMem_t** stack_array; // 共享栈数组
};

/**
 * @brief 协程控制块
 * 
 */
struct stCoRoutine_t {
    stCoRoutineEnv_t* env; // 协程执行环境，相当于调度器
    pfn_co_routine_t pfn; // 协程需执行的函数指针
    void* arg; // 函数的参数
    coctx_t ctx; // 上下文

    char cStart; // 是否开始运行
    char cEnd; // 是否结束
    char cIsMain; // 是否主协程
    char cEnableSysHook; // 是否允许 hook，默认关闭
    char cIsShareStack; // 是否使用共享栈，默认不使用

    void* pvEnv; // 保存系统环境变量的指针

    //char sRunStack[ 1024 * 128 ];
    stStackMem_t* stack_mem; // 协程运行时栈

    //save satck buffer while confilct on same stack_buffer;
    char* stack_sp; // 栈顶指针
    unsigned int save_size; // 缓冲区大小
    char* save_buffer; // 协程被切换出去时的缓冲区指针

    stCoSpec_t aSpec[1024];
};

//1.env
void co_init_curr_thread_env();
stCoRoutineEnv_t* co_get_curr_thread_env();

//2.coroutine
void co_free(stCoRoutine_t* co);
void co_yield_env(stCoRoutineEnv_t* env);

//3.func

//-----------------------------------------------------------------------------------------------

struct stTimeout_t;
struct stTimeoutItem_t;

stTimeout_t* AllocTimeout(int iSize);
void FreeTimeout(stTimeout_t* apTimeout);
int AddTimeout(stTimeout_t* apTimeout, stTimeoutItem_t* apItem, uint64_t allNow);

struct stCoEpoll_t;
stCoEpoll_t* AllocEpoll();
void FreeEpoll(stCoEpoll_t* ctx);

stCoRoutine_t* GetCurrThreadCo();
void SetEpoll(stCoRoutineEnv_t* env, stCoEpoll_t* ev);

typedef void (*pfnCoRoutineFunc_t)();

#endif

#define __CO_ROUTINE_INNER_H__
