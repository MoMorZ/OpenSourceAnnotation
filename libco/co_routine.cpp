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

#include "co_routine.h"
#include "co_epoll.h"
#include "co_routine_inner.h"

#include <map>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>

#include <errno.h>
#include <poll.h>
#include <sys/time.h>

#include <assert.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

extern "C" {
extern void coctx_swap(coctx_t*, coctx_t*) asm("coctx_swap");
};
using namespace std;
stCoRoutine_t* GetCurrCo(stCoRoutineEnv_t* env);
struct stCoEpoll_t;

/**
 * @brief 单个线程的协程调度器，或者说环境
 * 
 */
struct stCoRoutineEnv_t {
    stCoRoutine_t* pCallStack[128]; // 调用栈，最后一位是当前协程，前一位是父协程
    int iCallStackSize; // 当前调用栈大小
    stCoEpoll_t* pEpoll; //

    //for copy stack log lastco and nextco
    stCoRoutine_t* pending_co; // 将要切换运行的协程
    stCoRoutine_t* occupy_co; // 占有共享栈的协程
};
//int socket(int domain, int type, int protocol);
void co_log_err(const char* fmt, ...)
{
}

#if defined(__LIBCO_RDTSCP__)
static unsigned long long counter(void)
{
    register uint32_t lo, hi;
    register unsigned long long o;
    __asm__ __volatile__(
        "rdtscp"
        : "=a"(lo), "=d"(hi)::"%rcx");
    o = hi;
    o <<= 32;
    return (o | lo);
}
static unsigned long long getCpuKhz()
{
    FILE* fp = fopen("/proc/cpuinfo", "r");
    if (!fp)
        return 1;
    char buf[4096] = { 0 };
    fread(buf, 1, sizeof(buf), fp);
    fclose(fp);

    char* lp = strstr(buf, "cpu MHz");
    if (!lp)
        return 1;
    lp += strlen("cpu MHz");
    while (*lp == ' ' || *lp == '\t' || *lp == ':') {
        ++lp;
    }

    double mhz = atof(lp);
    unsigned long long u = (unsigned long long)(mhz * 1000);
    return u;
}
#endif

static unsigned long long GetTickMS()
{
#if defined(__LIBCO_RDTSCP__)
    static uint32_t khz = getCpuKhz();
    return counter() / khz;
#else
    struct timeval now = { 0 };
    gettimeofday(&now, NULL);
    unsigned long long u = now.tv_sec;
    u *= 1000;
    u += now.tv_usec / 1000;
    return u;
#endif
}

/* no longer use
static pid_t GetPid()
{
    static __thread pid_t pid = 0;
    static __thread pid_t tid = 0;
    if( !pid || !tid || pid != getpid() )
    {
        pid = getpid();
#if defined( __APPLE__ )
		tid = syscall( SYS_gettid );
		if( -1 == (long)tid )
		{
			tid = pid;
		}
#elif defined( __FreeBSD__ )
		syscall(SYS_thr_self, &tid);
		if( tid < 0 )
		{
			tid = pid;
		}
#else 
        tid = syscall( __NR_gettid );
#endif

    }
    return tid;

}
static pid_t GetPid()
{
	char **p = (char**)pthread_self();
	return p ? *(pid_t*)(p + 18) : getpid();
}
*/
template <class T, class TLink>
void RemoveFromLink(T* ap)
{
    TLink* lst = ap->pLink;
    if (!lst)
        return;
    assert(lst->head && lst->tail);

    if (ap == lst->head) {
        lst->head = ap->pNext;
        if (lst->head) {
            lst->head->pPrev = NULL;
        }
    } else {
        if (ap->pPrev) {
            ap->pPrev->pNext = ap->pNext;
        }
    }

    if (ap == lst->tail) {
        lst->tail = ap->pPrev;
        if (lst->tail) {
            lst->tail->pNext = NULL;
        }
    } else {
        ap->pNext->pPrev = ap->pPrev;
    }

    ap->pPrev = ap->pNext = NULL;
    ap->pLink = NULL;
}

template <class TNode, class TLink>
void inline AddTail(TLink* apLink, TNode* ap)
{
    if (ap->pLink) {
        return;
    }
    if (apLink->tail) {
        apLink->tail->pNext = (TNode*)ap;
        ap->pNext = NULL;
        ap->pPrev = apLink->tail;
        apLink->tail = ap;
    } else {
        apLink->head = apLink->tail = ap;
        ap->pNext = ap->pPrev = NULL;
    }
    ap->pLink = apLink;
}
template <class TNode, class TLink>
void inline PopHead(TLink* apLink)
{
    if (!apLink->head) {
        return;
    }
    TNode* lp = apLink->head;
    if (apLink->head == apLink->tail) {
        apLink->head = apLink->tail = NULL;
    } else {
        apLink->head = apLink->head->pNext;
    }

    lp->pPrev = lp->pNext = NULL;
    lp->pLink = NULL;

    if (apLink->head) {
        apLink->head->pPrev = NULL;
    }
}

template <class TNode, class TLink>
void inline Join(TLink* apLink, TLink* apOther)
{
    //printf("apOther %p\n",apOther);
    if (!apOther->head) {
        return;
    }
    TNode* lp = apOther->head;
    while (lp) {
        lp->pLink = apLink;
        lp = lp->pNext;
    }
    lp = apOther->head;
    if (apLink->tail) {
        apLink->tail->pNext = (TNode*)lp;
        lp->pPrev = apLink->tail;
        apLink->tail = apOther->tail;
    } else {
        apLink->head = apOther->head;
        apLink->tail = apOther->tail;
    }

    apOther->head = apOther->tail = NULL;
}

/////////////////for copy stack //////////////////////////

/**
 * @brief 分配栈内存
 * 
 * @param stack_size 栈大小
 * @return stStackMem_t* 栈指针
 */
stStackMem_t* co_alloc_stackmem(unsigned int stack_size)
{
    stStackMem_t* stack_mem = (stStackMem_t*)malloc(sizeof(stStackMem_t));
    stack_mem->occupy_co = NULL; // 初始化占用协程为无
    stack_mem->stack_size = stack_size; // 设置大小
    stack_mem->stack_buffer = (char*)malloc(stack_size); // 申请内存
    stack_mem->stack_bp = stack_mem->stack_buffer + stack_size; // 栈底指针
    return stack_mem;
}

/**
 * @brief 创建共享栈
 * 
 * @param count 创建的共享栈个数
 * @param stack_size 每个共享栈的大小
 * @return stShareStack_t* 共享栈指针
 */
stShareStack_t* co_alloc_sharestack(int count, int stack_size)
{
    stShareStack_t* share_stack = (stShareStack_t*)malloc(sizeof(stShareStack_t));
    share_stack->alloc_idx = 0; // 初始化使用中共享栈 id 为无
    share_stack->stack_size = stack_size; // 设置大小

    //alloc stack array
    share_stack->count = count; // 设置个数
    stStackMem_t** stack_array = (stStackMem_t**)calloc(count, sizeof(stStackMem_t*));
    for (int i = 0; i < count; i++) {
        stack_array[i] = co_alloc_stackmem(stack_size); // 为每个共享栈分配栈空间
    }
    share_stack->stack_array = stack_array; // 设置共享栈数组的指针
    return share_stack;
}

/**
 * @brief 获取当前使用中共享栈
 * 
 * @param share_stack 共享栈管理结构
 * @return stStackMem_t* 共享栈指针
 */
static stStackMem_t* co_get_stackmem(stShareStack_t* share_stack)
{
    if (!share_stack) {
        return NULL;
    }
    int idx = share_stack->alloc_idx % share_stack->count; // 轮询机制
    share_stack->alloc_idx++;

    return share_stack->stack_array[idx];
}

// ----------------------------------------------------------------------------
struct stTimeoutItemLink_t;
struct stTimeoutItem_t;
struct stCoEpoll_t {
    int iEpollFd;
    static const int _EPOLL_SIZE = 1024 * 10;

    struct stTimeout_t* pTimeout;

    struct stTimeoutItemLink_t* pstTimeoutList;

    struct stTimeoutItemLink_t* pstActiveList;

    co_epoll_res* result;
};
typedef void (*OnPreparePfn_t)(stTimeoutItem_t*, struct epoll_event& ev, stTimeoutItemLink_t* active);
typedef void (*OnProcessPfn_t)(stTimeoutItem_t*);
struct stTimeoutItem_t {

    enum {
        eMaxTimeout = 40 * 1000 //40s
    };
    stTimeoutItem_t* pPrev;
    stTimeoutItem_t* pNext;
    stTimeoutItemLink_t* pLink;

    unsigned long long ullExpireTime;

    OnPreparePfn_t pfnPrepare;
    OnProcessPfn_t pfnProcess;

    void* pArg; // routine
    bool bTimeout;
};
struct stTimeoutItemLink_t {
    stTimeoutItem_t* head;
    stTimeoutItem_t* tail;
};
struct stTimeout_t {
    stTimeoutItemLink_t* pItems;
    int iItemSize;

    unsigned long long ullStart;
    long long llStartIdx;
};
stTimeout_t* AllocTimeout(int iSize)
{
    stTimeout_t* lp = (stTimeout_t*)calloc(1, sizeof(stTimeout_t));

    lp->iItemSize = iSize;
    lp->pItems = (stTimeoutItemLink_t*)calloc(1, sizeof(stTimeoutItemLink_t) * lp->iItemSize);

    lp->ullStart = GetTickMS();
    lp->llStartIdx = 0;

    return lp;
}
void FreeTimeout(stTimeout_t* apTimeout)
{
    free(apTimeout->pItems);
    free(apTimeout);
}
int AddTimeout(stTimeout_t* apTimeout, stTimeoutItem_t* apItem, unsigned long long allNow)
{
    if (apTimeout->ullStart == 0) {
        apTimeout->ullStart = allNow;
        apTimeout->llStartIdx = 0;
    }
    if (allNow < apTimeout->ullStart) {
        co_log_err("CO_ERR: AddTimeout line %d allNow %llu apTimeout->ullStart %llu",
            __LINE__, allNow, apTimeout->ullStart);

        return __LINE__;
    }
    if (apItem->ullExpireTime < allNow) {
        co_log_err("CO_ERR: AddTimeout line %d apItem->ullExpireTime %llu allNow %llu apTimeout->ullStart %llu",
            __LINE__, apItem->ullExpireTime, allNow, apTimeout->ullStart);

        return __LINE__;
    }
    unsigned long long diff = apItem->ullExpireTime - apTimeout->ullStart;

    if (diff >= (unsigned long long)apTimeout->iItemSize) {
        diff = apTimeout->iItemSize - 1;
        co_log_err("CO_ERR: AddTimeout line %d diff %d",
            __LINE__, diff);

        //return __LINE__;
    }
    AddTail(apTimeout->pItems + (apTimeout->llStartIdx + diff) % apTimeout->iItemSize, apItem);

    return 0;
}
inline void TakeAllTimeout(stTimeout_t* apTimeout, unsigned long long allNow, stTimeoutItemLink_t* apResult)
{
    if (apTimeout->ullStart == 0) {
        apTimeout->ullStart = allNow;
        apTimeout->llStartIdx = 0;
    }

    if (allNow < apTimeout->ullStart) {
        return;
    }
    int cnt = allNow - apTimeout->ullStart + 1;
    if (cnt > apTimeout->iItemSize) {
        cnt = apTimeout->iItemSize;
    }
    if (cnt < 0) {
        return;
    }
    for (int i = 0; i < cnt; i++) {
        int idx = (apTimeout->llStartIdx + i) % apTimeout->iItemSize;
        Join<stTimeoutItem_t, stTimeoutItemLink_t>(apResult, apTimeout->pItems + idx);
    }
    apTimeout->ullStart = allNow;
    apTimeout->llStartIdx += cnt - 1;
}

/**
 * @brief 协程函数封装
 * 
 * @param co 协程指针
 * @return int 0
 */
static int CoRoutineFunc(stCoRoutine_t* co, void*)
{
    if (co->pfn) { // 函数指针不为空执行
        co->pfn(co->arg);
    }
    co->cEnd = 1; // 标记为已结束

    stCoRoutineEnv_t* env = co->env;

    co_yield_env(env); // 切出该协程

    return 0;
}

/**
 * @brief 从协程管理器创建一个新协程
 * 
 * @param env 协程管理器指针
 * @param attr 协程属性
 * @param pfn 协程函数
 * @param arg 协程函数参数
 * @return struct stCoRoutine_t* 协程指针
 */
struct stCoRoutine_t* co_create_env(stCoRoutineEnv_t* env, const stCoRoutineAttr_t* attr,
    pfn_co_routine_t pfn, void* arg)
{
    // 初始化属性
    stCoRoutineAttr_t at;
    if (attr) {
        memcpy(&at, attr, sizeof(at));
    }
    if (at.stack_size <= 0) { // 没分配内存则分配 128K
        at.stack_size = 128 * 1024;
    } else if (at.stack_size > 1024 * 1024 * 8) { // 过大则限制为 8M
        at.stack_size = 1024 * 1024 * 8;
    }

    if (at.stack_size & 0xFFF) { // 4K 对齐
        at.stack_size &= ~0xFFF;
        at.stack_size += 0x1000;
    }

    stCoRoutine_t* lp = (stCoRoutine_t*)malloc(sizeof(stCoRoutine_t)); // 申请内存空间

    memset(lp, 0, (long)(sizeof(stCoRoutine_t)));

    lp->env = env; // 设置调度器
    lp->pfn = pfn; // 设置协程函数
    lp->arg = arg; // 设置协程函数参数

    stStackMem_t* stack_mem = NULL;
    if (at.share_stack) { // 若采用共享栈，则获取其中在使用的共享栈指针
        stack_mem = co_get_stackmem(at.share_stack);
        at.stack_size = at.share_stack->stack_size;
    } else { // 若不采用共享栈，则分配内存
        stack_mem = co_alloc_stackmem(at.stack_size);
    }
    lp->stack_mem = stack_mem;

    lp->ctx.ss_sp = stack_mem->stack_buffer; // 设置上下文栈指针
    lp->ctx.ss_size = at.stack_size; // 设置上下文栈大小

    lp->cStart = 0; // 未开始
    lp->cEnd = 0; // 未结束
    lp->cIsMain = 0; // 非主协程
    lp->cEnableSysHook = 0; // 不开启 hook
    lp->cIsShareStack = at.share_stack != NULL; // 设置是否使用共享栈

    lp->save_size = 0; // 只有使用共享栈时才有意义
    lp->save_buffer = NULL;

    return lp;
}

/**
 * @brief 创建一个协程
 * 
 * @param ppco 协程指针地址，未申请内存及初始化
 * @param attr 协程属性
 * @param pfn 协程函数指针
 * @param arg 协程函数参数
 * @return int 0
 */
int co_create(stCoRoutine_t** ppco, const stCoRoutineAttr_t* attr, pfn_co_routine_t pfn, void* arg)
{
    if (!co_get_curr_thread_env()) { // 获取当前协程的管理环境
        co_init_curr_thread_env(); // 找不到则初始化
    }
    stCoRoutine_t* co = co_create_env(co_get_curr_thread_env(), attr, pfn, arg); // 根据协程的运行环境，创建一个协程
    *ppco = co;
    return 0;
}

/**
 * @brief 释放协程内存空间
 * 
 * @param co 协程指针
 */
void co_free(stCoRoutine_t* co)
{
    if (!co->cIsShareStack) { // 非共享栈直接释放栈空间
        free(co->stack_mem->stack_buffer);
        free(co->stack_mem);
    }
    //walkerdu fix at 2018-01-20
    //存在内存泄漏
    else { // 共享栈则释放缓冲区空间
        if (co->save_buffer)
            free(co->save_buffer);

        if (co->stack_mem->occupy_co == co) // 设置对应的共享栈占用协程为无
            co->stack_mem->occupy_co = NULL;
    }

    free(co);
}

/**
 * @brief 释放协程
 * 
 * @param co 
 */
void co_release(stCoRoutine_t* co)
{
    co_free(co);
}

void co_swap(stCoRoutine_t* curr, stCoRoutine_t* pending_co);

/**
 * @brief 启动协程
 * 
 * @param co 要启动的协程的指针
 */
void co_resume(stCoRoutine_t* co)
{
    stCoRoutineEnv_t* env = co->env; // 取调度器
    stCoRoutine_t* lpCurrRoutine = env->pCallStack[env->iCallStackSize - 1]; // 取出当前协程
    if (!co->cStart) { // 首次启动，创建上下文，设置为开始
        coctx_make(&co->ctx, (coctx_pfn_t)CoRoutineFunc, co, 0);
        co->cStart = 1;
    }
    env->pCallStack[env->iCallStackSize++] = co; // 协程压入调用栈
    co_swap(lpCurrRoutine, co); // 进行切换
}

// walkerdu 2018-01-14
// 用于reset超时无法重复使用的协程
void co_reset(stCoRoutine_t* co)
{
    if (!co->cStart || co->cIsMain)
        return;

    co->cStart = 0;
    co->cEnd = 0;

    // 如果当前协程有共享栈被切出的buff，要进行释放
    if (co->save_buffer) {
        free(co->save_buffer);
        co->save_buffer = NULL;
        co->save_size = 0;
    }

    // 如果共享栈被当前协程占用，要释放占用标志，否则被切换，会执行save_stack_buffer()
    if (co->stack_mem->occupy_co == co)
        co->stack_mem->occupy_co = NULL;
}

/**
 * @brief 切出协程
 * 
 * @param env 协程调度器
 */
void co_yield_env(stCoRoutineEnv_t* env)
{

    stCoRoutine_t* last = env->pCallStack[env->iCallStackSize - 2]; // 取父协程
    stCoRoutine_t* curr = env->pCallStack[env->iCallStackSize - 1]; // 取当前协程

    env->iCallStackSize--; // 调用栈大小减一

    co_swap(curr, last); // 进行切换
}

void co_yield_ct()
{
    co_yield_env(co_get_curr_thread_env());
}

void co_yield(stCoRoutine_t* co)
{
    co_yield_env(co->env);
}

/**
 * @brief 保存占有共享栈的协程的内容到缓冲区
 * 
 * @param occupy_co 占有共享栈的协程
 */
void save_stack_buffer(stCoRoutine_t* occupy_co)
{
    ///copy out
    stStackMem_t* stack_mem = occupy_co->stack_mem;
    int len = stack_mem->stack_bp - occupy_co->stack_sp; // 栈底指针-栈顶指针得到栈大小

    if (occupy_co->save_buffer) { // 释放原来的缓冲区内存
        free(occupy_co->save_buffer), occupy_co->save_buffer = NULL;
    }

    occupy_co->save_buffer = (char*)malloc(len); //malloc buf;
    occupy_co->save_size = len;

    memcpy(occupy_co->save_buffer, occupy_co->stack_sp, len); // 拷贝运行时栈的内容到缓冲区
}

/**
 * @brief 协程切换，将当前上下文保存到 curr，切换为 pending_co 的上下文
 * 
 * @param curr 当前协程
 * @param pending_co 要切换到的协程
 */
void co_swap(stCoRoutine_t* curr, stCoRoutine_t* pending_co)
{
    stCoRoutineEnv_t* env = co_get_curr_thread_env();

    //get curr stack sp
    char c;
    curr->stack_sp = &c; // 这里新分配的 c 在栈顶，所以可以利用这个保存当前协程栈的位置

    if (!pending_co->cIsShareStack) { // 私有栈模式
        env->pending_co = NULL;
        env->occupy_co = NULL;
    } else { // 共享栈模式
        env->pending_co = pending_co;
        //get last occupy co on the same stack mem
        stCoRoutine_t* occupy_co = pending_co->stack_mem->occupy_co; // 取出当前占有该共享栈的协程，也就是和 pending_co 使用同一个共享站的协程
        //set pending co to occupy thest stack mem;
        pending_co->stack_mem->occupy_co = pending_co; // 把占有该共享栈的协程设置为将切换协程
        // 将原有的 occupy_co 以及 pending_co 都记录到调度器中，方便切换后的读入
        env->occupy_co = occupy_co;
        if (occupy_co && occupy_co != pending_co) {
            // 保存 occupy_co 的运行时栈的内容
            save_stack_buffer(occupy_co);
        }
    }

    //swap context
    // 交换上下文，保存 curr 寄存器，恢复 pending_co 的寄存器
    // 切换 ebp、esp 使其指向 pending_co 的协程栈
    coctx_swap(&(curr->ctx), &(pending_co->ctx));

    //stack buffer may be overwrite, so get again;
    // 这里已经到 pending_co 的环境了，所以可以直接取出
    stCoRoutineEnv_t* curr_env = co_get_curr_thread_env();
    stCoRoutine_t* update_occupy_co = curr_env->occupy_co;
    stCoRoutine_t* update_pending_co = curr_env->pending_co;

    // 恢复栈内容，如果是私有栈则不用恢复，如果 occupy_co 和 pending_co 不是同一协程则需要恢复
    if (update_occupy_co && update_pending_co && update_occupy_co != update_pending_co) {
        //resume stack buffer
        if (update_pending_co->save_buffer && update_pending_co->save_size > 0) {
            memcpy(update_pending_co->stack_sp, update_pending_co->save_buffer, update_pending_co->save_size);
        }
    }
}

//int poll(struct pollfd fds[], nfds_t nfds, int timeout);
// { fd,events,revents }
struct stPollItem_t;
struct stPoll_t : public stTimeoutItem_t {
    struct pollfd* fds;
    nfds_t nfds; // typedef unsigned long int nfds_t;

    stPollItem_t* pPollItems;

    int iAllEventDetach;

    int iEpollFd;

    int iRaiseCnt;
};
struct stPollItem_t : public stTimeoutItem_t {
    struct pollfd* pSelf;
    stPoll_t* pPoll;

    struct epoll_event stEvent;
};
/*
 *   EPOLLPRI 		POLLPRI    // There is urgent data to read.  
 *   EPOLLMSG 		POLLMSG
 *
 *   				POLLREMOVE
 *   				POLLRDHUP
 *   				POLLNVAL
 *
 * */
static uint32_t PollEvent2Epoll(short events)
{
    uint32_t e = 0;
    if (events & POLLIN)
        e |= EPOLLIN;
    if (events & POLLOUT)
        e |= EPOLLOUT;
    if (events & POLLHUP)
        e |= EPOLLHUP;
    if (events & POLLERR)
        e |= EPOLLERR;
    if (events & POLLRDNORM)
        e |= EPOLLRDNORM;
    if (events & POLLWRNORM)
        e |= EPOLLWRNORM;
    return e;
}
static short EpollEvent2Poll(uint32_t events)
{
    short e = 0;
    if (events & EPOLLIN)
        e |= POLLIN;
    if (events & EPOLLOUT)
        e |= POLLOUT;
    if (events & EPOLLHUP)
        e |= POLLHUP;
    if (events & EPOLLERR)
        e |= POLLERR;
    if (events & EPOLLRDNORM)
        e |= POLLRDNORM;
    if (events & EPOLLWRNORM)
        e |= POLLWRNORM;
    return e;
}

static __thread stCoRoutineEnv_t* gCoEnvPerThread = NULL;

void co_init_curr_thread_env()
{
    gCoEnvPerThread = (stCoRoutineEnv_t*)calloc(1, sizeof(stCoRoutineEnv_t));
    stCoRoutineEnv_t* env = gCoEnvPerThread;

    env->iCallStackSize = 0;
    struct stCoRoutine_t* self = co_create_env(env, NULL, NULL, NULL);
    self->cIsMain = 1;

    env->pending_co = NULL;
    env->occupy_co = NULL;

    coctx_init(&self->ctx);

    env->pCallStack[env->iCallStackSize++] = self;

    stCoEpoll_t* ev = AllocEpoll();
    SetEpoll(env, ev);
}
stCoRoutineEnv_t* co_get_curr_thread_env()
{
    return gCoEnvPerThread;
}

void OnPollProcessEvent(stTimeoutItem_t* ap)
{
    stCoRoutine_t* co = (stCoRoutine_t*)ap->pArg;
    co_resume(co);
}

void OnPollPreparePfn(stTimeoutItem_t* ap, struct epoll_event& e, stTimeoutItemLink_t* active)
{
    stPollItem_t* lp = (stPollItem_t*)ap;
    lp->pSelf->revents = EpollEvent2Poll(e.events);

    stPoll_t* pPoll = lp->pPoll;
    pPoll->iRaiseCnt++;

    if (!pPoll->iAllEventDetach) {
        pPoll->iAllEventDetach = 1;

        RemoveFromLink<stTimeoutItem_t, stTimeoutItemLink_t>(pPoll);

        AddTail(active, pPoll);
    }
}

void co_eventloop(stCoEpoll_t* ctx, pfn_co_eventloop_t pfn, void* arg)
{
    if (!ctx->result) {
        ctx->result = co_epoll_res_alloc(stCoEpoll_t::_EPOLL_SIZE);
    }
    co_epoll_res* result = ctx->result;

    for (;;) {
        int ret = co_epoll_wait(ctx->iEpollFd, result, stCoEpoll_t::_EPOLL_SIZE, 1);

        stTimeoutItemLink_t* active = (ctx->pstActiveList);
        stTimeoutItemLink_t* timeout = (ctx->pstTimeoutList);

        memset(timeout, 0, sizeof(stTimeoutItemLink_t));

        for (int i = 0; i < ret; i++) {
            stTimeoutItem_t* item = (stTimeoutItem_t*)result->events[i].data.ptr;
            if (item->pfnPrepare) {
                item->pfnPrepare(item, result->events[i], active);
            } else {
                AddTail(active, item);
            }
        }

        unsigned long long now = GetTickMS();
        TakeAllTimeout(ctx->pTimeout, now, timeout);

        stTimeoutItem_t* lp = timeout->head;
        while (lp) {
            //printf("raise timeout %p\n",lp);
            lp->bTimeout = true;
            lp = lp->pNext;
        }

        Join<stTimeoutItem_t, stTimeoutItemLink_t>(active, timeout);

        lp = active->head;
        while (lp) {

            PopHead<stTimeoutItem_t, stTimeoutItemLink_t>(active);
            if (lp->bTimeout && now < lp->ullExpireTime) {
                int ret = AddTimeout(ctx->pTimeout, lp, now);
                if (!ret) {
                    lp->bTimeout = false;
                    lp = active->head;
                    continue;
                }
            }
            if (lp->pfnProcess) {
                lp->pfnProcess(lp);
            }

            lp = active->head;
        }
        if (pfn) {
            if (-1 == pfn(arg)) {
                break;
            }
        }
    }
}
void OnCoroutineEvent(stTimeoutItem_t* ap)
{
    stCoRoutine_t* co = (stCoRoutine_t*)ap->pArg;
    co_resume(co);
}

stCoEpoll_t* AllocEpoll()
{
    stCoEpoll_t* ctx = (stCoEpoll_t*)calloc(1, sizeof(stCoEpoll_t));

    ctx->iEpollFd = co_epoll_create(stCoEpoll_t::_EPOLL_SIZE);
    ctx->pTimeout = AllocTimeout(60 * 1000);

    ctx->pstActiveList = (stTimeoutItemLink_t*)calloc(1, sizeof(stTimeoutItemLink_t));
    ctx->pstTimeoutList = (stTimeoutItemLink_t*)calloc(1, sizeof(stTimeoutItemLink_t));

    return ctx;
}

void FreeEpoll(stCoEpoll_t* ctx)
{
    if (ctx) {
        free(ctx->pstActiveList);
        free(ctx->pstTimeoutList);
        FreeTimeout(ctx->pTimeout);
        co_epoll_res_free(ctx->result);
    }
    free(ctx);
}

stCoRoutine_t* GetCurrCo(stCoRoutineEnv_t* env)
{
    return env->pCallStack[env->iCallStackSize - 1];
}
stCoRoutine_t* GetCurrThreadCo()
{
    stCoRoutineEnv_t* env = co_get_curr_thread_env();
    if (!env)
        return 0;
    return GetCurrCo(env);
}

typedef int (*poll_pfn_t)(struct pollfd fds[], nfds_t nfds, int timeout);
int co_poll_inner(stCoEpoll_t* ctx, struct pollfd fds[], nfds_t nfds, int timeout, poll_pfn_t pollfunc)
{
    if (timeout == 0) {
        return pollfunc(fds, nfds, timeout);
    }
    if (timeout < 0) {
        timeout = INT_MAX;
    }
    int epfd = ctx->iEpollFd;
    stCoRoutine_t* self = co_self();

    //1.struct change
    stPoll_t& arg = *((stPoll_t*)malloc(sizeof(stPoll_t)));
    memset(&arg, 0, sizeof(arg));

    arg.iEpollFd = epfd;
    arg.fds = (pollfd*)calloc(nfds, sizeof(pollfd));
    arg.nfds = nfds;

    stPollItem_t arr[2];
    if (nfds < sizeof(arr) / sizeof(arr[0]) && !self->cIsShareStack) {
        arg.pPollItems = arr;
    } else {
        arg.pPollItems = (stPollItem_t*)malloc(nfds * sizeof(stPollItem_t));
    }
    memset(arg.pPollItems, 0, nfds * sizeof(stPollItem_t));

    arg.pfnProcess = OnPollProcessEvent;
    arg.pArg = GetCurrCo(co_get_curr_thread_env());

    //2. add epoll
    for (nfds_t i = 0; i < nfds; i++) {
        arg.pPollItems[i].pSelf = arg.fds + i;
        arg.pPollItems[i].pPoll = &arg;

        arg.pPollItems[i].pfnPrepare = OnPollPreparePfn;
        struct epoll_event& ev = arg.pPollItems[i].stEvent;

        if (fds[i].fd > -1) {
            ev.data.ptr = arg.pPollItems + i;
            ev.events = PollEvent2Epoll(fds[i].events);

            int ret = co_epoll_ctl(epfd, EPOLL_CTL_ADD, fds[i].fd, &ev);
            if (ret < 0 && errno == EPERM && nfds == 1 && pollfunc != NULL) {
                if (arg.pPollItems != arr) {
                    free(arg.pPollItems);
                    arg.pPollItems = NULL;
                }
                free(arg.fds);
                free(&arg);
                return pollfunc(fds, nfds, timeout);
            }
        }
        //if fail,the timeout would work
    }

    //3.add timeout

    unsigned long long now = GetTickMS();
    arg.ullExpireTime = now + timeout;
    int ret = AddTimeout(ctx->pTimeout, &arg, now);
    int iRaiseCnt = 0;
    if (ret != 0) {
        co_log_err("CO_ERR: AddTimeout ret %d now %lld timeout %d arg.ullExpireTime %lld",
            ret, now, timeout, arg.ullExpireTime);
        errno = EINVAL;
        iRaiseCnt = -1;

    } else {
        co_yield_env(co_get_curr_thread_env());
        iRaiseCnt = arg.iRaiseCnt;
    }

    {
        //clear epoll status and memory
        RemoveFromLink<stTimeoutItem_t, stTimeoutItemLink_t>(&arg);
        for (nfds_t i = 0; i < nfds; i++) {
            int fd = fds[i].fd;
            if (fd > -1) {
                co_epoll_ctl(epfd, EPOLL_CTL_DEL, fd, &arg.pPollItems[i].stEvent);
            }
            fds[i].revents = arg.fds[i].revents;
        }

        if (arg.pPollItems != arr) {
            free(arg.pPollItems);
            arg.pPollItems = NULL;
        }

        free(arg.fds);
        free(&arg);
    }

    return iRaiseCnt;
}

int co_poll(stCoEpoll_t* ctx, struct pollfd fds[], nfds_t nfds, int timeout_ms)
{
    return co_poll_inner(ctx, fds, nfds, timeout_ms, NULL);
}

void SetEpoll(stCoRoutineEnv_t* env, stCoEpoll_t* ev)
{
    env->pEpoll = ev;
}
stCoEpoll_t* co_get_epoll_ct()
{
    if (!co_get_curr_thread_env()) {
        co_init_curr_thread_env();
    }
    return co_get_curr_thread_env()->pEpoll;
}
struct stHookPThreadSpec_t {
    stCoRoutine_t* co;
    void* value;

    enum {
        size = 1024
    };
};
void* co_getspecific(pthread_key_t key)
{
    stCoRoutine_t* co = GetCurrThreadCo();
    if (!co || co->cIsMain) {
        return pthread_getspecific(key);
    }
    return co->aSpec[key].value;
}
int co_setspecific(pthread_key_t key, const void* value)
{
    stCoRoutine_t* co = GetCurrThreadCo();
    if (!co || co->cIsMain) {
        return pthread_setspecific(key, value);
    }
    co->aSpec[key].value = (void*)value;
    return 0;
}

void co_disable_hook_sys()
{
    stCoRoutine_t* co = GetCurrThreadCo();
    if (co) {
        co->cEnableSysHook = 0;
    }
}
bool co_is_enable_sys_hook()
{
    stCoRoutine_t* co = GetCurrThreadCo();
    return (co && co->cEnableSysHook);
}

stCoRoutine_t* co_self()
{
    return GetCurrThreadCo();
}

//co cond
struct stCoCond_t;
struct stCoCondItem_t {
    stCoCondItem_t* pPrev;
    stCoCondItem_t* pNext;
    stCoCond_t* pLink;

    stTimeoutItem_t timeout;
};
struct stCoCond_t {
    stCoCondItem_t* head;
    stCoCondItem_t* tail;
};
static void OnSignalProcessEvent(stTimeoutItem_t* ap)
{
    stCoRoutine_t* co = (stCoRoutine_t*)ap->pArg;
    co_resume(co);
}

stCoCondItem_t* co_cond_pop(stCoCond_t* link);
int co_cond_signal(stCoCond_t* si)
{
    stCoCondItem_t* sp = co_cond_pop(si);
    if (!sp) {
        return 0;
    }
    RemoveFromLink<stTimeoutItem_t, stTimeoutItemLink_t>(&sp->timeout);

    AddTail(co_get_curr_thread_env()->pEpoll->pstActiveList, &sp->timeout);

    return 0;
}
int co_cond_broadcast(stCoCond_t* si)
{
    for (;;) {
        stCoCondItem_t* sp = co_cond_pop(si);
        if (!sp)
            return 0;

        RemoveFromLink<stTimeoutItem_t, stTimeoutItemLink_t>(&sp->timeout);

        AddTail(co_get_curr_thread_env()->pEpoll->pstActiveList, &sp->timeout);
    }

    return 0;
}

int co_cond_timedwait(stCoCond_t* link, int ms)
{
    stCoCondItem_t* psi = (stCoCondItem_t*)calloc(1, sizeof(stCoCondItem_t));
    psi->timeout.pArg = GetCurrThreadCo();
    psi->timeout.pfnProcess = OnSignalProcessEvent;

    if (ms > 0) {
        unsigned long long now = GetTickMS();
        psi->timeout.ullExpireTime = now + ms;

        int ret = AddTimeout(co_get_curr_thread_env()->pEpoll->pTimeout, &psi->timeout, now);
        if (ret != 0) {
            free(psi);
            return ret;
        }
    }
    AddTail(link, psi);

    co_yield_ct();

    RemoveFromLink<stCoCondItem_t, stCoCond_t>(psi);
    free(psi);

    return 0;
}
stCoCond_t* co_cond_alloc()
{
    return (stCoCond_t*)calloc(1, sizeof(stCoCond_t));
}
int co_cond_free(stCoCond_t* cc)
{
    free(cc);
    return 0;
}

stCoCondItem_t* co_cond_pop(stCoCond_t* link)
{
    stCoCondItem_t* p = link->head;
    if (p) {
        PopHead<stCoCondItem_t, stCoCond_t>(link);
    }
    return p;
}
