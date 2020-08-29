#include "coroutine.h"
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if __APPLE__ && __MACH__
#include <sys/ucontext.h>
#else
#include <ucontext.h>
#endif

// 默认栈大小
#define STACK_SIZE (1024 * 1024)
// 初始最大协程数
#define DEFAULT_COROUTINE 16

struct coroutine;

/**
 * @brief 调度器
 * 
 */
struct schedule {
    char stack[STACK_SIZE]; // 运行时栈
    ucontext_t main; // 主协程上下文
    int nco; // 当前存活协程数目
    int cap; // 调度器所能容纳的最大协程数，即容量，不够则进行双倍扩容
    int running; // 当前正在执行的协程的 id
    struct coroutine** co; // 一维数组，用于存放协程指针
};

/**
 * @brief 协程
 * 
 */
struct coroutine {
    coroutine_func func; // 协程需要运行的函数的指针
    void* ud; // 协程的参数
    ucontext_t ctx; // 上下文
    struct schedule* sch; // 协程所属的调度器的指针
    ptrdiff_t cap; // 协程栈已分配内存大小，即协程栈容量
    ptrdiff_t size; // 协程栈保存后的大小
    int status; // 协程状态
    char* stack; // 当前协程保存的运行时栈，这里简称为协程栈
};

/**
 * @brief 创建一个新协程并返回其指针
 * 
 * @param S 调度器指针
 * @param func 函数指针
 * @param ud 参数列表
 * @return struct coroutine* 创建的协程的指针 
 */
struct coroutine*
_co_new(struct schedule* S, coroutine_func func, void* ud)
{
    // 分配对应内存
    struct coroutine* co = malloc(sizeof(*co));
    // 赋初值
    co->func = func; // 设置函数指针
    co->ud = ud; // 设置函数参数列表
    co->sch = S; // 设置所属调度器
    co->cap = 0; //初始容量为零
    co->size = 0; // 初始协程栈大小为零
    co->status = COROUTINE_READY; // 初始状态为就绪
    co->stack = NULL; // 运行时栈指向空
    return co;
}

/**
 * @brief 释放协程内存
 * 
 * @param co 协程指针
 */
void _co_delete(struct coroutine* co)
{
    free(co->stack);
    free(co);
}

struct schedule*
coroutine_open(void)
{
    // 分配对应内存
    struct schedule* S = malloc(sizeof(*S));
    S->nco = 0; // 初始协程存活数为零
    S->cap = DEFAULT_COROUTINE; // 初始化协程容量
    S->running = -1; // 无运行中协程，设为 -1
    S->co = malloc(sizeof(struct coroutine*) * S->cap); // 分配协程数组空间
    memset(S->co, 0, sizeof(struct coroutine*) * S->cap); // 协程数组内存初始化为零
    return S;
}

void coroutine_close(struct schedule* S)
{
    int i;
    // 取出调度器所管辖的所有协程
    for (i = 0; i < S->cap; i++) {
        struct coroutine* co = S->co[i];
        // 如果还没释放，则进行释放
        if (co) {
            _co_delete(co);
        }
    }
    // 释放协程数组空间
    free(S->co);
    S->co = NULL;
    free(S);
}

int coroutine_new(struct schedule* S, coroutine_func func, void* ud)
{
    // 创建新协程
    struct coroutine* co = _co_new(S, func, ud);
    // 若当前协程存活数超过容量
    if (S->nco >= S->cap) {
        // 新协程 id 显然为 cap
        int id = S->cap;
        // 拓展已分配内存为原来的两倍
        S->co = realloc(S->co, S->cap * 2 * sizeof(struct coroutine*));
        // 初始化新分配内存为零
        memset(S->co + S->cap, 0, sizeof(struct coroutine*) * S->cap);
        // 新协程放入调度器
        S->co[S->cap] = co;
        // 修改容量
        S->cap *= 2;
        // 增加协程存活数
        ++S->nco;
        return id;
    } else {
        int i;
        // 若当前协程数未超过容量
        // 则枚举协程数组，寻找可插入新协程的空位
        for (i = 0; i < S->cap; i++) {
            // 从 nco 开始寻找插入位置，小优化
            // 因为前 nco 个大概率是非 NULL 的
            int id = (i + S->nco) % S->cap;
            // 找到后将新协程放入
            if (S->co[id] == NULL) {
                S->co[id] = co;
                ++S->nco;
                return id;
            }
        }
    }
    assert(0);
    // 创建失败，返回 -1
    return -1;
}

/**
 * @brief 协程需执行函数的封装
 * 
 * @param low32 调度器指针的低32位
 * @param hi32 调度器指针的高32位
 */
static void
mainfunc(uint32_t low32, uint32_t hi32)
{
    // 使用拼接指针的原因是
    // makecontext 函数指针的参数列表是可变 int
    // 在64位系统下，单个 int 无法承载一个指针
    uintptr_t ptr = (uintptr_t)low32 | ((uintptr_t)hi32 << 32); // 拼接得到完整的调度器指针
    struct schedule* S = (struct schedule*)ptr; // 指针转换
    int id = S->running; // 获取当前正在执行的协程 id
    struct coroutine* C = S->co[id]; // 根据 id 取出相应协程
    C->func(S, C->ud); // 根据传入的函数指针及参数列表执行函数
    _co_delete(C); // 释放协程
    S->co[id] = NULL; // 相应位置设空
    --S->nco; // 减少存活数
    S->running = -1; // 当前无运行中协程
}

void coroutine_resume(struct schedule* S, int id)
{
    assert(S->running == -1); // 检查是否有运行中协程
    assert(id >= 0 && id < S->cap); // 检查 id 合法性
    struct coroutine* C = S->co[id]; // 取出 id 对应协程
    if (C == NULL)
        return;
    int status = C->status; // 取协程状态
    switch (status) {
    case COROUTINE_READY: // 就绪
        getcontext(&C->ctx); // 调用 getcontext 获取当前上下文并保存到 C->ctx 中
        C->ctx.uc_stack.ss_sp = S->stack; // 指定分配给上下文的栈，这里用的是共享栈，传过去的是栈顶
        C->ctx.uc_stack.ss_size = STACK_SIZE; // 设定栈大小为默认大小
        C->ctx.uc_link = &S->main; // 后继上下文设为主协程
        S->running = id; // 执行中协程设为当前协程
        C->status = COROUTINE_RUNNING; // 协程状态设置为运行中
        uintptr_t ptr = (uintptr_t)S;
        // 将函数和堆栈绑定到新建的上下文中
        makecontext(&C->ctx, (void (*)(void))mainfunc, 2, (uint32_t)ptr, (uint32_t)(ptr >> 32));
        swapcontext(&S->main, &C->ctx); // 将当前上下文保存到主协程，切换到新建的上下文，开始执行 mainfunc
        break;
    case COROUTINE_SUSPEND: // 挂起
        // 将协程栈的内容保存到运行时栈
        // 注意，Linux 下，栈从高地址向低地址扩展
        // 故 S->stack + STACK_SIZE 得到的是栈底
        memcpy(S->stack + STACK_SIZE - C->size, C->stack, C->size);
        S->running = id; // 执行中协程设为当前协程
        C->status = COROUTINE_RUNNING; // 协程状态设置为运行中
        swapcontext(&S->main, &C->ctx); // 将当前上下文保存到主协程，切换到被挂起协程的上下文，开始执行 mainfunc
        break;
    default:
        assert(0);
    }
}

/**
 * @brief 保存协程运行时栈
 * 
 * @param C 协程指针
 * @param top 运行时栈栈顶指针
 */
static void
_save_stack(struct coroutine* C, char* top)
{
    // 新创建一个变量，该变量刚刚被分配到栈上
    // 则该变量所在的位置是在运行时栈的其他变量末尾
    // 故运行时栈的大小为 S->stack + STACK_SIZE - &dummy
    // 即 top - &dummy
    char dummy = 0;
    assert(top - &dummy <= STACK_SIZE);
    // 若协程栈容量小于当前运行时栈的大小
    // 则需要重新分配
    if (C->cap < top - &dummy) {
        free(C->stack);
        C->cap = top - &dummy;
        C->stack = malloc(C->cap);
    }
    C->size = top - &dummy; // 设置协程栈的大小
    memcpy(C->stack, &dummy, C->size); // 将运行时栈的内容保存到协程栈中
}

void coroutine_yield(struct schedule* S)
{
    int id = S->running; // 取出当前执行中协程的 id
    assert(id >= 0);
    struct coroutine* C = S->co[id]; // 根据 id 取出协程指针
    assert((char*)&C > S->stack);
    _save_stack(C, S->stack + STACK_SIZE); // 将当前运行时栈保存到该协程的协程栈中
    C->status = COROUTINE_SUSPEND; // 设置该协程状态为挂起
    S->running = -1; // 执行中协程设置为无
    swapcontext(&C->ctx, &S->main); // 从当前协程切到主协程
}

int coroutine_status(struct schedule* S, int id)
{
    assert(id >= 0 && id < S->cap);
    if (S->co[id] == NULL) {
        return COROUTINE_DEAD;
    }
    return S->co[id]->status;
}

int coroutine_running(struct schedule* S)
{
    return S->running;
}
