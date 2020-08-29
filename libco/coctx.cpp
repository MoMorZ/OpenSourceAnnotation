/*
* Tencent is pleased to support the open source community by making Libco
available.

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

#include "coctx.h"
#include <stdio.h>
#include <string.h>

#define ESP 0
#define EIP 1
#define EAX 2
#define ECX 3
// -----------
#define RSP 0
#define RIP 1
#define RBX 2
#define RDI 3
#define RSI 4

#define RBP 5
#define R12 6
#define R13 7
#define R14 8
#define R15 9
#define RDX 10
#define RCX 11
#define R8 12
#define R9 13

//----- --------
// 32 bit
// | regs[0]: ret |
// | regs[1]: ebx |
// | regs[2]: ecx |
// | regs[3]: edx |
// | regs[4]: edi |
// | regs[5]: esi |
// | regs[6]: ebp |
// | regs[7]: eax |  = esp
enum {
    kEIP = 0,
    kEBP = 6,
    kESP = 7,
};

//-------------
// 64 bit
// low | regs[0]: r15 |
//    | regs[1]: r14 |
//    | regs[2]: r13 |
//    | regs[3]: r12 |
//    | regs[4]: r9  |
//    | regs[5]: r8  |
//    | regs[6]: rbp |
//    | regs[7]: rdi |
//    | regs[8]: rsi |
//    | regs[9]: ret |  //ret func addr
//    | regs[10]: rdx |
//    | regs[11]: rcx |
//    | regs[12]: rbx |
// hig | regs[13]: rsp |
enum {
    kRDI = 7,
    kRSI = 8,
    kRETAddr = 9,
    kRSP = 13,
};

// 64 bit
/**
 * @brief 切换上下文，并跳转到调用该函数的下一条语句
 * 
 */
extern "C" {
extern void coctx_swap(coctx_t*, coctx_t*) asm("coctx_swap");
};
#if defined(__i386__)
/**
 * @brief 初始化上下文，内存空间清零
 * 
 * @param ctx 上下文指针
 * @return int 0
 */
int coctx_init(coctx_t* ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    return 0;
}

/**
 * @brief 创建上下文，初始化栈和跳转点
 * 
 * @param ctx 上下文指针
 * @param pfn 协程函数指针
 * @param s 协程指针
 * @param s1 协程函数参数指针
 * @return int 0
 */
int coctx_make(coctx_t* ctx, coctx_pfn_t pfn, const void* s, const void* s1)
{
    // make room for coctx_param
    char* sp = ctx->ss_sp + ctx->ss_size - sizeof(coctx_param_t); // 栈顶指针从高地址开始，需要减去两个参数的大小，用于放置 s 和 s1
    sp = (char*)((unsigned long)sp & -16L); // 内存对齐，后4位清零

    coctx_param_t* param = (coctx_param_t*)sp;
    void** ret_addr = (void**)(sp - sizeof(void*) * 2); // ra 返回地址，在 sp 的基础上还要减去前两个参数的大小
    *ret_addr = (void*)pfn; // 设置返回地址指向协程函数指针
    param->s1 = s; // 设置协程指针
    param->s2 = s1; // 设置函数参数指针

    memset(ctx->regs, 0, sizeof(ctx->regs)); // 寄存器清零

    ctx->regs[kESP] = (char*)(sp) - sizeof(void*) * 2; // esp 存放的是返回地址
    return 0;
}
#elif defined(__x86_64__)
int coctx_make(coctx_t* ctx, coctx_pfn_t pfn, const void* s, const void* s1)
{
    char* sp = ctx->ss_sp + ctx->ss_size - sizeof(void*); // 这里不确定为什么只减了一个指针的大小？
    sp = (char*)((unsigned long)sp & -16LL); // 内存对齐，后4位清零

    memset(ctx->regs, 0, sizeof(ctx->regs)); // 寄存器清零
    void** ret_addr = (void**)(sp); // ra 返回地址
    *ret_addr = (void*)pfn; // 设置返回地址指向协程函数指针

    ctx->regs[kRSP] = sp; // rsp 设置为栈底

    ctx->regs[kRETAddr] = (char*)pfn; // ret 设置为协程函数

    ctx->regs[kRDI] = (char*)s; // rdi 设置协程指针
    ctx->regs[kRSI] = (char*)s1; // rsi 设置函数参数指针
    return 0;
}

int coctx_init(coctx_t* ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    return 0;
}

#endif
