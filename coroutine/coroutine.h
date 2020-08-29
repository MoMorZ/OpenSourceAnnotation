/*
 * @Author: your name
 * @Date: 2020-08-18 15:29:41
 * @LastEditTime: 2020-08-18 19:08:06
 * @LastEditors: Please set LastEditors
 * @Description: In User Settings Edit
 * @FilePath: \coroutine\coroutine.h
 */
#ifndef C_COROUTINE_H
#define C_COROUTINE_H

// 协程状态码
#define COROUTINE_DEAD 0 // 死亡
#define COROUTINE_READY 1 // 就绪
#define COROUTINE_RUNNING 2 // 运行中
#define COROUTINE_SUSPEND 3 // 挂起

struct schedule;

/**
 * @brief 函数指针
 */
typedef void (*coroutine_func)(struct schedule*, void* ud);

/**
 * @brief 创建并返回一个新的协程调度器
 * 
 * @return struct schedule* 新的协程调度器的指针
 */
struct schedule* coroutine_open(void);

/**
 * @brief 关闭一个协程调度器
 * 
 * @param S 调度器指针
 */
void coroutine_close(struct schedule*);

/**
 * @brief 创建一个新的协程对象
 * 
 * @param S 调度器指针
 * @param func 函数指针
 * @param ud 函数参数列表
 * @return int 成功则返回协程 id,否则返回-1
 */
int coroutine_new(struct schedule*, coroutine_func, void* ud);

/**
 * @brief 切换到 id 对应的协程
 * 
 * @param S 调度器指针
 * @param id 协程 id
 */
void coroutine_resume(struct schedule*, int id);

/**
 * @brief 返回 id 对应协程的状态
 * 
 * @param S 调度器指针
 * @param id 协程 id
 * @return int 协程状态
 */
int coroutine_status(struct schedule*, int id);

/**
 * @brief 返回正在运行的协程 id
 * 
 * @param S 调度器 id
 * @return int 正在运行的协程 id
 */
int coroutine_running(struct schedule*);

/**
 * @brief 切出当前协程，切换到主协程
 * 
 * @param S 调度器指针
 */
void coroutine_yield(struct schedule*);

#endif
