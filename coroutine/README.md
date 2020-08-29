原仓库地址：[coroutine](https://github.com/cloudwu/coroutine/)

基于`ucontext`实现的共享栈的协程库。

结构上实现了一个协程调度器，以及协程的结构体。

协程有死亡态，挂起态，就绪态，运行态，通过各种函数进行状态转换。

`ucontext.h`的简单介绍可以参考[这里](https://momorz.github.io/2020/08/29/ucontext%E5%BA%93%E6%8E%A5%E5%8F%A3%E7%AE%80%E5%8D%95%E4%BB%8B%E7%BB%8D/)。

