//
//  QGDecompileProtect.m
//  DecompilationProtect
//
//  Created by   on 2019/8/16.
//  Copyright © 2019年 jorgon. All rights reserved.
//

#import "QGDecompileProtect.h"

//ptrace
#import <dlfcn.h>
#import <sys/types.h>
//sysctl
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/sysctl.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/sysctl.h>
#include <stdlib.h>

//ptrace反调试
#import <dlfcn.h>
#import <sys/types.h>
typedef int (*ptrace_ptr_t)(int _request, pid_t pid, caddr_t _addr, int _data);
#if !defined(PT_DENT_ATTACH)
#define PT_DENT_ATTACH 31
#endif

void disable_gdb() {
    void * handle = dlopen(0, RTLD_GLOBAL|RTLD_NOW);
    ptrace_ptr_t ptrace_ptr = dlsym(handle, "ptrace");
    ptrace_ptr(PT_DENT_ATTACH, 0, 0, 0);
    dlclose(handle);
}

static bool is_debugger_present(void) {
    int name[4];//存放字节码，查询信息
    struct kinfo_proc info;//接受进程查询结果信息的结构体
    size_t info_size = sizeof(info);//结构体的大小
    
    info.kp_proc.p_flag = 0;
    name[0] = CTL_KERN;//内核查看
    name[1] = KERN_PROC;//进程查看
    name[2] = KERN_PROC_PID;//进程ID
    name[3] = getpid();//获取pid，据说这个可以直接传0?
    
    int proc_err = sysctl(name, 4, &info, &info_size, NULL, 0);
    if (proc_err == -1) { //判断是否出现了异常
        exit(-1);
    }
    //info.kp_proc.p_flag中存放的是标志位（二进制），在proc.h文件中有p_flag的宏定义，通过&运算可知对应标志位的值是否为0。（若结果值为0则对应标志位为0）。其中P_TRACED为正在跟踪调试过程。
    return ((info.kp_proc.p_flag & P_TRACED) != 0);
}

@implementation QGDecompileProtect

@end
