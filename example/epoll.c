/*
 *  Collin's Binary Instrumentation Tool/Framework for Android
 *  Collin Mulliner <collin[at]mulliner.org>
 *  http://www.mulliner.org/android/
 *
 *  (c) 2012,2013
 *
 *  License: LGPL v2.1
 *
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <string.h>
#include <termios.h>
#include <pthread.h>
#include <sys/epoll.h>

#include <jni.h>
#include <stdlib.h>

// #include "android_runtime/AndroidRuntime.h"

#include "../base/hook.h"
#include "../base/base.h"

#undef log

#define log(...) \
        {FILE *fp = fopen("/data/local/tmp/adbi_example.log", "a+"); if (fp) {\
        fprintf(fp, __VA_ARGS__);\
        fclose(fp);}}


// this file is going to be compiled into a thumb mode binary

void __attribute__ ((constructor)) my_init(void);

static struct hook_t eph;

// for demo code only
static int counter;

// arm version of hook
extern int my_epoll_wait_arm(int epfd, struct epoll_event *events, int maxevents, int timeout);

/*  
 *  log function to pass to the hooking library to implement central loggin
 *
 *  see: set_logfunction() in base.h
 */
static void my_log(char *msg)
{
	log("%s", msg)
}

int my_epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout)
{
	int (*orig_epoll_wait)(int epfd, struct epoll_event *events, int maxevents, int timeout);
	orig_epoll_wait = (void*)eph.orig;

	hook_precall(&eph);
	int res = orig_epoll_wait(epfd, events, maxevents, timeout);
	if (counter) {
		hook_postcall(&eph);
		log("epoll_wait() called\n");
		counter--;
		if (!counter)
			log("removing hook for epoll_wait()\n");
	}
        
	return res;
}

void my_init(void){
    int i = 0;
    log("start")
    void *handle = dlopen("libdvm.so", RTLD_LAZY);
    if (handle == NULL) {
        log("%s\n", "can not open libdvm.so")
        return;
    }

    int gdvm = (int)dlsym(handle, "gDvm");
    if (gdvm != 0) {
        log("%s0x%x\n", "get gDvm address=", gdvm);
    }

    void *func = dlsym(handle, "_Z25dvmInternalNativeShutdownv");
    if (func != NULL) {
        int address = (int)func;
        if (address % 2 != 0)
            address--;
        log("%s0x%x\n", "Get function:", address)
        for ( ; i < 32; i++) {
            log("\\x%02x", *(char*)(address+i))
        }
        log("\n")
    } else {
        log("func is NULL: %s\n", dlerror())
    }

    dlclose(handle);
}
