/*
 * Changes:
 *   Nov 22, 2009:	added basic live update support  (Cristiano Giuffrida)
 *   Mar 02, 2009:	Extended isolation policies  (Jorrit N. Herder)
 *   Jul 22, 2005:	Created  (Jorrit N. Herder)
 */

#include <paths.h>

#include <sys/exec_elf.h>

#include "inc.h"

#include "kernel/proc.h"

static int run_script(struct rproc *rp);

/*===========================================================================*
 *				caller_is_root				     *
 *===========================================================================*/
static int caller_is_root(endpoint)
endpoint_t endpoint;				/* caller endpoint */
{
  uid_t euid;

  /* Check if caller has root user ID. */
  euid = getnuid(endpoint);
  if (rs_verbose && euid != 0)
  {
	printf("RS: got unauthorized request from endpoint %d\n", endpoint);
  }
  
  return euid == 0;
}

/*===========================================================================*
 *				caller_can_control			     *
 *===========================================================================*/
static int caller_can_control(endpoint, target_rp)
endpoint_t endpoint;
struct rproc *target_rp;
{
  int control_allowed = 0;
  register struct rproc *rp;
  register struct rprocpub *rpub;
  char *proc_name;
  int c;

  proc_name = target_rp->r_pub->proc_name;

  /* Check if label is listed in caller's isolation policy. */
  for (rp = BEG_RPROC_ADDR; rp < END_RPROC_ADDR; rp++) {
	if (!(rp->r_flags & RS_IN_USE))
		continue;

	rpub = rp->r_pub;
	if (rpub->endpoint == endpoint) {
		break;
	}
  }
  if (rp == END_RPROC_ADDR) return 0;

  for (c = 0; c < rp->r_nr_control; c++) {
	if (strcmp(rp->r_control[c], proc_name) == 0) {
		control_allowed = 1;
		break;
	}
  }

  if (rs_verbose) 
	printf("RS: allowing %u control over %s via policy: %s\n",
		endpoint, target_rp->r_pub->label,
		control_allowed ? "yes" : "no");

  return control_allowed;
}

/*===========================================================================*
 *			     check_call_permission			     *
 *===========================================================================*/
int check_call_permission(caller, call, rp)
endpoint_t caller;
int call;
struct rproc *rp;
{
/* Check if the caller has permission to execute a particular call. */
  struct rprocpub *rpub;
  int call_allowed;

  /* Caller should be either root or have control privileges. */
  call_allowed = caller_is_root(caller);
  if(rp) {
      call_allowed |= caller_can_control(caller, rp);
  }
  if(!call_allowed) {
      return EPERM;
  }

  if(rp) {
      rpub = rp->r_pub;

      /* Only allow RS_EDIT if the target is a user process. */
      if(!(rp->r_priv.s_flags & SYS_PROC)) {
          if(call != RS_EDIT) return EPERM;
      }

      /* Disallow the call if an update is in progress. */
      if(RUPDATE_IS_UPDATING()) {
      	  return EBUSY;
      }

      /* Disallow the call if another call is in progress for the service. */
      if((rp->r_flags & RS_LATEREPLY)
          || (rp->r_flags & RS_INITIALIZING)) {
          return EBUSY;
      }

      /* Only allow RS_DOWN and RS_RESTART if the service has terminated. */
      if(rp->r_flags & RS_TERMINATED) {
          if(call != RS_DOWN && call != RS_RESTART) return EPERM;
      }

      /* Disallow RS_DOWN for core system services. */
      if (rpub->sys_flags & SF_CORE_SRV) {
          if(call == RS_DOWN) return EPERM;
      }
  }

  return OK;
}

/*===========================================================================*
 *				copy_rs_start				     *
 *===========================================================================*/
int copy_rs_start(src_e, src_rs_start, dst_rs_start)
endpoint_t src_e;
char *src_rs_start;
struct rs_start *dst_rs_start;
{
  int r;

  r = sys_datacopy(src_e, (vir_bytes) src_rs_start, 
  	SELF, (vir_bytes) dst_rs_start, sizeof(struct rs_start));

  return r;
}

/*===========================================================================*
 *				copy_label				     *
 *===========================================================================*/
int copy_label(src_e, src_label, src_len, dst_label, dst_len)
endpoint_t src_e;
char *src_label;
size_t src_len;
char *dst_label;
size_t dst_len;
{
  int s, len;

  len = MIN(dst_len-1, src_len);

  s = sys_datacopy(src_e, (vir_bytes) src_label,
	SELF, (vir_bytes) dst_label, len);
  if (s != OK) return s;

  dst_label[len] = 0;

  return OK;
}

/*===========================================================================*
 *			      init_state_data				     *
 *===========================================================================*/
int init_state_data(endpoint_t src_e, int prepare_state,
    struct rs_state_data *src_rs_state_data,
    struct rs_state_data *dst_rs_state_data)
{
    if (src_rs_state_data->size != sizeof(struct rs_state_data)) {
        return E2BIG;
    }

    memset(dst_rs_state_data, 0, sizeof(struct rs_state_data));

    if (prepare_state == SEF_LU_STATE_EVAL) {
        if (src_rs_state_data->eval_len == 0 || src_rs_state_data->eval_addr == NULL) {
            return EINVAL;
        }

        dst_rs_state_data->eval_addr = malloc(src_rs_state_data->eval_len + 1);
        if (dst_rs_state_data->eval_addr == NULL) {
            return ENOMEM;
        }

        int s = sys_datacopy(src_e, (vir_bytes) src_rs_state_data->eval_addr,
                             SELF, (vir_bytes) dst_rs_state_data->eval_addr,
                             src_rs_state_data->eval_len);
        if (s != OK) {
            free(dst_rs_state_data->eval_addr);
            return s;
        }

        ((char*)dst_rs_state_data->eval_addr)[src_rs_state_data->eval_len] = '\0';
        dst_rs_state_data->eval_len = src_rs_state_data->eval_len;
        dst_rs_state_data->size = src_rs_state_data->size;
    }

    if (src_rs_state_data->ipcf_els == NULL) {
        return OK;
    }

    if (src_rs_state_data->ipcf_els_size % sizeof(struct rs_ipc_filter_el) != 0) {
        return E2BIG;
    }

    int num_ipc_filters = src_rs_state_data->ipcf_els_size / sizeof(struct rs_ipc_filter_el);
    size_t buffer_size = sizeof(ipc_filter_el_t) * IPCF_MAX_ELEMENTS * num_ipc_filters;

    if (src_e == VM_PROC_NR) {
        buffer_size += sizeof(ipc_filter_el_t) * IPCF_MAX_ELEMENTS;
    }

    ipc_filter_el_t (*ipcf_els_buff)[IPCF_MAX_ELEMENTS] = malloc(buffer_size);
    if (ipcf_els_buff == NULL) {
        return ENOMEM;
    }

    memset(ipcf_els_buff, 0, buffer_size);

    struct rs_ipc_filter_el (*rs_ipc_filter_els)[IPCF_MAX_ELEMENTS] = src_rs_state_data->ipcf_els;
    struct rs_ipc_filter_el rs_ipc_filter[IPCF_MAX_ELEMENTS];

    for (int i = 0; i < num_ipc_filters; i++) {
        int s = sys_datacopy(src_e, (vir_bytes) rs_ipc_filter_els[i],
                             SELF, (vir_bytes) rs_ipc_filter, sizeof(rs_ipc_filter));
        if (s != OK) {
            free(ipcf_els_buff);
            return s;
        }

        for (int j = 0; j < IPCF_MAX_ELEMENTS; j++) {
            if (rs_ipc_filter[j].flags == 0) break;

            endpoint_t m_source = 0;
            int m_type = 0;

            if (rs_ipc_filter[j].flags & IPCF_MATCH_M_TYPE) {
                m_type = rs_ipc_filter[j].m_type;
            }
            if (rs_ipc_filter[j].flags & IPCF_MATCH_M_SOURCE) {
                if (ds_retrieve_label_endpt(rs_ipc_filter[j].m_label, &m_source) != OK) {
                    char *endptr;
                    m_source = strtol(rs_ipc_filter[j].m_label, &endptr, 10);
                    if (*endptr != '\0') {
                        if (!strcmp("ANY_USR", rs_ipc_filter[j].m_label)) {
                            m_source = ANY_USR;
                        } else if (!strcmp("ANY_SYS", rs_ipc_filter[j].m_label)) {
                            m_source = ANY_SYS;
                        } else if (!strcmp("ANY_TSK", rs_ipc_filter[j].m_label)) {
                            m_source = ANY_TSK;
                        } else {
                            free(ipcf_els_buff);
                            return ESRCH;
                        }
                    }
                }
            }

            ipcf_els_buff[i][j].flags = rs_ipc_filter[j].flags;
            ipcf_els_buff[i][j].m_source = m_source;
            ipcf_els_buff[i][j].m_type = m_type;
        }
    }

    if (src_e == VM_PROC_NR) {
        ipcf_els_buff[num_ipc_filters][0].flags = (IPCF_EL_WHITELIST | IPCF_MATCH_M_SOURCE | IPCF_MATCH_M_TYPE);
        ipcf_els_buff[num_ipc_filters][0].m_source = RS_PROC_NR;
        ipcf_els_buff[num_ipc_filters][0].m_type = VM_RS_UPDATE;
    }

    dst_rs_state_data->ipcf_els = ipcf_els_buff;
    dst_rs_state_data->ipcf_els_size = buffer_size;
    dst_rs_state_data->size = src_rs_state_data->size;

    return OK;
}

/*===========================================================================*
 *			        build_cmd_dep				     *
 *===========================================================================*/
void build_cmd_dep(struct rproc *rp) {
    struct rprocpub *rpub = rp->r_pub;
    int arg_count = 0;
    char *cmd_ptr;

    strncpy(rp->r_args, rp->r_cmd, sizeof(rp->r_args) - 1);
    rp->r_args[sizeof(rp->r_args) - 1] = '\0'; // Ensure null termination

    rp->r_argv[arg_count++] = rp->r_args;
    cmd_ptr = rp->r_args;

    while (*cmd_ptr != '\0') {
        if (*cmd_ptr == ' ') {
            *cmd_ptr = '\0';
            while (*++cmd_ptr == ' ') {}
            if (*cmd_ptr == '\0') break;

            if (arg_count >= ARGV_ELEMENTS - 1) {
                fprintf(stderr, "RS: build_cmd_dep: too many args\n");
                break;
            }
            rp->r_argv[arg_count++] = cmd_ptr;
        }
        cmd_ptr++;
    }

    rp->r_argv[arg_count] = NULL;
    rp->r_argc = arg_count;
}

/*===========================================================================*
 *				end_srv_init				     *
 *===========================================================================*/
void end_srv_init(struct rproc *rp) {
    if (!rp || !rp->r_pub) return;

    late_reply(rp, OK);

    if (rp->r_prev_rp) {
        if (SRV_IS_UPD_SCHEDULED(rp->r_prev_rp)) {
            rupdate_upd_move(rp->r_prev_rp, rp);
        }
        cleanup_service(rp->r_prev_rp);
        rp->r_prev_rp = NULL;
        rp->r_restarts++;

        if (rs_verbose) {
            printf("RS: %s completed restart\n", srv_to_string(rp));
        }
    }
    rp->r_next_rp = NULL;
}

/*===========================================================================*
 *			     kill_service_debug				     *
 *===========================================================================*/
#include <stdio.h>

int kill_service_debug(const char *file, int line, struct rproc *rp, const char *errstr, int err) {
    if (errstr != NULL && !shutting_down) {
        printf("RS: %s (error %d)\n", errstr, err);
    }
    if (rp == NULL) {
        return -1; // Error handling for null rp
    }
    rp->r_flags |= RS_EXITING;
    crash_service_debug(file, line, rp);
    return err;
}

/*===========================================================================*
 *			    crash_service_debug				     *
 *===========================================================================*/
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

int crash_service_debug(const char *file, int line, struct rproc *rp) {
    if (!file || !rp || !rp->r_pub) {
        return -1; // Error handling
    }

    struct rprocpub *rpub = rp->r_pub;

    if (rs_verbose) {
        printf("RS: %s %skilled at %s:%d\n", srv_to_string(rp),
               (rp->r_flags & RS_EXITING) ? "lethally " : "", file, line);
    }

    if (rpub->endpoint == RS_PROC_NR) {
        exit(1);
    }

    return sys_kill(rpub->endpoint, SIGKILL);
}

/*===========================================================================*
 *			  cleanup_service_debug				     *
 *===========================================================================*/
#include <stdio.h>
#include <signal.h>

void cleanup_service_debug(const char *file, int line, struct rproc *rp) {
  struct rprocpub *rpub = rp->r_pub;
  int cleanup_script = rp->r_flags & RS_CLEANUP_SCRIPT;
  int detach = rp->r_flags & RS_CLEANUP_DETACH;

  if (!(rp->r_flags & RS_DEAD)) {
    if (rs_verbose) {
      printf("RS: %s marked for cleanup at %s:%d\n", srv_to_string(rp), file, line);
    }

    /* Unlink service */
    if (rp->r_next_rp != NULL) { rp->r_next_rp->r_prev_rp = NULL; }
    rp->r_next_rp = NULL;
    
    if (rp->r_prev_rp != NULL) { rp->r_prev_rp->r_next_rp = NULL; }
    rp->r_prev_rp = NULL;
    
    if (rp->r_new_rp != NULL) { rp->r_new_rp->r_old_rp = NULL; }
    rp->r_new_rp = NULL;
    
    if (rp->r_old_rp != NULL) { rp->r_old_rp->r_new_rp = NULL; }
    rp->r_old_rp = NULL;
    
    rp->r_flags |= RS_DEAD;

    /* Prevent service from running further and clear IPC */
    sys_privctl(rpub->endpoint, SYS_PRIV_DISALLOW, NULL);
    sys_privctl(rpub->endpoint, SYS_PRIV_CLEAR_IPC_REFS, NULL);
    rp->r_flags &= ~RS_ACTIVE;

    /* Handle pending replies */
    late_reply(rp, OK);
    return;
  }

  /* Handle cleanup */
  if (!detach) {
    if (rs_verbose) {
      printf("RS: %s cleaned up at %s:%d\n", srv_to_string(rp), file, line);
    }

    int s;
    if ((s = sched_stop(rp->r_scheduler, rpub->endpoint)) != OK) {
      printf("RS: warning: scheduler won't give up process: %d\n", s);
    }

    if (rp->r_pid == -1) {
      printf("RS: warning: attempt to kill pid -1!\n");
    } else {
      srv_kill(rp->r_pid, SIGKILL);
    }
  }

  /* Run cleanup script if required */
  if (cleanup_script) {
    rp->r_flags &= ~RS_CLEANUP_SCRIPT;
    int s = run_script(rp);
    if (s != OK) {
      printf("RS: warning: cannot run cleanup script: %d\n", s);
    }
  }

  /* Detach or free slot */
  if (detach) {
    detach_service(rp);
  } else {
    if (!(rp->r_flags & RS_REINCARNATE)) {
      free_slot(rp);
    }
  }
}

/*===========================================================================*
 *			     detach_service_debug			     *
 *===========================================================================*/
#include <stdio.h>
#include <string.h>
#include <errno.h>

#define RS_MAX_LABEL_LEN 64
#define DSF_OVERWRITE 0
#define RS_IN_USE 0x01
#define RS_ACTIVE 0x02
#define SF_CORE_SRV 0x04
#define SF_DET_RESTART 0x08

struct rproc {
    struct rprocpub *r_pub;
    int r_flags;
    int r_period;
};

struct rprocpub {
    char label[RS_MAX_LABEL_LEN];
    int endpoint;
    int sys_flags;
    int dev_nr;
    int nr_domain;
};

void ds_publish_label(const char *label, int endpoint, int flags);
int sys_privctl(int endpoint, int command, void *arg);
int rs_verbose;
const char *srv_to_string(struct rproc *rp);

void detach_service_debug(const char *file, int line, struct rproc *rp) {
    static unsigned long detach_counter = 0;
    char label[RS_MAX_LABEL_LEN];
    struct rprocpub *rpub;

    if (!rp || !rp->r_pub) {
        fprintf(stderr, "Error: Invalid rproc structure\n");
        return;
    }

    rpub = rp->r_pub;

    strncpy(label, rpub->label, RS_MAX_LABEL_LEN - 1);
    label[RS_MAX_LABEL_LEN - 1] = '\0';
    int ret = snprintf(rpub->label, RS_MAX_LABEL_LEN, "%lu.%s", ++detach_counter, label);
    if (ret < 0 || ret >= RS_MAX_LABEL_LEN) {
        fprintf(stderr, "Error: Label creation failed\n");
        return;
    }

    ds_publish_label(rpub->label, rpub->endpoint, DSF_OVERWRITE);

    if (rs_verbose) {
        printf("RS: %s detached at %s:%d\n", srv_to_string(rp), file, line);
    }

    rp->r_flags = RS_IN_USE | RS_ACTIVE;
    rpub->sys_flags &= ~(SF_CORE_SRV | SF_DET_RESTART);
    rp->r_period = 0;
    rpub->dev_nr = 0;
    rpub->nr_domain = 0;

    if (sys_privctl(rpub->endpoint, SYS_PRIV_ALLOW, NULL) != 0) {
        fprintf(stderr, "Error: sys_privctl failed: %s\n", strerror(errno));
    }
}

/*===========================================================================*
 *				create_service				     *
 *===========================================================================*/
int create_service(struct rproc *rp) {
    int child_proc_nr_e, child_proc_nr_n;
    pid_t child_pid;
    int s;
    extern char **environ;
    struct rprocpub *rpub = rp->r_pub;

    int use_copy = (rpub->sys_flags & SF_USE_COPY);
    int has_replica = (rp->r_old_rp || (rp->r_prev_rp && !(rp->r_prev_rp->r_flags & RS_TERMINATED)));

    if ((!has_replica && (rpub->sys_flags & SF_NEED_REPL)) || 
        (!use_copy && ((rpub->sys_flags & SF_NEED_COPY) || !strcmp(rp->r_cmd, "")))) {
        printf("RS: unable to create service '%s'%s\n", rpub->label, 
               has_replica ? " without an in-memory copy" : " without a replica or command");
        free_slot(rp);
        return EPERM;
    }

    if (rs_verbose) printf("RS: forking child with srv_fork()...\n");
    child_pid = srv_fork(rp->r_uid, 0);
    if (child_pid < 0) {
        printf("RS: srv_fork() failed (error %d)\n", child_pid);
        free_slot(rp);
        return child_pid;
    }

    if ((s = getprocnr(child_pid, &child_proc_nr_e)) != 0) panic("unable to get child endpoint: %d", s);

    child_proc_nr_n = _ENDPOINT_P(child_proc_nr_e);
    rp->r_flags = RS_IN_USE;
    rpub->endpoint = child_proc_nr_e;
    rp->r_pid = child_pid;
    rp->r_check_tm = 0;
    rp->r_alive_tm = getticks();
    rp->r_stop_tm = 0;
    rp->r_backoff = 0;
    rproc_ptr[child_proc_nr_n] = rp;
    rpub->in_use = TRUE;

    if ((s = sys_privctl(child_proc_nr_e, SYS_PRIV_SET_SYS, &rp->r_priv)) != OK ||
        (s = sys_getpriv(&rp->r_priv, child_proc_nr_e)) != OK) {
        printf("RS: unable to set privilege structure: %d\n", s);
        cleanup_service(rp);
        vm_memctl(RS_PROC_NR, VM_RS_MEM_PIN, 0, 0);
        return ENOMEM;
    }

    if ((s = sched_init_proc(rp)) != OK) {
        printf("RS: unable to start scheduling: %d\n", s);
        cleanup_service(rp);
        vm_memctl(RS_PROC_NR, VM_RS_MEM_PIN, 0, 0);
        return s;
    }

    if (!use_copy && (s = read_exec(rp)) != OK) {
        printf("RS: read_exec failed: %d\n", s);
        cleanup_service(rp);
        vm_memctl(RS_PROC_NR, VM_RS_MEM_PIN, 0, 0);
        return s;
    }

    if (rs_verbose) printf("RS: execing child with srv_execve()...\n");
    s = srv_execve(child_proc_nr_e, rp->r_exec, rp->r_exec_len, rpub->proc_name, rp->r_argv, environ);
    vm_memctl(RS_PROC_NR, VM_RS_MEM_PIN, 0, 0);
    if (s != OK) {
        printf("RS: srv_execve failed: %d\n", s);
        cleanup_service(rp);
        return s;
    }
    if (!use_copy) free_exec(rp);

    setuid(0);

    if (rp->r_priv.s_flags & ROOT_SYS_PROC) {
        if (rs_verbose) printf("RS: pinning memory of RS instance %s\n", srv_to_string(rp));
        if ((s = vm_memctl(rpub->endpoint, VM_RS_MEM_PIN, 0, 0)) != OK) {
            printf("vm_memctl failed: %d\n", s);
            cleanup_service(rp);
            return s;
        }
    }

    if (rp->r_priv.s_flags & VM_SYS_PROC) {
        struct rproc *rs_rp;
        struct rproc **rs_rps;
        int i, nr_rs_rps;
        if (rs_verbose) printf("RS: informing VM of instance %s\n", srv_to_string(rp));
        if ((s = vm_memctl(rpub->endpoint, VM_RS_MEM_MAKE_VM, 0, 0)) != OK) {
            printf("vm_memctl failed: %d\n", s);
            cleanup_service(rp);
            return s;
        }
        rs_rp = rproc_ptr[_ENDPOINT_P(RS_PROC_NR)];
        get_service_instances(rs_rp, &rs_rps, &nr_rs_rps);
        for (i = 0; i < nr_rs_rps; i++) {
            vm_memctl(rs_rps[i]->r_pub->endpoint, VM_RS_MEM_PIN, 0, 0);
        }
    }

    if ((s = vm_set_priv(rpub->endpoint, &rpub->vm_call_mask[0], TRUE)) != OK) {
        printf("RS: vm_set_priv failed: %d\n", s);
        cleanup_service(rp);
        return s;
    }

    if (rs_verbose) printf("RS: %s created\n", srv_to_string(rp));

    return OK;
}

/*===========================================================================*
 *				clone_service				     *
 *===========================================================================*/
int clone_service(struct rproc *rp, int instance_flag, int init_flags) {
    struct rproc *replica_rp;
    struct rprocpub *replica_rpub;
    struct rproc **rp_link = NULL;
    struct rproc **replica_link = NULL;
    int r;

    if (rs_verbose) {
        printf("RS: %s creating a replica\n", srv_to_string(rp));
    }

    if (rp->r_pub->endpoint == VM_PROC_NR && instance_flag == LU_SYS_PROC && rp->r_next_rp) {
        cleanup_service_now(rp->r_next_rp);
        rp->r_next_rp = NULL;
    }

    r = clone_slot(rp, &replica_rp);
    if (r != OK) {
        return r;
    }
    replica_rpub = replica_rp->r_pub;

    if (instance_flag == LU_SYS_PROC) {
        rp_link = &rp->r_new_rp;
        replica_link = &replica_rp->r_old_rp;
    } else {
        rp_link = &rp->r_next_rp;
        replica_link = &replica_rp->r_prev_rp;
    }
    replica_rp->r_priv.s_flags |= instance_flag;
    replica_rp->r_priv.s_init_flags |= init_flags;

    *rp_link = replica_rp;
    *replica_link = rp;

    r = create_service(replica_rp);
    if (r != OK) {
        *rp_link = NULL;
        return r;
    }

    if ((replica_rp->r_priv.s_flags & (ROOT_SYS_PROC | RST_SYS_PROC)) == (ROOT_SYS_PROC | RST_SYS_PROC)) {
        struct rproc *rs_rp = rproc_ptr[_ENDPOINT_P(RS_PROC_NR)];

        r = update_sig_mgrs(rs_rp, SELF, replica_rpub->endpoint);
        if (r == OK) {
            r = update_sig_mgrs(replica_rp, SELF, NONE);
        }
        if (r != OK) {
            *rp_link = NULL;
            return kill_service(replica_rp, "update_sig_mgrs failed", r);
        }
    }

    return OK;
}

/*===========================================================================*
 *				publish_service				     *
 *===========================================================================*/
int publish_service(struct rproc *rp) {
  int r;
  struct rprocpub *rpub = rp->r_pub;
  struct rs_pci pci_acl;
  message m;
  endpoint_t ep;

  if ((r = ds_publish_label(rpub->label, rpub->endpoint, DSF_OVERWRITE)) != OK) 
      return kill_service(rp, "ds_publish_label call failed", r);

  if (rpub->dev_nr > 0 || rpub->nr_domain > 0) {
      setuid(0);

      if ((r = mapdriver(rpub->label, rpub->dev_nr, rpub->domain,
        rpub->nr_domain)) != OK) 
          return kill_service(rp, "couldn't map driver", r);
  }

#if USE_PCI
  if (rpub->pci_acl.rsp_nr_device || rpub->pci_acl.rsp_nr_class) {
      pci_acl = rpub->pci_acl;
      strncpy(pci_acl.rsp_label, rpub->label, sizeof(pci_acl.rsp_label) - 1);
      pci_acl.rsp_label[sizeof(pci_acl.rsp_label) - 1] = '\0';
      pci_acl.rsp_endpoint = rpub->endpoint;

      if ((r = pci_set_acl(&pci_acl)) != OK) 
          return kill_service(rp, "pci_set_acl call failed", r);
  }
#endif

  if (rpub->devman_id != 0) {
      if ((r = ds_retrieve_label_endpt("devman", &ep)) != OK) 
          return kill_service(rp, "devman not running?", r);

      m.m_type = DEVMAN_BIND;
      m.DEVMAN_ENDPOINT = rpub->endpoint;
      m.DEVMAN_DEVICE_ID = rpub->devman_id;

      if ((r = ipc_sendrec(ep, &m)) != OK || m.DEVMAN_RESULT != OK) 
          return kill_service(rp, "devman bind device failed", r);
  }

  if (rs_verbose)
      printf("RS: %s published\n", srv_to_string(rp));

  return OK;
}

/*===========================================================================*
 *			      unpublish_service				     *
 *===========================================================================*/
int unpublish_service(struct rproc *rp) {
    struct rprocpub *rpub = rp->r_pub;
    int result = OK;
    message m;
    endpoint_t ep;

    int r = ds_delete_label(rpub->label);
    if (r != OK && !shutting_down) {
        printf("RS: ds_delete_label call failed (error %d)\n", r);
        result = r;
    }

#if USE_PCI
    if (rpub->pci_acl.rsp_nr_device || rpub->pci_acl.rsp_nr_class) {
        r = pci_del_acl(rpub->endpoint);
        if (r != OK && !shutting_down) {
            printf("RS: pci_del_acl call failed (error %d)\n", r);
            result = r;
        }
    }
#endif

    if (rpub->devman_id != 0) {
        r = ds_retrieve_label_endpt("devman", &ep);

        if (r != OK) {
            printf("RS: devman not running?\n");
        } else {
            m.m_type = DEVMAN_UNBIND;
            m.DEVMAN_ENDPOINT = rpub->endpoint;
            m.DEVMAN_DEVICE_ID = rpub->devman_id;
            r = ipc_sendrec(ep, &m);

            if (r != OK || m.DEVMAN_RESULT != OK) {
                printf("RS: devman unbind device failed\n");
            }
        }
    }

    if (rs_verbose) {
        printf("RS: %s unpublished\n", srv_to_string(rp));
    }

    return result;
}

/*===========================================================================*
 *				run_service				     *
 *===========================================================================*/
int run_service(struct rproc *rp, int init_type, int init_flags) {
    struct rprocpub *rpub = rp->r_pub;
    int s;

    s = sys_privctl(rpub->endpoint, SYS_PRIV_ALLOW, NULL);
    if (s != OK) {
        return kill_service(rp, "unable to allow the service to run", s);
    }

    s = init_service(rp, init_type, init_flags);
    if (s != OK) {
        return kill_service(rp, "unable to initialize service", s);
    }

    if (rs_verbose) {
        printf("RS: %s allowed to run\n", srv_to_string(rp));
    }

    return OK;
}

/*===========================================================================*
 *				start_service				     *
 *===========================================================================*/
int start_service(struct rproc *rp, int init_flags) {
    int result;
    
    rp->r_priv.s_init_flags |= init_flags;

    if ((result = create_service(rp)) != OK) {
        return result;
    }

    activate_service(rp, NULL);

    if ((result = publish_service(rp)) != OK) {
        return result;
    }

    if ((result = run_service(rp, SEF_INIT_FRESH, init_flags)) != OK) {
        return result;
    }

    if (rs_verbose) {
        printf("RS: %s started with major %d\n", srv_to_string(rp), rp->r_pub->dev_nr);
    }

    return OK;
}

/*===========================================================================*
 *				stop_service				     *
 *===========================================================================*/
#include <stdio.h>
#include <signal.h>
#include <time.h>

#define RS_PROC_NR 1
#define SIGTERM 15
#define SIGHUP 1

struct rprocpub {
    int endpoint;
};

struct rproc {
    struct rprocpub *r_pub;
    int r_flags;
    clock_t r_stop_tm;
};

int sys_kill(int endpoint, int signo);
int getticks();
int rs_verbose;
const char* srv_to_string(struct rproc *rp);

void stop_service(struct rproc *rp, int how) {
    if (!rp || !rp->r_pub) {
        return; // Handle potential null pointers
    }
    
    struct rprocpub *rpub = rp->r_pub;
    int signo = (rpub->endpoint != RS_PROC_NR) ? SIGTERM : SIGHUP;

    if(rs_verbose) {
        printf("RS: %s signaled with %s\n", srv_to_string(rp), (signo == SIGTERM) ? "SIGTERM" : "SIGHUP");
    }
    
    rp->r_flags |= how;
    if (sys_kill(rpub->endpoint, signo) != 0) {
        perror("sys_kill failed");
        return;
    }
    
    rp->r_stop_tm = getticks();
}

/*===========================================================================*
 *			      activate_service				     *
 *===========================================================================*/
void activate_service(struct rproc *rp, struct rproc *ex_rp) {
    if (ex_rp && (ex_rp->r_flags & RS_ACTIVE)) {
        ex_rp->r_flags &= ~RS_ACTIVE;
        if (rs_verbose) {
            printf("RS: %s becomes inactive\n", srv_to_string(ex_rp));
        }
    }

    if (!(rp->r_flags & RS_ACTIVE)) {
        rp->r_flags |= RS_ACTIVE;
        if (rs_verbose) {
            printf("RS: %s becomes active\n", srv_to_string(rp));
        }
    }
}

/*===========================================================================*
 *			      reincarnate_service			     *
 *===========================================================================*/
void reincarnate_service(struct rproc *old_rp) {
    struct rproc *rp;
    int restarts;

    if (clone_slot(old_rp, &rp) != OK) {
        fprintf(stderr, "RS: Failed to clone the slot\n");
        return;
    }

    rp->r_flags = RS_IN_USE;
    int endpoint_index = _ENDPOINT_P(rp->r_pub->endpoint);
    if (endpoint_index >= 0 && endpoint_index < MAX_RPROCS) {
        rproc_ptr[endpoint_index] = NULL;
    }

    restarts = rp->r_restarts;
    if (start_service(rp, SEF_INIT_FRESH) != OK) {
        fprintf(stderr, "RS: Failed to start service\n");
    } else {
        rp->r_restarts = restarts + 1;
    }
}

/*===========================================================================*
 *			      terminate_service				     *
 *===========================================================================*/
void terminate_service(struct rproc *rp) {
    struct rproc **rps;
    struct rprocpub *rpub = rp->r_pub;
    int nr_rps, norestart, i, r;

    if (rs_verbose) {
        printf("RS: %s terminated\n", srv_to_string(rp));
    }

    if (rp->r_flags & RS_INITIALIZING) {
        if (SRV_IS_UPDATING(rp)) {
            printf("RS: update failed: state transfer failed. Rolling back...\n");
            end_update(rp->r_init_err, RS_REPLY);
            rp->r_init_err = ERESTART;
            return;
        }

        if (rpub->sys_flags & SF_NO_BIN_EXP) {
            if (rs_verbose) {
                printf("RS: service '%s' exited during initialization; refreshing\n", rpub->label);
            }
            rp->r_flags |= RS_REFRESHING;
        } else {
            if (rs_verbose) {
                printf("RS: service '%s' exited during initialization; exiting\n", rpub->label);
            }
            rp->r_flags |= RS_EXITING;
        }
    }

    if (RUPDATE_IS_UPDATING()) {
        printf("RS: aborting the update after a crash...\n");
        abort_update_proc(ERESTART);
    }

    norestart = !(rp->r_flags & RS_EXITING) && (rp->r_pub->sys_flags & SF_NORESTART);
    if (norestart) {
        rp->r_flags |= RS_EXITING;
        if ((rp->r_pub->sys_flags & SF_DET_RESTART) && (rp->r_restarts < MAX_DET_RESTART)) {
            rp->r_flags |= RS_CLEANUP_DETACH;
        }
        if (rp->r_script[0] != '\0') {
            rp->r_flags |= RS_CLEANUP_SCRIPT;
        }
    }

    if (rp->r_flags & RS_EXITING) {
        if ((rp->r_pub->sys_flags & SF_CORE_SRV) && !shutting_down) {
            printf("core system service died: %s\n", srv_to_string(rp));
            _exit(1);
        }

        if (SRV_IS_UPD_SCHEDULED(rp)) {
            printf("RS: aborting the scheduled update, one of the services part of it is exiting...\n");
            abort_update_proc(EDEADSRCDST);
        }

        r = (rp->r_caller_request == RS_DOWN || (rp->r_caller_request == RS_REFRESH && norestart)) ? OK : EDEADEPT;
        late_reply(rp, r);
        unpublish_service(rp);

        get_service_instances(rp, &rps, &nr_rps);
        for (i = 0; i < nr_rps; i++) {
            cleanup_service(rps[i]);
        }

        if (rp->r_flags & RS_REINCARNATE) {
            rp->r_flags &= ~RS_REINCARNATE;
            reincarnate_service(rp);
        }
    } else if (rp->r_flags & RS_REFRESHING) {
        restart_service(rp);
    } else {
        if (rp->r_restarts > 0) {
            if (!(rpub->sys_flags & SF_NO_BIN_EXP)) {
                rp->r_backoff = 1 << MIN(rp->r_restarts, (BACKOFF_BITS - 2));
                rp->r_backoff = MIN(rp->r_backoff, MAX_BACKOFF);
                if ((rpub->sys_flags & SF_USE_COPY) && rp->r_backoff > 1) {
                    rp->r_backoff = 1;
                }
            } else {
                rp->r_backoff = 1;
            }
            return;
        }
        restart_service(rp);
    }
}

/*===========================================================================*
 *				run_script				     *
 *===========================================================================*/
static int run_script(struct rproc *rp) {
    pid_t pid;
    char *reason;
    char incarnation_str[20];
    char *envp[1] = { NULL };
    struct rprocpub *rpub = rp->r_pub;
    int ret_code;

    reason = (rp->r_flags & RS_REFRESHING) ? "restart" :
             (rp->r_flags & RS_NOPINGREPLY) ? "no-heartbeat" : "terminated";
    snprintf(incarnation_str, sizeof(incarnation_str), "%d", rp->r_restarts);

    if (rs_verbose) {
        printf("RS: %s:\n", srv_to_string(rp));
        printf("RS:     calling script '%s'\n", rp->r_script);
        printf("RS:     reason: '%s'\n", reason);
        printf("RS:     incarnation: '%s'\n", incarnation_str);
    }

    pid = fork();
    if (pid == -1) {
        return errno;
    } else if (pid == 0) {
        execle(_PATH_BSHELL, "sh", rp->r_script, rpub->label, reason,
               incarnation_str, (char *)NULL, envp);
        fprintf(stderr, "RS: run_script: execl '%s' failed: %s\n",
                rp->r_script, strerror(errno));
        _exit(1);
    } else {
        ret_code = configure_script_privileges(pid, rp);
        if (ret_code != OK) return ret_code;
        vm_memctl(RS_PROC_NR, VM_RS_MEM_PIN, 0, 0);
    }
    return OK;
}

static int configure_script_privileges(pid_t pid, struct rproc *rp) {
    int r, endpoint;

    if ((r = getprocnr(pid, &endpoint)) != 0) {
        panic("unable to get child endpoint: %d", r);
        return r; // would never reach since panic() usually doesn't return, but placed for completeness 
    }

    if ((r = sys_privctl(endpoint, SYS_PRIV_SET_USER, NULL)) != OK) {
        return kill_service(rp, "can't set script privileges", r);
    }

    if ((r = vm_set_priv(endpoint, NULL, FALSE)) != OK) {
        return kill_service(rp, "can't set script VM privs", r);
    }

    if ((r = sys_privctl(endpoint, SYS_PRIV_ALLOW, NULL)) != OK) {
        return kill_service(rp, "can't let the script run", r);
    }

    return OK;
}

/*===========================================================================*
 *			      restart_service				     *
 *===========================================================================*/
void restart_service(struct rproc *rp) {
    struct rproc *replica_rp;
    int result;

    late_reply(rp, OK);

    if (rp->r_script[0] != '\0') {
        result = run_script(rp);
        if (result != OK) {
            kill_service(rp, "unable to run script", errno);
            return;
        }
    } else {
        replica_rp = rp->r_next_rp;
        if (replica_rp == NULL) {
            result = clone_service(rp, RST_SYS_PROC, 0);
            if (result != OK) {
                kill_service(rp, "unable to clone service", result);
                return;
            }
            replica_rp = rp->r_next_rp;
        }

        result = update_service(&rp, &replica_rp, RS_SWAP, 0);
        if (result != OK) {
            kill_service(rp, "unable to update into new replica", result);
            return;
        }

        result = run_service(replica_rp, SEF_INIT_RESTART, 0);
        if (result != OK) {
            kill_service(rp, "unable to let the replica run", result);
            return;
        }
    }

    if ((rp->r_pub->sys_flags & SF_DET_RESTART) && (rp->r_restarts < MAX_DET_RESTART)) {
        rp->r_flags |= RS_CLEANUP_DETACH;
    }

    if (rs_verbose) {
        printf("RS: %s restarted into %s\n", srv_to_string(rp), srv_to_string(replica_rp));
    }
}

/*===========================================================================*
 *		         inherit_service_defaults			     *
 *===========================================================================*/
void inherit_service_defaults(struct rproc *def_rp, struct rproc *rp) {
    struct rprocpub *def_rpub = def_rp->r_pub;
    struct rprocpub *rpub = rp->r_pub;

    rpub->dev_nr = def_rpub->dev_nr;
    rpub->nr_domain = def_rpub->nr_domain;
    
    memcpy(rpub->domain, def_rpub->domain, sizeof(int) * def_rpub->nr_domain);

    rpub->pci_acl = def_rpub->pci_acl;

    rpub->sys_flags = (rpub->sys_flags & ~IMM_SF) | (def_rpub->sys_flags & IMM_SF);
    
    rp->r_priv.s_flags = (rp->r_priv.s_flags & ~IMM_F) | (def_rp->r_priv.s_flags & IMM_F);

    rp->r_priv.s_trap_mask = def_rp->r_priv.s_trap_mask;
}

/*===========================================================================*
 *		           get_service_instances			     *
 *===========================================================================*/
#include <stddef.h>

#define MAX_INSTANCES 5

void get_service_instances(struct rproc *rp, struct rproc ***rps, int *length) {
    static struct rproc *instances[MAX_INSTANCES];
    int nr_instances = 0;

    if (rp != NULL) {
        instances[nr_instances++] = rp;
        if (rp->r_prev_rp != NULL && nr_instances < MAX_INSTANCES) instances[nr_instances++] = rp->r_prev_rp;
        if (rp->r_next_rp != NULL && nr_instances < MAX_INSTANCES) instances[nr_instances++] = rp->r_next_rp;
        if (rp->r_old_rp != NULL && nr_instances < MAX_INSTANCES) instances[nr_instances++] = rp->r_old_rp;
        if (rp->r_new_rp != NULL && nr_instances < MAX_INSTANCES) instances[nr_instances++] = rp->r_new_rp;
    }

    *rps = instances;
    *length = nr_instances;
}

/*===========================================================================*
 *				share_exec				     *
 *===========================================================================*/
#include <stdio.h>

void share_exec(struct rproc *rp_dst, struct rproc *rp_src) {
    if (rs_verbose) {
        printf("RS: %s shares exec image with %s\n", srv_to_string(rp_dst), srv_to_string(rp_src));
    }

    if (!rp_dst || !rp_src) {
        fprintf(stderr, "Error: NULL pointer encountered.\n");
        return;
    }

    rp_dst->r_exec_len = rp_src->r_exec_len;
    rp_dst->r_exec = rp_src->r_exec;
}

/*===========================================================================*
 *				read_exec				     *
 *===========================================================================*/
int read_exec(struct rproc *rp) {
    if (!rp || !rp->r_argv || !rp->r_pub || !rp->r_pub->label) {
        return EINVAL;
    }

    int fd;
    const char *e_name = rp->r_argv[0];
    struct stat sb;

    if (rs_verbose) {
        printf("RS: service '%s' reads exec image from: %s\n", rp->r_pub->label, e_name);
    }

    if (stat(e_name, &sb) != 0) {
        return -errno;
    }

    if (sb.st_size < sizeof(Elf_Ehdr)) {
        return ENOEXEC;
    }

    fd = open(e_name, O_RDONLY);
    if (fd == -1) {
        return -errno;
    }

    rp->r_exec_len = sb.st_size;
    rp->r_exec = malloc(rp->r_exec_len);
    if (rp->r_exec == NULL) {
        printf("RS: read_exec: unable to allocate %zu bytes\n", rp->r_exec_len);
        close(fd);
        return ENOMEM;
    }

    ssize_t bytesRead = read(fd, rp->r_exec, rp->r_exec_len);
    int read_errno = errno;
    close(fd);

    if (bytesRead == rp->r_exec_len) {
        return OK;
    }

    printf("RS: read_exec: read failed %zd, errno %d\n", bytesRead, read_errno);
    free_exec(rp);

    return (bytesRead >= 0) ? EIO : -read_errno;
}

/*===========================================================================*
 *				free_exec				     *
 *===========================================================================*/
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#define NR_SYS_PROCS 256

struct rproc {
    int r_flags;
    void *r_exec;
    size_t r_exec_len;
};

#define RS_IN_USE 0x1
bool rs_verbose = true;

const char *srv_to_string(struct rproc *rp);

void free_exec(struct rproc *rp) {
    bool has_shared_exec = false;
    struct rproc *other_rp = NULL;

    for (int slot_nr = 0; slot_nr < NR_SYS_PROCS; slot_nr++) {
        other_rp = &rproc[slot_nr];
        if ((other_rp->r_flags & RS_IN_USE) && other_rp != rp && other_rp->r_exec == rp->r_exec) {
            has_shared_exec = true;
            break;
        }
    }

    if (!has_shared_exec) {
        if (rs_verbose) {
            printf("RS: %s frees exec image\n", srv_to_string(rp));
        }
        free(rp->r_exec);
    } else {
        if (rs_verbose) {
            printf("RS: %s no longer sharing exec image with %s\n", srv_to_string(rp), srv_to_string(other_rp));
        }
    }
    rp->r_exec = NULL;
    rp->r_exec_len = 0;
}

/*===========================================================================*
 *				 edit_slot				     *
 *===========================================================================*/
int edit_slot(rp, rs_start, source)
struct rproc *rp;
struct rs_start *rs_start;
endpoint_t source;
{
/* Edit a given slot to override existing settings. */
  struct rprocpub *rpub;
  char *label;
  int len;
  int s, i;
  int basic_kc[] =  { SYS_BASIC_CALLS, NULL_C };
  int basic_vmc[] =  { VM_BASIC_CALLS, NULL_C };

  rpub = rp->r_pub;

  /* Update IPC target list. */
  if (rs_start->rss_ipclen==0 || rs_start->rss_ipclen+1>sizeof(rp->r_ipc_list)){
      printf("RS: edit_slot: ipc list empty or long for '%s'\n", rpub->label);
      return EINVAL;
  }
  s=sys_datacopy(source, (vir_bytes) rs_start->rss_ipc, 
      SELF, (vir_bytes) rp->r_ipc_list, rs_start->rss_ipclen);
  if (s != OK) return(s);
  rp->r_ipc_list[rs_start->rss_ipclen]= '\0';

  /* Update IRQs. */
  if(rs_start->rss_nr_irq == RSS_IRQ_ALL) {
      rs_start->rss_nr_irq = 0;
  }
  else {
      rp->r_priv.s_flags |= CHECK_IRQ;
  }
  if (rs_start->rss_nr_irq > NR_IRQ) {
      printf("RS: edit_slot: too many IRQs requested\n");
      return EINVAL;
  }
  rp->r_nr_irq= rp->r_priv.s_nr_irq= rs_start->rss_nr_irq;
  for (i= 0; i<rp->r_priv.s_nr_irq; i++) {
      rp->r_irq_tab[i]= rp->r_priv.s_irq_tab[i]= rs_start->rss_irq[i];
      if(rs_verbose)
          printf("RS: edit_slot: IRQ %d\n", rp->r_priv.s_irq_tab[i]);
  }

  /* Update I/O ranges. */
  if(rs_start->rss_nr_io == RSS_IO_ALL) {
      rs_start->rss_nr_io = 0;
  }
  else {
      rp->r_priv.s_flags |= CHECK_IO_PORT;
  }
  if (rs_start->rss_nr_io > NR_IO_RANGE) {
      printf("RS: edit_slot: too many I/O ranges requested\n");
      return EINVAL;
  }
  rp->r_nr_io_range= rp->r_priv.s_nr_io_range= rs_start->rss_nr_io;
  for (i= 0; i<rp->r_priv.s_nr_io_range; i++) {
      rp->r_priv.s_io_tab[i].ior_base= rs_start->rss_io[i].base;
      rp->r_priv.s_io_tab[i].ior_limit=
          rs_start->rss_io[i].base+rs_start->rss_io[i].len-1;
      rp->r_io_tab[i] = rp->r_priv.s_io_tab[i];
      if(rs_verbose)
          printf("RS: edit_slot: I/O [%x..%x]\n",
              rp->r_priv.s_io_tab[i].ior_base,
              rp->r_priv.s_io_tab[i].ior_limit);
  }

  /* Update kernel call mask. Inherit basic kernel calls when asked to. */
  memcpy(rp->r_priv.s_k_call_mask, rs_start->rss_system,
      sizeof(rp->r_priv.s_k_call_mask));
  if(rs_start->rss_flags & RSS_SYS_BASIC_CALLS) {
      fill_call_mask(basic_kc, NR_SYS_CALLS,
          rp->r_priv.s_k_call_mask, KERNEL_CALL, FALSE);
  }

  /* Update VM call mask. Inherit basic VM calls. */
  memcpy(rpub->vm_call_mask, rs_start->rss_vm,
      sizeof(rpub->vm_call_mask));
  if(rs_start->rss_flags & RSS_VM_BASIC_CALLS) {
      fill_call_mask(basic_vmc, NR_VM_CALLS,
          rpub->vm_call_mask, VM_RQ_BASE, FALSE);
  }

  /* Update control labels. */
  if(rs_start->rss_nr_control > 0) {
      int i, s;
      if (rs_start->rss_nr_control > RS_NR_CONTROL) {
          printf("RS: edit_slot: too many control labels\n");
          return EINVAL;
      }
      for (i=0; i<rs_start->rss_nr_control; i++) {
          s = copy_label(source, rs_start->rss_control[i].l_addr,
              rs_start->rss_control[i].l_len, rp->r_control[i],
              sizeof(rp->r_control[i]));
          if(s != OK)
              return s;
      }
      rp->r_nr_control = rs_start->rss_nr_control;

      if (rs_verbose) {
          printf("RS: edit_slot: control labels:");
          for (i=0; i<rp->r_nr_control; i++)
              printf(" %s", rp->r_control[i]);
          printf("\n");
      }
  }

  /* Update signal manager. */
  rp->r_priv.s_sig_mgr = rs_start->rss_sigmgr;

  /* Update scheduling properties if possible. */
  if(rp->r_scheduler != NONE) {
      rp->r_scheduler = rs_start->rss_scheduler;
      rp->r_priority = rs_start->rss_priority;
      rp->r_quantum = rs_start->rss_quantum;
      rp->r_cpu = rs_start->rss_cpu;
  }

  /* Update command and arguments. */
  if (rs_start->rss_cmdlen > MAX_COMMAND_LEN-1) return(E2BIG);
  s=sys_datacopy(source, (vir_bytes) rs_start->rss_cmd, 
      SELF, (vir_bytes) rp->r_cmd, rs_start->rss_cmdlen);
  if (s != OK) return(s);
  rp->r_cmd[rs_start->rss_cmdlen] = '\0';	/* ensure it is terminated */
  if (rp->r_cmd[0] != '/') return(EINVAL);	/* insist on absolute path */

  /* Build cmd dependencies (argv). */
  build_cmd_dep(rp);

  /* Copy in the program name. */
  if (rs_start->rss_prognamelen > sizeof(rpub->proc_name)-1) return(E2BIG);
  s=sys_datacopy(source, (vir_bytes) rs_start->rss_progname, 
      SELF, (vir_bytes) rpub->proc_name, rs_start->rss_prognamelen);
  if (s != OK) return(s);
  rpub->proc_name[rs_start->rss_prognamelen] = '\0';

  /* Update label if not already set. */
  if(!strcmp(rpub->label, "")) {
      if(rs_start->rss_label.l_len > 0) {
          /* RS_UP caller has supplied a custom label for this service. */
          int s = copy_label(source, rs_start->rss_label.l_addr,
              rs_start->rss_label.l_len, rpub->label, sizeof(rpub->label));
          if(s != OK)
              return s;
          if(rs_verbose)
              printf("RS: edit_slot: using label (custom) '%s'\n", rpub->label);
      } else {
          /* Default label for the service. */
          label = rpub->proc_name;
          len= strlen(label);
          memcpy(rpub->label, label, len);
          rpub->label[len]= '\0';
          if(rs_verbose)
              printf("RS: edit_slot: using label (from proc_name) '%s'\n",
                  rpub->label);
      }
  }

  /* Update recovery script. */
  if (rs_start->rss_scriptlen > MAX_SCRIPT_LEN-1) return(E2BIG);
  if (rs_start->rss_script != NULL && rs_start->rss_scriptlen > 0
      && !(rpub->sys_flags & SF_CORE_SRV)) {
      s=sys_datacopy(source, (vir_bytes) rs_start->rss_script, 
          SELF, (vir_bytes) rp->r_script, rs_start->rss_scriptlen);
      if (s != OK) return(s);
      rp->r_script[rs_start->rss_scriptlen] = '\0';
      rpub->sys_flags |= SF_USE_SCRIPT;
  }

  /* Update system flags and in-memory copy. */
  if ((rs_start->rss_flags & RSS_COPY) && !(rpub->sys_flags & SF_USE_COPY)) {
      int exst_cpy;
      struct rproc *rp2;
      struct rprocpub *rpub2;
      exst_cpy = 0;

      if(rs_start->rss_flags & RSS_REUSE) {
          int i;

          for(i = 0; i < NR_SYS_PROCS; i++) {
              rp2 = &rproc[i];
              rpub2 = rproc[i].r_pub;
              if(strcmp(rpub->proc_name, rpub2->proc_name) == 0 &&
                  (rpub2->sys_flags & SF_USE_COPY)) {
                  /* We have found the same binary that's
                   * already been copied */
                  exst_cpy = 1;
                  break;
              }
          }
      }                

      s = OK;
      if(!exst_cpy)
          s = read_exec(rp);
      else
          share_exec(rp, rp2);

      if (s != OK)
          return s;

      rpub->sys_flags |= SF_USE_COPY;
  }
  if (rs_start->rss_flags & RSS_REPLICA) {
      rpub->sys_flags |= SF_USE_REPL;
  }
  if (rs_start->rss_flags & RSS_NO_BIN_EXP) {
      rpub->sys_flags |= SF_NO_BIN_EXP;
  }
  if (rs_start->rss_flags & RSS_DETACH) {
      rpub->sys_flags |= SF_DET_RESTART;
  }
  else {
      rpub->sys_flags &= ~SF_DET_RESTART;
  }
  if (rs_start->rss_flags & RSS_NORESTART) {
      if(rpub->sys_flags & SF_CORE_SRV) {
          return EPERM;
      }
      rpub->sys_flags |= SF_NORESTART;
  }
  else {
      rpub->sys_flags &= ~SF_NORESTART;
  }

  /* Update period. */
  if(rpub->endpoint != RS_PROC_NR) {
      rp->r_period = rs_start->rss_period;
  }

  /* Update restarts. */
  if(rs_start->rss_restarts) {
      rp->r_restarts = rs_start->rss_restarts;
  }

  /* Update number of ASR live updates. */
  if(rs_start->rss_asr_count >= 0) {
      rp->r_asr_count = rs_start->rss_asr_count;
  }

  /* (Re)initialize privilege settings. */
  init_privs(rp, &rp->r_priv);

  return OK;
}

/*===========================================================================*
 *				 init_slot				     *
 *===========================================================================*/
int init_slot(rp, rs_start, source)
struct rproc *rp;
struct rs_start *rs_start;
endpoint_t source;
{
/* Initialize a slot as requested by the client. */
  struct rprocpub *rpub;
  int i;

  rpub = rp->r_pub;

  /* All dynamically created services get the same sys and privilege flags, and
   * allowed traps. Other privilege settings can be specified at runtime. The
   * privilege id is dynamically allocated by the kernel.
   */
  rpub->sys_flags = DSRV_SF;             /* system flags */
  rp->r_priv.s_flags = DSRV_F;           /* privilege flags */
  rp->r_priv.s_init_flags = DSRV_I;      /* init flags */
  rp->r_priv.s_trap_mask = DSRV_T;       /* allowed traps */
  rp->r_priv.s_bak_sig_mgr = NONE;       /* backup signal manager */

  /* Initialize uid. */
  rp->r_uid= rs_start->rss_uid;

  /* Initialize device driver settings. */
  if (rs_start->rss_nr_domain < 0 || rs_start->rss_nr_domain > NR_DOMAIN) {
      printf("RS: init_slot: too many domains\n");
      return EINVAL;
  }

  rpub->dev_nr = rs_start->rss_major;
  rpub->nr_domain = rs_start->rss_nr_domain;
  for (i = 0; i < rs_start->rss_nr_domain; i++)
	rpub->domain[i] = rs_start->rss_domain[i];
  rpub->devman_id = rs_start->devman_id;

  /* Initialize pci settings. */
  if (rs_start->rss_nr_pci_id > RS_NR_PCI_DEVICE) {
      printf("RS: init_slot: too many PCI device IDs\n");
      return EINVAL;
  }
  rpub->pci_acl.rsp_nr_device = rs_start->rss_nr_pci_id;
  for (i= 0; i<rpub->pci_acl.rsp_nr_device; i++) {
      rpub->pci_acl.rsp_device[i].vid= rs_start->rss_pci_id[i].vid;
      rpub->pci_acl.rsp_device[i].did= rs_start->rss_pci_id[i].did;
      rpub->pci_acl.rsp_device[i].sub_vid= rs_start->rss_pci_id[i].sub_vid;
      rpub->pci_acl.rsp_device[i].sub_did= rs_start->rss_pci_id[i].sub_did;
      if(rs_verbose)
          printf("RS: init_slot: PCI %04x/%04x (sub %04x:%04x)\n",
              rpub->pci_acl.rsp_device[i].vid,
              rpub->pci_acl.rsp_device[i].did,
              rpub->pci_acl.rsp_device[i].sub_vid,
              rpub->pci_acl.rsp_device[i].sub_did);
  }
  if (rs_start->rss_nr_pci_class > RS_NR_PCI_CLASS) {
      printf("RS: init_slot: too many PCI class IDs\n");
      return EINVAL;
  }
  rpub->pci_acl.rsp_nr_class= rs_start->rss_nr_pci_class;
  for (i= 0; i<rpub->pci_acl.rsp_nr_class; i++) {
      rpub->pci_acl.rsp_class[i].pciclass=rs_start->rss_pci_class[i].pciclass;
      rpub->pci_acl.rsp_class[i].mask= rs_start->rss_pci_class[i].mask;
      if(rs_verbose)
          printf("RS: init_slot: PCI class %06x mask %06x\n",
              (unsigned int) rpub->pci_acl.rsp_class[i].pciclass,
              (unsigned int) rpub->pci_acl.rsp_class[i].mask);
  }
  
  /* Initialize some fields. */
  rp->r_asr_count = 0;				/* no ASR updates yet */
  rp->r_restarts = 0; 				/* no restarts yet */
  rp->r_old_rp = NULL;			        /* no old version yet */
  rp->r_new_rp = NULL;			        /* no new version yet */
  rp->r_prev_rp = NULL;			        /* no prev replica yet */
  rp->r_next_rp = NULL;			        /* no next replica yet */
  rp->r_exec = NULL;                            /* no in-memory copy yet */
  rp->r_exec_len = 0;
  rp->r_script[0]= '\0';                        /* no recovery script yet */
  rpub->label[0]= '\0';                         /* no label yet */
  rp->r_scheduler = -1;                         /* no scheduler yet */
  rp->r_priv.s_sig_mgr = -1;                    /* no signal manager yet */
  rp->r_map_prealloc_addr = 0;                  /* no preallocated memory */
  rp->r_map_prealloc_len = 0;
  rp->r_init_err = ERESTART;                    /* default init error `*/

  /* Initialize editable slot settings. */
  return edit_slot(rp, rs_start, source);
}

/*===========================================================================*
 *				clone_slot				     *
 *===========================================================================*/
int clone_slot(struct rproc *rp, struct rproc **clone_rpp) {
    int r;
    struct rproc *clone_rp;
    struct rprocpub *rpub, *clone_rpub;

    r = alloc_slot(&clone_rp);
    if (r != OK) {
        fprintf(stderr, "RS: clone_slot: unable to allocate a new slot: %d\n", r);
        return r;
    }

    rpub = rp->r_pub;
    clone_rpub = clone_rp->r_pub;

    if ((r = sys_getpriv(&(rp->r_priv), rpub->endpoint)) != OK) {
        fprintf(stderr, "unable to sync privilege structure: %d\n", r);
        return r;
    }

    *clone_rp = *rp;
    *clone_rpub = *rpub;

    clone_rp->r_init_err = ERESTART;
    clone_rp->r_flags &= ~RS_ACTIVE;
    clone_rp->r_pid = -1;
    clone_rpub->endpoint = -1;
    clone_rp->r_pub = clone_rpub;
    build_cmd_dep(clone_rp);

    if (clone_rpub->sys_flags & SF_USE_COPY) {
        share_exec(clone_rp, rp);
    }

    clone_rp->r_old_rp = NULL;
    clone_rp->r_new_rp = NULL;
    clone_rp->r_prev_rp = NULL;
    clone_rp->r_next_rp = NULL;

    clone_rp->r_priv.s_flags |= DYN_PRIV_ID;
    clone_rp->r_priv.s_flags &= ~(LU_SYS_PROC | RST_SYS_PROC);
    clone_rp->r_priv.s_init_flags = 0;

    *clone_rpp = clone_rp;
    return OK;
}

/*===========================================================================*
 *			    swap_slot_pointer				     *
 *===========================================================================*/
static void swap_slot_pointer(struct rproc **rpp, struct rproc *src_rp, struct rproc *dst_rp) {
    if (rpp == NULL || *rpp == NULL) return;
    if (*rpp == src_rp) {
        *rpp = dst_rp;
    } else if (*rpp == dst_rp) {
        *rpp = src_rp;
    }
}

/*===========================================================================*
 *				swap_slot				     *
 *===========================================================================*/
void swap_slot(struct rproc **src_rpp, struct rproc **dst_rpp) {
    if (!src_rpp || !dst_rpp || !*src_rpp || !*dst_rpp) {
        return;
    }

    struct rproc *src_rp = *src_rpp;
    struct rproc *dst_rp = *dst_rpp;
    struct rprocpub *src_rpub = src_rp->r_pub;
    struct rprocpub *dst_rpub = dst_rp->r_pub;
    
    struct rproc orig_src_rproc = *src_rp;
    struct rprocpub orig_src_rprocpub = *src_rpub;
    struct rproc orig_dst_rproc = *dst_rp;
    struct rprocpub orig_dst_rprocpub = *dst_rpub;
    
    *src_rp = orig_dst_rproc;
    *src_rpub = orig_dst_rprocpub;
    *dst_rp = orig_src_rproc;
    *dst_rpub = orig_src_rprocpub;
    
    src_rp->r_pub = orig_src_rproc.r_pub;
    dst_rp->r_pub = orig_dst_rproc.r_pub;
    src_rp->r_upd = orig_src_rproc.r_upd;
    dst_rp->r_upd = orig_dst_rproc.r_upd;

    build_cmd_dep(src_rp);
    build_cmd_dep(dst_rp);
    
    swap_slot_pointer(&src_rp->r_prev_rp, src_rp, dst_rp);
    swap_slot_pointer(&src_rp->r_next_rp, src_rp, dst_rp);
    swap_slot_pointer(&src_rp->r_old_rp, src_rp, dst_rp);
    swap_slot_pointer(&src_rp->r_new_rp, src_rp, dst_rp);
    swap_slot_pointer(&dst_rp->r_prev_rp, src_rp, dst_rp);
    swap_slot_pointer(&dst_rp->r_next_rp, src_rp, dst_rp);
    swap_slot_pointer(&dst_rp->r_old_rp, src_rp, dst_rp);
    swap_slot_pointer(&dst_rp->r_new_rp, src_rp, dst_rp);

    struct rprocupd *prev_rpupd = NULL, *rpupd = NULL;
    RUPDATE_ITER(rupdate.first_rpupd, prev_rpupd, rpupd,
        swap_slot_pointer(&rpupd->rp, src_rp, dst_rp);
    );
    
    swap_slot_pointer(&rproc_ptr[_ENDPOINT_P(src_rp->r_pub->endpoint)], src_rp, dst_rp);
    swap_slot_pointer(&rproc_ptr[_ENDPOINT_P(dst_rp->r_pub->endpoint)], src_rp, dst_rp);

    *src_rpp = dst_rp;
    *dst_rpp = src_rp;
}

/*===========================================================================*
 *			   lookup_slot_by_label				     *
 *===========================================================================*/
#include <stddef.h>
#include <string.h>

struct rproc *lookup_slot_by_label(const char *label) {
    int slot_nr;
    struct rproc *rp;
    struct rprocpub *rpub;

    if (!label) return NULL;

    for (slot_nr = 0; slot_nr < NR_SYS_PROCS; slot_nr++) {
        rp = &rproc[slot_nr];
        if ((rp->r_flags & RS_ACTIVE) == 0) {
            continue;
        }
        rpub = rp->r_pub;
        if (rpub && strcmp(rpub->label, label) == 0) {
            return rp;
        }
    }
    return NULL;
}

/*===========================================================================*
 *			   lookup_slot_by_pid				     *
 *===========================================================================*/
struct rproc* lookup_slot_by_pid(pid_t pid)
{
    if (pid < 0) return NULL;

    for (int slot_nr = 0; slot_nr < NR_SYS_PROCS; slot_nr++) {
        struct rproc *rp = &rproc[slot_nr];
        if ((rp->r_flags & RS_IN_USE) && (rp->r_pid == pid)) {
            return rp;
        }
    }

    return NULL;
}

/*===========================================================================*
 *			   lookup_slot_by_dev_nr			     *
 *===========================================================================*/
struct rproc* lookup_slot_by_dev_nr(dev_t dev_nr) {
    if (dev_nr <= 0) {
        return NULL;
    }
    
    for (int slot_nr = 0; slot_nr < NR_SYS_PROCS; slot_nr++) {
        struct rproc *rp = &rproc[slot_nr];
        if ((rp->r_flags & RS_IN_USE) && rp->r_pub->dev_nr == dev_nr) {
            return rp;
        }
    }

    return NULL;
}

/*===========================================================================*
 *			   lookup_slot_by_domain			     *
 *===========================================================================*/
struct rproc* lookup_slot_by_domain(int domain) {
    if (domain <= 0) {
        return NULL;
    }

    for (int slot_nr = 0; slot_nr < NR_SYS_PROCS; slot_nr++) {
        struct rproc* rp = &rproc[slot_nr];
        if (!(rp->r_flags & RS_IN_USE)) {
            continue;
        }

        struct rprocpub* rpub = rp->r_pub;
        for (int i = 0; i < rpub->nr_domain; i++) {
            if (rpub->domain[i] == domain) {
                return rp;
            }
        }
    }

    return NULL;
}

/*===========================================================================*
 *			   lookup_slot_by_flags				     *
 *===========================================================================*/
struct rproc* lookup_slot_by_flags(int flags) {
    if (flags == 0) {
        return NULL;
    }

    for (int slot_nr = 0; slot_nr < NR_SYS_PROCS; slot_nr++) {
        struct rproc *rp = &rproc[slot_nr];
        if ((rp->r_flags & RS_IN_USE) && (rp->r_flags & flags)) {
            return rp;
        }
    }

    return NULL;
}

/*===========================================================================*
 *				alloc_slot				     *
 *===========================================================================*/
int alloc_slot(struct rproc **rpp) {
    for (int slot_nr = 0; slot_nr < NR_SYS_PROCS; slot_nr++) {
        *rpp = &rproc[slot_nr];
        if (!((*rpp)->r_flags & RS_IN_USE)) {
            return OK;
        }
    }
    return ENOMEM;
}

/*===========================================================================*
 *				free_slot				     *
 *===========================================================================*/
void free_slot(struct rproc *rp) {
    struct rprocpub *rpub = rp->r_pub;

    if (late_reply(rp, OK) != 0) {
        // Handle potential late_reply error if necessary
    }

    if (rpub->sys_flags & SF_USE_COPY) {
        free_exec(rp);
    }

    rp->r_flags = 0;
    rp->r_pid = -1;
    rpub->in_use = FALSE;
    rproc_ptr[_ENDPOINT_P(rpub->endpoint)] = NULL;
}


/*===========================================================================*
 *				get_next_name				     *
 *===========================================================================*/
#include <stdio.h>
#include <ctype.h>
#include <string.h>

#define RS_MAX_LABEL_LEN 64

static char *get_next_name(char *ptr, char *name, const char *caller_label) {
    char *current = ptr;
    size_t len;

    while (*current != '\0') {
        while (isspace((unsigned char)*current)) {
            current++;
        }

        if (*current == '\0') {
            break;
        }

        char *next = current;
        while (*next != '\0' && !isspace((unsigned char)*next)) {
            next++;
        }

        len = next - current;
        if (len > RS_MAX_LABEL_LEN) {
            fprintf(stderr, 
                    "Error: bad ipc list entry '%.*s' for %s: too long\n", 
                    (int)len, current, caller_label);
            current = next;
            continue;
        }

        memcpy(name, current, len);
        name[len] = '\0';

        return next;
    }
    return NULL;
}

/*===========================================================================*
 *				add_forward_ipc				     *
 *===========================================================================*/
void add_forward_ipc(struct rproc *rp, struct priv *privp) {
    char name[RS_MAX_LABEL_LEN + 1];
    struct rproc *rrp;
    endpoint_t endpoint;
    int r;
    char *p = rp->r_ipc_list;

    while ((p = get_next_name(p, name, rp->r_pub->label)) != NULL) {
        if (strcmp(name, "SYSTEM") == 0) {
            endpoint = SYSTEM;
        } else if (strcmp(name, "USER") == 0) {
            endpoint = INIT_PROC_NR;
        } else {
            for (rrp = BEG_RPROC_ADDR; rrp < END_RPROC_ADDR; rrp++) {
                if ((rrp->r_flags & RS_IN_USE) && !strcmp(rrp->r_pub->proc_name, name)) {
                    set_sys_bit(privp->s_ipc_to, rrp->r_priv.s_id);
                }
            }
            continue;
        }

        if ((r = sys_getpriv(&priv, endpoint)) < 0) {
            printf("add_forward_ipc: unable to get priv_id for '%s': %d\n", name, r);
            continue;
        }
        set_sys_bit(privp->s_ipc_to, priv.s_id);
    }
}


/*===========================================================================*
 *				add_backward_ipc			     *
 *===========================================================================*/
#include <string.h>

void add_backward_ipc(struct rproc *rp, struct priv *privp) {
    char name[RS_MAX_LABEL_LEN+1], *p;
    char *proc_name = rp->r_pub->proc_name;
    struct rproc *rrp;
    int priv_id;

    for (rrp = BEG_RPROC_ADDR; rrp < END_RPROC_ADDR; rrp++) {
        if (!(rrp->r_flags & RS_IN_USE) || !rrp->r_ipc_list[0]) {
            continue;
        }

        int is_ipc_all = !strcmp(rrp->r_ipc_list, RSS_IPC_ALL);
        int is_ipc_all_sys = !strcmp(rrp->r_ipc_list, RSS_IPC_ALL_SYS);

        if (is_ipc_all || (is_ipc_all_sys && (privp->s_flags & SYS_PROC))) {
            priv_id = rrp->r_priv.s_id;
            set_sys_bit(privp->s_ipc_to, priv_id);
            continue;
        }

        p = rrp->r_ipc_list;
        while ((p = get_next_name(p, name, rrp->r_pub->label)) != NULL) {
            if (!strcmp(proc_name, name)) {
                priv_id = rrp->r_priv.s_id;
                set_sys_bit(privp->s_ipc_to, priv_id);
            }
        }
    }
}


/*===========================================================================*
 *				init_privs				     *
 *===========================================================================*/
void init_privs(struct rproc *rp, struct priv *privp) {
    int is_ipc_all = !strcmp(rp->r_ipc_list, RSS_IPC_ALL);
    int is_ipc_all_sys = !strcmp(rp->r_ipc_list, RSS_IPC_ALL_SYS);

    fill_send_mask(&privp->s_ipc_to, FALSE);

#if PRIV_DEBUG
    printf("  RS: init_privs: ipc list is '%s'...\n", rp->r_ipc_list);
#endif

    if (is_ipc_all || is_ipc_all_sys) {
        for (int i = 0; i < NR_SYS_PROCS; i++) {
            if (is_ipc_all || i != USER_PRIV_ID) {
                set_sys_bit(privp->s_ipc_to, i);
            }
        }
    } else {
        add_forward_ipc(rp, privp);
        add_backward_ipc(rp, privp);
    }
}

