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
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

static int get_endpoint_from_label(const char *label, endpoint_t *ep)
{
    if (ds_retrieve_label_endpt(label, ep) == OK) {
        return OK;
    }

    if (strcmp("ANY_USR", label) == 0) {
        *ep = ANY_USR;
    } else if (strcmp("ANY_SYS", label) == 0) {
        *ep = ANY_SYS;
    } else if (strcmp("ANY_TSK", label) == 0) {
        *ep = ANY_TSK;
    } else {
        char *end_ptr;
        errno = 0;
        long val = strtol(label, &end_ptr, 10);
        if (errno != 0 || *end_ptr != '\0' || val > INT_MAX || val < INT_MIN) {
            return ESRCH;
        }
        *ep = (endpoint_t)val;
    }
    return OK;
}

static int parse_ipc_filter_element(const struct rs_ipc_filter_el *src_el,
                                    ipc_filter_el_t *dst_el)
{
    dst_el->flags = src_el->flags;
    dst_el->m_type = 0;
    dst_el->m_source = 0;

    if (src_el->flags & IPCF_MATCH_M_TYPE) {
        dst_el->m_type = src_el->m_type;
    }

    if (src_el->flags & IPCF_MATCH_M_SOURCE) {
        int result = get_endpoint_from_label(src_el->m_label, &dst_el->m_source);
        if (result != OK) {
            return result;
        }
    }
    return OK;
}

static int init_eval_expression(endpoint_t src_e,
                                const struct rs_state_data *src_data,
                                struct rs_state_data *dst_data)
{
    if (src_data->eval_len == 0 || src_data->eval_addr == NULL) {
        return EINVAL;
    }

    dst_data->eval_addr = malloc(src_data->eval_len + 1);
    if (dst_data->eval_addr == NULL) {
        return ENOMEM;
    }
    dst_data->eval_len = src_data->eval_len;

    int s = sys_datacopy(src_e, (vir_bytes)src_data->eval_addr,
                         SELF, (vir_bytes)dst_data->eval_addr,
                         dst_data->eval_len);
    if (s != OK) {
        free(dst_data->eval_addr);
        dst_data->eval_addr = NULL;
        return s;
    }

    ((char *)dst_data->eval_addr)[dst_data->eval_len] = '\0';
    return OK;
}

static int init_ipc_filters(endpoint_t src_e,
                            const struct rs_state_data *src_data,
                            struct rs_state_data *dst_data)
{
    const size_t filter_group_size = sizeof(struct rs_ipc_filter_el[IPCF_MAX_ELEMENTS]);

    if (src_data->ipcf_els_size % filter_group_size != 0) {
        return E2BIG;
    }

    if (src_data->ipcf_els == NULL) {
        return OK;
    }

    int num_ipc_filters = src_data->ipcf_els_size / filter_group_size;
    int add_vm_filter = (src_e == VM_PROC_NR);
    size_t num_total_filters = num_ipc_filters + add_vm_filter;

    size_t ipcf_els_buff_size = sizeof(ipc_filter_el_t[IPCF_MAX_ELEMENTS]) * num_total_filters;
    ipc_filter_el_t (*ipcf_els_buff)[IPCF_MAX_ELEMENTS] = calloc(1, ipcf_els_buff_size);
    if (ipcf_els_buff == NULL) {
        return ENOMEM;
    }

    struct rs_ipc_filter_el (*src_filters)[IPCF_MAX_ELEMENTS] = src_data->ipcf_els;
    struct rs_ipc_filter_el local_filter_copy[IPCF_MAX_ELEMENTS];
    int s = OK;

    for (int i = 0; i < num_ipc_filters; i++) {
        s = sys_datacopy(src_e, (vir_bytes)src_filters[i],
                         SELF, (vir_bytes)local_filter_copy, filter_group_size);
        if (s != OK) {
            goto cleanup;
        }

        for (int j = 0; j < IPCF_MAX_ELEMENTS && local_filter_copy[j].flags; j++) {
            s = parse_ipc_filter_element(&local_filter_copy[j], &ipcf_els_buff[i][j]);
            if (s != OK) {
                goto cleanup;
            }
        }
    }

    if (add_vm_filter) {
        ipcf_els_buff[num_ipc_filters][0].flags = (IPCF_EL_WHITELIST | IPCF_MATCH_M_SOURCE | IPCF_MATCH_M_TYPE);
        ipcf_els_buff[num_ipc_filters][0].m_source = RS_PROC_NR;
        ipcf_els_buff[num_ipc_filters][0].m_type = VM_RS_UPDATE;
    }

    dst_data->ipcf_els = ipcf_els_buff;
    dst_data->ipcf_els_size = ipcf_els_buff_size;
    return OK;

cleanup:
    free(ipcf_els_buff);
    return s;
}

int init_state_data(endpoint_t src_e, int prepare_state,
    struct rs_state_data *src_rs_state_data,
    struct rs_state_data *dst_rs_state_data)
{
    memset(dst_rs_state_data, 0, sizeof(*dst_rs_state_data));

    if (src_rs_state_data->size != sizeof(struct rs_state_data)) {
        return E2BIG;
    }

    int result = OK;

    if (prepare_state == SEF_LU_STATE_EVAL) {
        result = init_eval_expression(src_e, src_rs_state_data, dst_rs_state_data);
        if (result != OK) {
            return result;
        }
    }

    result = init_ipc_filters(src_e, src_rs_state_data, dst_rs_state_data);
    if (result != OK) {
        free(dst_rs_state_data->eval_addr);
        dst_rs_state_data->eval_addr = NULL;
        return result;
    }

    dst_rs_state_data->size = src_rs_state_data->size;

    return OK;
}

/*===========================================================================*
 *			        build_cmd_dep				     *
 *===========================================================================*/
#include <stdio.h>
#include <string.h>
#include <stddef.h>

void build_cmd_dep(struct rproc *rp)
{
    size_t r_args_size = sizeof(rp->r_args);
    strncpy(rp->r_args, rp->r_cmd, r_args_size);
    if (r_args_size > 0) {
        rp->r_args[r_args_size - 1] = '\0';
    }

    rp->r_argc = 0;
    char *p = rp->r_args;

    while (*p != '\0') {
        while (*p == ' ') {
            p++;
        }
        if (*p == '\0') {
            break;
        }

        if (rp->r_argc >= ARGV_ELEMENTS - 1) {
            fprintf(stderr, "RS: build_cmd_dep: Too many arguments.\n");
            break;
        }
        rp->r_argv[rp->r_argc++] = p;

        while (*p != ' ' && *p != '\0') {
            p++;
        }
        
        if (*p == '\0') {
            break;
        }

        *p = '\0';
        p++;
    }

    rp->r_argv[rp->r_argc] = NULL;
}

/*===========================================================================*
 *				end_srv_init				     *
 *===========================================================================*/
void end_srv_init(struct rproc *rp)
{
    if (!rp) {
        return;
    }

    late_reply(rp, OK);

    if (rp->r_prev_rp) {
        struct rproc *prev_rp = rp->r_prev_rp;

        if (SRV_IS_UPD_SCHEDULED(prev_rp)) {
            rupdate_upd_move(prev_rp, rp);
        }

        cleanup_service(prev_rp);
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
int kill_service_debug(const char *file, int line, struct rproc *rp, const char *errstr, int err)
{
    if (!rp) {
        return err;
    }

    if (errstr && !shutting_down) {
        printf("RS: %s (error %d)\n", errstr, err);
    }

    rp->r_flags |= RS_EXITING;
    crash_service_debug(file, line, rp);

    return err;
}

/*===========================================================================*
 *			    crash_service_debug				     *
 *===========================================================================*/
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>

int crash_service_debug(const char *file, int line, const struct rproc *rp)
{
    const struct rprocpub *rpub = rp->r_pub;

    if (rs_verbose) {
        const char *adverb = (rp->r_flags & RS_EXITING) ? "lethally " : "";
        printf("RS: %s %skilled at %s:%d\n", srv_to_string(rp), adverb, file, line);
    }

    if (rpub->endpoint == RS_PROC_NR) {
        exit(EXIT_FAILURE);
    }

    return sys_kill(rpub->endpoint, SIGKILL);
}

/*===========================================================================*
 *			  cleanup_service_debug				     *
 *===========================================================================*/
void cleanup_service_debug(const char *file, int line, struct rproc *rp)
{
    if (!rp) {
        return;
    }

    struct rprocpub *rpub = rp->r_pub;
    int s;

    if (!(rp->r_flags & RS_DEAD)) {
        if (rs_verbose) {
            printf("RS: %s marked for cleanup at %s:%d\n", srv_to_string(rp),
                file, line);
        }

        if (rp->r_next_rp) {
            rp->r_next_rp->r_prev_rp = NULL;
            rp->r_next_rp = NULL;
        }
        if (rp->r_prev_rp) {
            rp->r_prev_rp->r_next_rp = NULL;
            rp->r_prev_rp = NULL;
        }
        if (rp->r_new_rp) {
            rp->r_new_rp->r_old_rp = NULL;
            rp->r_new_rp = NULL;
        }
        if (rp->r_old_rp) {
            rp->r_old_rp->r_new_rp = NULL;
            rp->r_old_rp = NULL;
        }
        rp->r_flags |= RS_DEAD;

        sys_privctl(rpub->endpoint, SYS_PRIV_DISALLOW, NULL);
        sys_privctl(rpub->endpoint, SYS_PRIV_CLEAR_IPC_REFS, NULL);
        rp->r_flags &= ~RS_ACTIVE;

        late_reply(rp, OK);

        return;
    }

    if (!(rp->r_flags & RS_CLEANUP_DETACH)) {
        if (rs_verbose) {
            printf("RS: %s cleaned up at %s:%d\n", srv_to_string(rp),
                file, line);
        }

        if ((s = sched_stop(rp->r_scheduler, rpub->endpoint)) != OK) {
            printf("RS: warning: scheduler won't give up process: %d\n", s);
        }

        if (rp->r_pid == -1) {
            printf("RS: warning: attempt to kill pid -1!\n");
        } else {
            srv_kill(rp->r_pid, SIGKILL);
        }
    }

    if (rp->r_flags & RS_CLEANUP_SCRIPT) {
        rp->r_flags &= ~RS_CLEANUP_SCRIPT;
        if ((s = run_script(rp)) != OK) {
            printf("RS: warning: cannot run cleanup script: %d\n", s);
        }
    }

    if (rp->r_flags & RS_CLEANUP_DETACH) {
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
void detach_service_debug(const char *file, int line, struct rproc *rp)
{
    static unsigned long detach_counter = 0;
    char old_label[RS_MAX_LABEL_LEN];
    struct rprocpub *rpub;

    if (!rp || !rp->r_pub) {
        return;
    }
    rpub = rp->r_pub;

    strncpy(old_label, rpub->label, RS_MAX_LABEL_LEN - 1);
    old_label[RS_MAX_LABEL_LEN - 1] = '\0';

    snprintf(rpub->label, RS_MAX_LABEL_LEN, "%lu.%s", ++detach_counter, old_label);
    ds_publish_label(rpub->label, rpub->endpoint, DSF_OVERWRITE);

    if (rs_verbose) {
        printf("RS: %s detached at %s:%d\n", srv_to_string(rp), file, line);
    }

    rp->r_flags = RS_IN_USE | RS_ACTIVE;
    rpub->sys_flags &= ~(SF_CORE_SRV | SF_DET_RESTART);
    rp->r_period = 0;
    rpub->dev_nr = 0;
    rpub->nr_domain = 0;
    sys_privctl(rpub->endpoint, SYS_PRIV_ALLOW, NULL);
}

/*===========================================================================*
 *				create_service				     *
 *===========================================================================*/
static int pin_root_service_memory(const struct rproc *rp)
{
    int s;

    if (rs_verbose) {
        printf("RS: pinning memory of RS instance %s\n", srv_to_string(rp));
    }

    s = vm_memctl(rp->r_pub->endpoint, VM_RS_MEM_PIN, 0, 0);
    if (s != OK) {
        printf("RS: vm_memctl failed to pin root service: %d\n", s);
    }
    return s;
}

static int setup_vm_service(const struct rproc *rp)
{
    struct rproc *rs_rp;
    struct rproc **rs_rps;
    int i, nr_rs_rps, s;

    if (rs_verbose) {
        printf("RS: informing VM of instance %s\n", srv_to_string(rp));
    }

    s = vm_memctl(rp->r_pub->endpoint, VM_RS_MEM_MAKE_VM, 0, 0);
    if (s != OK) {
        printf("RS: vm_memctl failed to make VM instance: %d\n", s);
        return s;
    }

    rs_rp = rproc_ptr[_ENDPOINT_P(RS_PROC_NR)];
    get_service_instances(rs_rp, &rs_rps, &nr_rs_rps);
    for (i = 0; i < nr_rs_rps; i++) {
        vm_memctl(rs_rps[i]->r_pub->endpoint, VM_RS_MEM_PIN, 0, 0);
    }

    return OK;
}

int create_service(struct rproc *rp)
{
    int s;
    int child_proc_nr_e, child_proc_nr_n;
    pid_t child_pid;
    int use_copy;
    int has_replica;
    int needs_free_exec = 0;
    struct rprocpub *rpub;
    extern char **environ;

    rpub = rp->r_pub;
    use_copy = !!(rpub->sys_flags & SF_USE_COPY);
    has_replica = !!(rp->r_old_rp || (rp->r_prev_rp && !(rp->r_prev_rp->r_flags & RS_TERMINATED)));

    if (!has_replica && (rpub->sys_flags & SF_NEED_REPL)) {
        printf("RS: unable to create service '%s' without a replica\n", rpub->label);
        s = EPERM;
    } else if (!use_copy && (rpub->sys_flags & SF_NEED_COPY)) {
        printf("RS: unable to create service '%s' without an in-memory copy\n", rpub->label);
        s = EPERM;
    } else if (!use_copy && strcmp(rp->r_cmd, "") == 0) {
        printf("RS: unable to create service '%s' without a copy or command\n", rpub->label);
        s = EPERM;
    } else {
        s = OK;
    }
    if (s != OK) {
        free_slot(rp);
        return s;
    }

    if (rs_verbose) printf("RS: forking child with srv_fork()...\n");
    child_pid = srv_fork(rp->r_uid, 0);
    if (child_pid < 0) {
        printf("RS: srv_fork() failed (error %d)\n", child_pid);
        free_slot(rp);
        return child_pid;
    }

    if ((s = getprocnr(child_pid, &child_proc_nr_e)) != OK) {
        printf("RS: unable to get child endpoint for pid %d (error %d)\n", child_pid, s);
        free_slot(rp);
        return s;
    }

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
        s = ENOMEM;
        goto cleanup_repin;
    }

    if ((s = sched_init_proc(rp)) != OK) {
        printf("RS: unable to start scheduling: %d\n", s);
        goto cleanup_repin;
    }

    if (!use_copy) {
        if ((s = read_exec(rp)) != OK) {
            printf("RS: read_exec failed: %d\n", s);
            goto cleanup_repin;
        }
        needs_free_exec = 1;
    }

    if (rs_verbose) printf("RS: execing child with srv_execve()...\n");
    s = srv_execve(child_proc_nr_e, rp->r_exec, rp->r_exec_len, rpub->proc_name, rp->r_argv, environ);
    vm_memctl(RS_PROC_NR, VM_RS_MEM_PIN, 0, 0);

    if (needs_free_exec) {
        free_exec(rp);
    }

    if (s != OK) {
        printf("RS: srv_execve failed: %d\n", s);
        goto cleanup;
    }

    setuid(0);

    if ((rp->r_priv.s_flags & ROOT_SYS_PROC) && (s = pin_root_service_memory(rp)) != OK) {
        goto cleanup;
    }

    if ((rp->r_priv.s_flags & VM_SYS_PROC) && (s = setup_vm_service(rp)) != OK) {
        goto cleanup;
    }

    if ((s = vm_set_priv(rpub->endpoint, &rpub->vm_call_mask[0], TRUE)) != OK) {
        printf("RS: vm_set_priv failed: %d\n", s);
        goto cleanup;
    }

    if (rs_verbose) printf("RS: %s created\n", srv_to_string(rp));

    return OK;

cleanup_repin:
    vm_memctl(RS_PROC_NR, VM_RS_MEM_PIN, 0, 0);
cleanup:
    cleanup_service(rp);
    return s;
}

/*===========================================================================*
 *				clone_service				     *
 *===========================================================================*/
int clone_service(struct rproc *rp, int instance_flag, int init_flags)
{
    struct rproc *replica_rp;
    int r;
    const int is_live_update = (instance_flag == LU_SYS_PROC);

    if (rs_verbose) {
        printf("RS: %s creating a replica\n", srv_to_string(rp));
    }

    if (is_live_update && rp->r_pub->endpoint == VM_PROC_NR && rp->r_next_rp) {
        cleanup_service_now(rp->r_next_rp);
        rp->r_next_rp = NULL;
    }

    r = clone_slot(rp, &replica_rp);
    if (r != OK) {
        return r;
    }

    replica_rp->r_priv.s_flags |= instance_flag;
    replica_rp->r_priv.s_init_flags |= init_flags;

    if (is_live_update) {
        rp->r_new_rp = replica_rp;
        replica_rp->r_old_rp = rp;
    } else {
        rp->r_next_rp = replica_rp;
        replica_rp->r_prev_rp = rp;
    }

    r = create_service(replica_rp);
    if (r != OK) {
        if (is_live_update) {
            rp->r_new_rp = NULL;
        } else {
            rp->r_next_rp = NULL;
        }
        return r;
    }

    const int rs_flags = ROOT_SYS_PROC | RST_SYS_PROC;
    if ((replica_rp->r_priv.s_flags & rs_flags) == rs_flags) {
        struct rproc *rs_rp = rproc_ptr[_ENDPOINT_P(RS_PROC_NR)];
        struct rprocpub *replica_rpub = replica_rp->r_pub;

        r = update_sig_mgrs(rs_rp, SELF, replica_rpub->endpoint);
        if (r == OK) {
            r = update_sig_mgrs(replica_rp, SELF, NONE);
        }

        if (r != OK) {
            if (is_live_update) {
                rp->r_new_rp = NULL;
            } else {
                rp->r_next_rp = NULL;
            }
            return kill_service(replica_rp, "update_sig_mgrs failed", r);
        }
    }

    return OK;
}

/*===========================================================================*
 *				publish_service				     *
 *===========================================================================*/
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <minix/rs.h>
#include <minix/ipc.h>
#include <minix/ds.h>
#include "rs.h"

/* Forward declarations for static functions not shown in the original snippet */
static int kill_service(struct rproc *rp, const char *reason, int err);
static const char* srv_to_string(struct rproc *rp);

#if USE_PCI
#include <minix/pci.h>
#endif

int publish_service(struct rproc *rp)
{
    if (!rp || !rp->r_pub) {
        return EINVAL;
    }

    struct rprocpub *rpub = rp->r_pub;
    int r;

    r = ds_publish_label(rpub->label, rpub->endpoint, DSF_OVERWRITE);
    if (r != OK) {
        return kill_service(rp, "ds_publish_label call failed", r);
    }

    if (rpub->dev_nr > 0 || rpub->nr_domain > 0) {
        /* The purpose of non-blocking forks is to avoid involving VFS in the
         * forking process, because VFS may be blocked on a ipc_sendrec() to a MFS
         * that is waiting for a endpoint update for a dead driver. We have just
         * published that update, but VFS may still be blocked. As a result, VFS
         * may not yet have received PM's fork message. Hence, if we call
         * mapdriver() immediately, VFS may not know about the process and thus
         * refuse to add the driver entry. The following temporary hack works
         * around this by forcing blocking communication from PM to VFS. Once VFS
         * has been made non-blocking towards MFS instances, this hack and the
         * big part of srv_fork() can go.
         */
        setuid(0);

        r = mapdriver(rpub->label, rpub->dev_nr, rpub->domain, rpub->nr_domain);
        if (r != OK) {
            return kill_service(rp, "couldn't map driver", r);
        }
    }

#if USE_PCI
    if (rpub->pci_acl.rsp_nr_device || rpub->pci_acl.rsp_nr_class) {
        struct rs_pci pci_acl = rpub->pci_acl;
        pci_acl.rsp_endpoint = rpub->endpoint;

        strncpy(pci_acl.rsp_label, rpub->label, sizeof(pci_acl.rsp_label) - 1);
        pci_acl.rsp_label[sizeof(pci_acl.rsp_label) - 1] = '\0';

        r = pci_set_acl(&pci_acl);
        if (r != OK) {
            return kill_service(rp, "pci_set_acl call failed", r);
        }
    }
#endif /* USE_PCI */

    if (rpub->devman_id != 0) {
        endpoint_t ep;
        r = ds_retrieve_label_endpt("devman", &ep);
        if (r != OK) {
            return kill_service(rp, "devman not running?", r);
        }

        message m;
        m.m_type = DEVMAN_BIND;
        m.DEVMAN_ENDPOINT = rpub->endpoint;
        m.DEVMAN_DEVICE_ID = rpub->devman_id;
        
        r = ipc_sendrec(ep, &m);
        if (r != OK) {
            return kill_service(rp, "devman bind ipc failed", r);
        }
        if (m.DEVMAN_RESULT != OK) {
            return kill_service(rp, "devman bind request failed", m.DEVMAN_RESULT);
        }
    }

    if (rs_verbose) {
        printf("RS: %s published\n", srv_to_string(rp));
    }

    return OK;
}

/*===========================================================================*
 *			      unpublish_service				     *
 *===========================================================================*/
int unpublish_service(struct rproc *rp)
{
/* Unpublish a service. */
    struct rprocpub *rpub;
    int status;
    int result;

    if (!rp || !rp->r_pub) {
        return EINVAL;
    }

    rpub = rp->r_pub;
    result = OK;

    /* Unregister label with DS. */
    status = ds_delete_label(rpub->label);
    if (status != OK) {
        if (!shutting_down) {
            printf("RS: ds_delete_label for '%s' failed (error %d)\n",
                rpub->label, status);
        }
        result = status;
    }

    /* No need to inform VFS and VM, cleanup is done on exit automatically. */

#if USE_PCI
    /* If PCI properties are set, inform the PCI driver. */
    if (rpub->pci_acl.rsp_nr_device || rpub->pci_acl.rsp_nr_class) {
        status = pci_del_acl(rpub->endpoint);
        if (status != OK) {
            if (!shutting_down) {
                printf("RS: pci_del_acl for endpoint %d failed (error %d)\n",
                    rpub->endpoint, status);
            }
            if (result == OK) {
                result = status;
            }
        }
    }
#endif /* USE_PCI */

    if (rpub->devman_id != 0) {
        endpoint_t ep;
        status = ds_retrieve_label_endpt("devman", &ep);
        if (status != OK) {
            if (!shutting_down) {
                printf("RS: failed to retrieve devman endpoint (error %d)\n", status);
            }
            if (result == OK) {
                result = status;
            }
        } else {
            message m;
            m.m_type = DEVMAN_UNBIND;
            m.DEVMAN_ENDPOINT  = rpub->endpoint;
            m.DEVMAN_DEVICE_ID = rpub->devman_id;
            status = ipc_sendrec(ep, &m);

            if (status != OK) {
                if (!shutting_down) {
                    printf("RS: ipc_sendrec to devman failed (error %d)\n", status);
                }
                if (result == OK) {
                    result = status;
                }
            } else if (m.DEVMAN_RESULT != OK) {
                if (!shutting_down) {
                    printf("RS: devman unbind for device %d failed (error %d)\n",
                        rpub->devman_id, m.DEVMAN_RESULT);
                }
                if (result == OK) {
                    result = m.DEVMAN_RESULT;
                }
            }
        }
    }

    if(rs_verbose)
        printf("RS: %s unpublished\n", srv_to_string(rp));

    return result;
}

/*===========================================================================*
 *				run_service				     *
 *===========================================================================*/
int run_service(struct rproc *rp, int init_type, int init_flags)
{
    int status;

    if (!rp || !rp->r_pub) {
        return -1;
    }

    status = sys_privctl(rp->r_pub->endpoint, SYS_PRIV_ALLOW, NULL);
    if (status != OK) {
        return kill_service(rp, "Failed to set service privileges", status);
    }

    status = init_service(rp, init_type, init_flags);
    if (status != OK) {
        return kill_service(rp, "Failed to initialize service", status);
    }

    if (rs_verbose) {
        printf("RS: %s allowed to run\n", srv_to_string(rp));
    }

    return OK;
}

/*===========================================================================*
 *				start_service				     *
 *===========================================================================*/
int start_service(struct rproc *rp, int init_flags)
{
    if (!rp || !rp->r_pub) {
        return EINVAL;
    }

    int r;

    rp->r_priv.s_init_flags |= init_flags;

    r = create_service(rp);
    if (r != OK) {
        return r;
    }

    activate_service(rp, NULL);

    r = publish_service(rp);
    if (r != OK) {
        return r;
    }

    r = run_service(rp, SEF_INIT_FRESH, init_flags);
    if (r == OK && rs_verbose) {
        printf("RS: %s started with major %d\n", srv_to_string(rp),
               rp->r_pub->dev_nr);
    }

    return r;
}

/*===========================================================================*
 *				stop_service				     *
 *===========================================================================*/
void stop_service(struct rproc *rp, int how)
{
    const struct rprocpub *rpub = rp->r_pub;
    const int signo = (rpub->endpoint == RS_PROC_NR) ? SIGHUP : SIGTERM;

    if (rs_verbose) {
        printf("RS: Signaling %s to stop with signal %d\n",
               srv_to_string(rp), signo);
    }

    rp->r_flags |= how;

    if (sys_kill(rpub->endpoint, signo) == 0) {
        rp->r_stop_tm = getticks();
    } else {
        printf("RS: ERROR: Failed to send signal to endpoint %d\n",
               rpub->endpoint);
    }
}

/*===========================================================================*
 *			      activate_service				     *
 *===========================================================================*/
void activate_service(struct rproc *rp, struct rproc *ex_rp)
{
    const int should_deactivate = ex_rp && (ex_rp->r_flags & RS_ACTIVE);
    const int should_activate = rp && !(rp->r_flags & RS_ACTIVE);

    if (should_deactivate) {
        ex_rp->r_flags &= ~RS_ACTIVE;
        if (rs_verbose) {
            printf("RS: %s becomes inactive\n", srv_to_string(ex_rp));
        }
    }

    if (should_activate) {
        rp->r_flags |= RS_ACTIVE;
        if (rs_verbose) {
            printf("RS: %s becomes active\n", srv_to_string(rp));
        }
    }
}

/*===========================================================================*
 *			      reincarnate_service			     *
 *===========================================================================*/
void reincarnate_service(struct rproc *old_rp)
{
    if (old_rp == NULL) {
        printf("RS: Error: reincarnate_service called with a NULL service pointer.\n");
        return;
    }

    struct rproc *rp;
    int r = clone_slot(old_rp, &rp);
    if (r != OK) {
        printf("RS: Failed to clone the slot: %d\n", r);
        return;
    }

    rp->r_flags = RS_IN_USE;
    rproc_ptr[_ENDPOINT_P(rp->r_pub->endpoint)] = NULL;

    const int restarts = rp->r_restarts;
    start_service(rp, SEF_INIT_FRESH);
    rp->r_restarts = restarts + 1;
}

/*===========================================================================*
 *			      terminate_service				     *
 *===========================================================================*/
static int handle_initialization_failure(struct rproc *rp)
{
    if (!(rp->r_flags & RS_INITIALIZING)) {
        return 0;
    }

    if (SRV_IS_UPDATING(rp)) {
        printf("RS: update failed: state transfer failed. Rolling back...\n");
        end_update(rp->r_init_err, RS_REPLY);
        rp->r_init_err = ERESTART;
        return 1;
    }

    if (rp->r_pub->sys_flags & SF_NO_BIN_EXP) {
        if (rs_verbose) {
            printf("RS: service '%s' exited during initialization; "
                   "refreshing\n", rp->r_pub->label);
        }
        rp->r_flags |= RS_REFRESHING;
    } else {
        if (rs_verbose) {
            printf("RS: service '%s' exited during initialization; "
                   "exiting\n", rp->r_pub->label);
        }
        rp->r_flags |= RS_EXITING;
    }
    return 0;
}

static int force_exit_if_no_restart(struct rproc *rp)
{
    int norestart = !(rp->r_flags & RS_EXITING) && (rp->r_pub->sys_flags & SF_NORESTART);
    if (norestart) {
        rp->r_flags |= RS_EXITING;
        if ((rp->r_pub->sys_flags & SF_DET_RESTART)
            && (rp->r_restarts < MAX_DET_RESTART)) {
            rp->r_flags |= RS_CLEANUP_DETACH;
        }
        if (rp->r_script[0] != '\0') {
            rp->r_flags |= RS_CLEANUP_SCRIPT;
        }
    }
    return norestart;
}

static void cleanup_and_exit_service(struct rproc *rp, int norestart)
{
    struct rproc **rps;
    int nr_rps;
    int i, r;

    if ((rp->r_pub->sys_flags & SF_CORE_SRV) && !shutting_down) {
        printf("core system service died: %s\n", srv_to_string(rp));
        _exit(1);
    }

    if (SRV_IS_UPD_SCHEDULED(rp)) {
        printf("RS: aborting the scheduled update, one of the services part of it is exiting...\n");
        abort_update_proc(EDEADSRCDST);
    }

    r = (rp->r_caller_request == RS_DOWN
        || (rp->r_caller_request == RS_REFRESH && norestart)) ? OK : EDEADEPT;
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
}

static int should_restart_immediately(struct rproc *rp)
{
    struct rprocpub *rpub = rp->r_pub;

    if (rp->r_restarts == 0) {
        return 1;
    }

    if (!(rpub->sys_flags & SF_NO_BIN_EXP)) {
        rp->r_backoff = 1 << MIN(rp->r_restarts, (BACKOFF_BITS - 2));
        rp->r_backoff = MIN(rp->r_backoff, MAX_BACKOFF);
        if ((rpub->sys_flags & SF_USE_COPY) && rp->r_backoff > 1) {
            rp->r_backoff = 1;
        }
    } else {
        rp->r_backoff = 1;
    }

    return 0;
}

void terminate_service(struct rproc *rp)
{
    int norestart;

    if (rs_verbose) {
        printf("RS: %s terminated\n", srv_to_string(rp));
    }

    if (handle_initialization_failure(rp)) {
        return;
    }

    if (RUPDATE_IS_UPDATING()) {
        printf("RS: aborting the update after a crash...\n");
        abort_update_proc(ERESTART);
    }

    norestart = force_exit_if_no_restart(rp);

    if (rp->r_flags & RS_EXITING) {
        cleanup_and_exit_service(rp, norestart);
    } else if (rp->r_flags & RS_REFRESHING) {
        restart_service(rp);
    } else {
        if (should_restart_immediately(rp)) {
            restart_service(rp);
        }
    }
}

/*===========================================================================*
 *				run_script				     *
 *===========================================================================*/
static const char *get_reason_string(unsigned int flags)
{
	if (flags & RS_REFRESHING) {
		return "restart";
	}
	if (flags & RS_NOPINGREPLY) {
		return "no-heartbeat";
	}
	return "terminated";
}

static void log_script_execution(const struct rproc *rp, const char *reason,
	const char *incarnation_str)
{
	if (rs_verbose) {
		printf("RS: %s:\n", srv_to_string(rp));
		printf("RS:     calling script '%s'\n", rp->r_script);
		printf("RS:     reason: '%s'\n", reason);
		printf("RS:     incarnation: '%s'\n", incarnation_str);
	}
}

static void execute_script_in_child(struct rproc *rp, const char *reason,
	const char *incarnation_str)
{
	char *envp[] = { NULL };
	struct rprocpub *rpub = rp->r_pub;

	execle(_PATH_BSHELL, "sh", rp->r_script, rpub->label, reason,
		incarnation_str, (char *) NULL, envp);

	printf("RS: run_script: execle '%s' failed: %s\n",
		rp->r_script, strerror(errno));
	exit(1);
}

static int setup_child_privileges(pid_t pid, struct rproc *rp)
{
	int r, endpoint;

	if ((r = getprocnr(pid, &endpoint)) != OK) {
		panic("unable to get child endpoint: %d", r);
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

	vm_memctl(RS_PROC_NR, VM_RS_MEM_PIN, 0, 0);

	return OK;
}

static int run_script(struct rproc *rp)
{
	pid_t pid;
	char incarnation_str[20];
	const char *reason = get_reason_string(rp->r_flags);

	int len = snprintf(incarnation_str, sizeof(incarnation_str), "%d",
		rp->r_restarts);
	if (len < 0 || (size_t)len >= sizeof(incarnation_str)) {
		return E2BIG;
	}

	log_script_execution(rp, reason, incarnation_str);

	pid = fork();
	if (pid < 0) {
		return errno;
	}

	if (pid == 0) {
		execute_script_in_child(rp, reason, incarnation_str);
	}

	return setup_child_privileges(pid, rp);
}

/*===========================================================================*
 *			      restart_service				     *
 *===========================================================================*/
void restart_service(struct rproc *rp)
{
    struct rproc *replica_rp;
    int r;

    late_reply(rp, OK);

    if (rp->r_script[0] != '\0') {
        if (run_script(rp) != OK) {
            kill_service(rp, "unable to run script", errno);
        }
        return;
    }

    replica_rp = rp->r_next_rp;
    if (replica_rp == NULL) {
        r = clone_service(rp, RST_SYS_PROC, 0);
        if (r != OK) {
            kill_service(rp, "unable to clone service", r);
            return;
        }
        replica_rp = rp->r_next_rp;
    }

    if ((r = update_service(&rp, &replica_rp, RS_SWAP, 0)) != OK) {
        kill_service(rp, "unable to update into new replica", r);
        return;
    }

    if ((r = run_service(replica_rp, SEF_INIT_RESTART, 0)) != OK) {
        kill_service(rp, "unable to let the replica run", r);
        return;
    }

    if ((rp->r_pub->sys_flags & SF_DET_RESTART)
        && (rp->r_restarts < MAX_DET_RESTART)) {
        rp->r_flags |= RS_CLEANUP_DETACH;
    }

    if (rs_verbose) {
        printf("RS: %s restarted into %s\n",
            srv_to_string(rp), srv_to_string(replica_rp));
    }
}

/*===========================================================================*
 *		         inherit_service_defaults			     *
 *===========================================================================*/
void inherit_service_defaults(struct rproc *def_rp, struct rproc *rp)
{
    if (!def_rp || !rp || !def_rp->r_pub || !rp->r_pub) {
        return;
    }

    struct rprocpub *def_rpub = def_rp->r_pub;
    struct rprocpub *rpub = rp->r_pub;

    rpub->dev_nr = def_rpub->dev_nr;
    rpub->nr_domain = def_rpub->nr_domain;
    if (def_rpub->nr_domain > 0) {
        memcpy(rpub->domain, def_rpub->domain,
               (size_t)def_rpub->nr_domain * sizeof(rpub->domain[0]));
    }
    rpub->pci_acl = def_rpub->pci_acl;

    rpub->sys_flags &= ~IMM_SF;
    rpub->sys_flags |= (def_rpub->sys_flags & IMM_SF);

    rp->r_priv.s_flags &= ~IMM_F;
    rp->r_priv.s_flags |= (def_rp->r_priv.s_flags & IMM_F);

    rp->r_priv.s_trap_mask = def_rp->r_priv.s_trap_mask;
}

/*===========================================================================*
 *		           get_service_instances			     *
 *===========================================================================*/
void get_service_instances(const struct rproc *rp, struct rproc **rps, int *length)
{
    static struct rproc *instances[5];
    int nr_instances = 0;

    if (rp == NULL || rps == NULL || length == NULL) {
        if (rps != NULL) {
            *rps = NULL;
        }
        if (length != NULL) {
            *length = 0;
        }
        return;
    }

    instances[nr_instances++] = (struct rproc *)rp;

    if (rp->r_prev_rp != NULL) {
        instances[nr_instances++] = rp->r_prev_rp;
    }
    if (rp->r_next_rp != NULL) {
        instances[nr_instances++] = rp->r_next_rp;
    }
    if (rp->r_old_rp != NULL) {
        instances[nr_instances++] = rp->r_old_rp;
    }
    if (rp->r_new_rp != NULL) {
        instances[nr_instances++] = rp->r_new_rp;
    }

    *rps = instances;
    *length = nr_instances;
}

/*===========================================================================*
 *				share_exec				     *
 *===========================================================================*/
void share_exec(struct rproc *rp_dst, const struct rproc *rp_src)
{
    if (rp_dst == NULL || rp_src == NULL) {
        return;
    }

    if (rs_verbose) {
        printf("RS: %s shares exec image with %s\n",
            srv_to_string(rp_dst), srv_to_string(rp_src));
    }

    rp_dst->r_exec_len = rp_src->r_exec_len;
    rp_dst->r_exec = rp_src->r_exec;
}

/*===========================================================================*
 *				read_exec				     *
 *===========================================================================*/
int read_exec(struct rproc *rp)
{
    const char *e_name = rp->r_argv[0];
    struct stat sb;
    int fd;

    if (rs_verbose) {
        printf("RS: service '%s' reads exec image from: %s\n",
               rp->r_pub->label, e_name);
    }

    if (stat(e_name, &sb) != 0) {
        return -errno;
    }

    if (sb.st_size < 0 || (size_t)sb.st_size < sizeof(Elf_Ehdr)) {
        return ENOEXEC;
    }

    fd = open(e_name, O_RDONLY);
    if (fd < 0) {
        return -errno;
    }

    size_t exec_len = (size_t)sb.st_size;
    rp->r_exec = malloc(exec_len);
    if (rp->r_exec == NULL) {
        fprintf(stderr, "RS: read_exec: unable to allocate %zu bytes for %s\n",
                exec_len, e_name);
        close(fd);
        return ENOMEM;
    }
    rp->r_exec_len = exec_len;

    ssize_t bytes_read = read(fd, rp->r_exec, rp->r_exec_len);
    int read_errno = errno;
    close(fd);

    if (bytes_read == (ssize_t)rp->r_exec_len) {
        return OK;
    }

    free_exec(rp);

    if (bytes_read >= 0) {
        fprintf(stderr, "RS: read_exec: short read on %s (%zd of %zu bytes)\n",
                e_name, bytes_read, rp->r_exec_len);
        return EIO;
    }

    fprintf(stderr, "RS: read_exec: read from %s failed: %s\n",
            e_name, strerror(read_errno));
    return -read_errno;
}

/*===========================================================================*
 *				free_exec				     *
 *===========================================================================*/
void free_exec(struct rproc *rp)
{
    if (!rp || !rp->r_exec) {
        return;
    }

    struct rproc *sharer = NULL;
    for (int slot_nr = 0; slot_nr < NR_SYS_PROCS; slot_nr++) {
        struct rproc *other_rp = &rproc[slot_nr];
        if ((other_rp->r_flags & RS_IN_USE) &&
            (other_rp != rp) &&
            (other_rp->r_exec == rp->r_exec)) {
            sharer = other_rp;
            break;
        }
    }

    if (sharer) {
        if (rs_verbose) {
            printf("RS: %s no longer sharing exec image with %s\n",
                   srv_to_string(rp), srv_to_string(sharer));
        }
    } else {
        if (rs_verbose) {
            printf("RS: %s frees exec image\n", srv_to_string(rp));
        }
        free(rp->r_exec);
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
static void initialize_clone(struct rproc *clone_rp, const struct rproc *src_rp)
{
    struct rprocpub *clone_rpub = clone_rp->r_pub;

    clone_rp->r_init_err = ERESTART;
    clone_rp->r_flags &= ~RS_ACTIVE;
    clone_rp->r_pid = -1;
    clone_rpub->endpoint = -1;

    build_cmd_dep(clone_rp);
    if (clone_rpub->sys_flags & SF_USE_COPY) {
        share_exec(clone_rp, src_rp);
    }

    clone_rp->r_old_rp = NULL;
    clone_rp->r_new_rp = NULL;
    clone_rp->r_prev_rp = NULL;
    clone_rp->r_next_rp = NULL;

    clone_rp->r_priv.s_flags |= DYN_PRIV_ID;
    clone_rp->r_priv.s_flags &= ~(LU_SYS_PROC | RST_SYS_PROC);
    clone_rp->r_priv.s_init_flags = 0;
}

int clone_slot(struct rproc *rp, struct rproc **clone_rpp)
{
    int r;
    struct rproc *clone_rp;
    struct rprocpub *clone_rpub_ptr;

    if ((r = alloc_slot(&clone_rp)) != OK) {
        printf("RS: clone_slot: unable to allocate a new slot: %d\n", r);
        return r;
    }

    if ((r = sys_getpriv(&rp->r_priv, rp->r_pub->endpoint)) != OK) {
        panic("unable to synch privilege structure: %d", r);
    }

    clone_rpub_ptr = clone_rp->r_pub;

    *clone_rp = *rp;
    *clone_rpub_ptr = *(rp->r_pub);

    clone_rp->r_pub = clone_rpub_ptr;

    initialize_clone(clone_rp, rp);

    *clone_rpp = clone_rp;
    return OK;
}

/*===========================================================================*
 *			    swap_slot_pointer				     *
 *===========================================================================*/
static void swap_slot_pointer(struct rproc **rpp, struct rproc *src_rp,
    struct rproc *dst_rp)
{
    if (!rpp) {
        return;
    }

    struct rproc *current_rp = *rpp;
    if (current_rp == src_rp) {
        *rpp = dst_rp;
    } else if (current_rp == dst_rp) {
        *rpp = src_rp;
    }
}

/*===========================================================================*
 *				swap_slot				     *
 *===========================================================================*/
void swap_slot(struct rproc **src_rpp, struct rproc **dst_rpp)
{
    if (!src_rpp || !(*src_rpp) || !dst_rpp || !(*dst_rpp)) {
        return;
    }

    struct rproc *src_rp = *src_rpp;
    struct rproc *dst_rp = *dst_rpp;

    if (src_rp == dst_rp) {
        return;
    }

    struct rprocpub *src_rpub = src_rp->r_pub;
    struct rprocpub *dst_rpub = dst_rp->r_pub;

    if (!src_rpub || !dst_rpub) {
        return;
    }

    struct rprocpub temp_rpub = *src_rpub;
    *src_rpub = *dst_rpub;
    *dst_rpub = temp_rpub;

    struct rproc temp_rp = *src_rp;
    *src_rp = *dst_rp;
    *dst_rp = temp_rp;

    struct rprocpub *pub_ptr_temp = src_rp->r_pub;
    src_rp->r_pub = dst_rp->r_pub;
    dst_rp->r_pub = pub_ptr_temp;

    struct rprocupd *upd_ptr_temp = src_rp->r_upd;
    src_rp->r_upd = dst_rp->r_upd;
    dst_rp->r_upd = upd_ptr_temp;

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

    struct rprocupd *prev_rpupd, *rpupd;
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
struct rproc* lookup_slot_by_label(const char *label)
{
    if (!label) {
        return NULL;
    }

    for (int i = 0; i < NR_SYS_PROCS; i++) {
        struct rproc *rp = &rproc[i];
        if ((rp->r_flags & RS_ACTIVE) && rp->r_pub &&
            strcmp(rp->r_pub->label, label) == 0) {
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
    if (pid < 0) {
        return NULL;
    }

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
struct rproc *lookup_slot_by_dev_nr(dev_t dev_nr)
{
    if (dev_nr <= 0) {
        return NULL;
    }

    for (int slot_nr = 0; slot_nr < NR_SYS_PROCS; slot_nr++) {
        struct rproc *rp = &rproc[slot_nr];
        if ((rp->r_flags & RS_IN_USE) && rp->r_pub && (rp->r_pub->dev_nr == dev_nr)) {
            return rp;
        }
    }

    return NULL;
}

/*===========================================================================*
 *			   lookup_slot_by_domain			     *
 *===========================================================================*/
static bool process_supports_domain(const struct rproc *rp, int domain)
{
    if (!rp || !rp->r_pub) {
        return false;
    }

    const struct rprocpub *rpub = rp->r_pub;
    for (int i = 0; i < rpub->nr_domain; i++) {
        if (rpub->domain[i] == domain) {
            return true;
        }
    }

    return false;
}

struct rproc* lookup_slot_by_domain(int domain)
{
/* Lookup a service slot matching the given protocol family. */
    if (domain <= 0) {
        return NULL;
    }

    for (int slot_nr = 0; slot_nr < NR_SYS_PROCS; slot_nr++) {
        struct rproc *rp = &rproc[slot_nr];
        if ((rp->r_flags & RS_IN_USE) && process_supports_domain(rp, domain)) {
            return rp;
        }
    }

    return NULL;
}

/*===========================================================================*
 *			   lookup_slot_by_flags				     *
 *===========================================================================*/
struct rproc* lookup_slot_by_flags(const int flags)
{
    struct rproc *rp;
    
    for (rp = rproc; rp < &rproc[NR_SYS_PROCS]; rp++) {
        if ((rp->r_flags & RS_IN_USE) && (rp->r_flags & flags)) {
            return rp;
        }
    }
    
    return NULL;
}

/*===========================================================================*
 *				alloc_slot				     *
 *===========================================================================*/
int alloc_slot(struct rproc **rpp)
{
    for (struct rproc *rp = rproc; rp < &rproc[NR_SYS_PROCS]; rp++) {
        if (!(rp->r_flags & RS_IN_USE)) {
            *rpp = rp;
            return OK;
        }
    }
    return ENOMEM;
}

/*===========================================================================*
 *				free_slot				     *
 *===========================================================================*/
void free_slot(struct rproc *rp)
{
    if (rp == NULL || rp->r_pub == NULL) {
        return;
    }

    struct rprocpub *rpub = rp->r_pub;

    late_reply(rp, OK);

    if ((rpub->sys_flags & SF_USE_COPY) != 0) {
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
#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <stddef.h>

#define RS_MAX_LABEL_LEN 64 // An assumed value for compilation

static char *get_next_name(const char *ptr, char *name, const char *caller_label)
{
	while (1)
	{
		while (isspace((unsigned char)*ptr))
		{
			ptr++;
		}

		if (*ptr == '\0')
		{
			return NULL;
		}

		const char *name_start = ptr;
		while (*ptr != '\0' && !isspace((unsigned char)*ptr))
		{
			ptr++;
		}

		const size_t len = (size_t)(ptr - name_start);

		if (len > RS_MAX_LABEL_LEN)
		{
			fprintf(stderr,
				"rs:get_next_name: bad ipc list entry '%.*s' for %s: too long\n",
				(int)len, name_start, caller_label);
			continue;
		}

		memcpy(name, name_start, len);
		name[len] = '\0';
		return (char *)ptr;
	}
}

/*===========================================================================*
 *				add_forward_ipc				     *
 *===========================================================================*/
void add_forward_ipc(struct rproc *rp, struct priv *privp)
{
	char name[RS_MAX_LABEL_LEN + 1];
	char *p = rp->r_ipc_list;
	struct rprocpub *rpub = rp->r_pub;

	while ((p = get_next_name(p, name, rpub->label)) != NULL) {
		if (strcmp(name, "SYSTEM") == 0 || strcmp(name, "USER") == 0) {
			endpoint_t endpoint = (strcmp(name, "SYSTEM") == 0) ? SYSTEM : INIT_PROC_NR;
			struct priv priv;
			int r = sys_getpriv(&priv, endpoint);

			if (r < 0) {
				printf("add_forward_ipc: unable to get priv_id for '%s': %d\n", name, r);
			} else {
#if PRIV_DEBUG
				printf("  RS: add_forward_ipc: setting sendto bit for %d...\n", endpoint);
#endif
				set_sys_bit(privp->s_ipc_to, priv.s_id);
			}
		} else {
			struct rproc *rrp;
			for (rrp = BEG_RPROC_ADDR; rrp < END_RPROC_ADDR; rrp++) {
				if ((rrp->r_flags & RS_IN_USE) &&
					(strcmp(rrp->r_pub->proc_name, name) == 0)) {
#if PRIV_DEBUG
					printf("  RS: add_forward_ipc: setting"
						" sendto bit for %d...\n",
						rrp->r_pub->endpoint);
#endif
					set_sys_bit(privp->s_ipc_to, rrp->r_priv.s_id);
				}
			}
		}
	}
}


/*===========================================================================*
 *				add_backward_ipc			     *
 *===========================================================================*/
void add_backward_ipc(struct rproc *rp, struct priv *privp)
{
	const char *proc_name = rp->r_pub->proc_name;
	const int is_sys_proc = (privp->s_flags & SYS_PROC);

	for (struct rproc *rrp = BEG_RPROC_ADDR; rrp < END_RPROC_ADDR; rrp++) {
		if (!(rrp->r_flags & RS_IN_USE) || !rrp->r_ipc_list[0]) {
			continue;
		}

		int grant_permission = 0;
		const struct rprocpub *rrpub = rrp->r_pub;

		if (strcmp(rrp->r_ipc_list, RSS_IPC_ALL) == 0) {
			grant_permission = 1;
		} else if (strcmp(rrp->r_ipc_list, RSS_IPC_ALL_SYS) == 0 && is_sys_proc) {
			grant_permission = 1;
		} else {
			char name[RS_MAX_LABEL_LEN + 1];
			const char *p = rrp->r_ipc_list;
			while ((p = get_next_name(p, name, rrpub->label)) != NULL) {
				if (strcmp(proc_name, name) == 0) {
					grant_permission = 1;
					break;
				}
			}
		}

		if (grant_permission) {
#if PRIV_DEBUG
			printf("  RS: add_backward_ipc: setting sendto bit for %d...\n",
				rrpub->endpoint);
#endif
			set_sys_bit(privp->s_ipc_to, rrp->r_priv.s_id);
		}
	}
}


/*===========================================================================*
 *				init_privs				     *
 *===========================================================================*/
void init_privs(struct rproc *rp, struct priv *privp)
{
	if (!rp || !privp || !rp->r_ipc_list)
	{
		return;
	}

	fill_send_mask(&privp->s_ipc_to, 0);

#if PRIV_DEBUG
	printf("  RS: init_privs: ipc list is '%s'...\n", rp->r_ipc_list);
#endif

	if (strcmp(rp->r_ipc_list, RSS_IPC_ALL) == 0)
	{
		for (int i = 0; i < NR_SYS_PROCS; i++)
		{
			set_sys_bit(privp->s_ipc_to, i);
		}
	}
	else if (strcmp(rp->r_ipc_list, RSS_IPC_ALL_SYS) == 0)
	{
		for (int i = 0; i < NR_SYS_PROCS; i++)
		{
			if (i != USER_PRIV_ID)
			{
				set_sys_bit(privp->s_ipc_to, i);
			}
		}
	}
	else
	{
		add_forward_ipc(rp, privp);
		add_backward_ipc(rp, privp);
	}
}

