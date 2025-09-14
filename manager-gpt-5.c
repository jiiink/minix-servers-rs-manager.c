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
  int s, i, j, num_ipc_filters = 0;
  struct rs_ipc_filter_el (*rs_ipc_filter_els)[IPCF_MAX_ELEMENTS];
  struct rs_ipc_filter_el rs_ipc_filter[IPCF_MAX_ELEMENTS];
  size_t rs_ipc_filter_size = sizeof(rs_ipc_filter);
  ipc_filter_el_t (*ipcf_els_buff)[IPCF_MAX_ELEMENTS] = NULL;
  size_t ipcf_els_buff_size = 0;

  dst_rs_state_data->size = 0;
  dst_rs_state_data->eval_addr = NULL;
  dst_rs_state_data->eval_len = 0;
  dst_rs_state_data->ipcf_els = NULL;
  dst_rs_state_data->ipcf_els_size = 0;

  if (src_rs_state_data->size != sizeof(struct rs_state_data)) {
    return E2BIG;
  }

  if (prepare_state == SEF_LU_STATE_EVAL) {
    if (src_rs_state_data->eval_len == 0 || !src_rs_state_data->eval_addr) {
      return EINVAL;
    }
    dst_rs_state_data->eval_addr = malloc(src_rs_state_data->eval_len + 1);
    dst_rs_state_data->eval_len = src_rs_state_data->eval_len;
    if (!dst_rs_state_data->eval_addr) {
      return ENOMEM;
    }
    s = sys_datacopy(src_e, (vir_bytes)src_rs_state_data->eval_addr,
                     SELF, (vir_bytes)dst_rs_state_data->eval_addr,
                     dst_rs_state_data->eval_len);
    if (s != OK) {
      free(dst_rs_state_data->eval_addr);
      dst_rs_state_data->eval_addr = NULL;
      dst_rs_state_data->eval_len = 0;
      return s;
    }
    *((char *)dst_rs_state_data->eval_addr + dst_rs_state_data->eval_len) = '\0';
    dst_rs_state_data->size = src_rs_state_data->size;
  }

  if (src_rs_state_data->ipcf_els_size % rs_ipc_filter_size) {
    if (dst_rs_state_data->eval_addr) {
      free(dst_rs_state_data->eval_addr);
      dst_rs_state_data->eval_addr = NULL;
      dst_rs_state_data->eval_len = 0;
    }
    return E2BIG;
  }

  rs_ipc_filter_els = src_rs_state_data->ipcf_els;
  num_ipc_filters = src_rs_state_data->ipcf_els_size / rs_ipc_filter_size;
  if (!rs_ipc_filter_els) {
    return OK;
  }

  {
    size_t filters_capacity = (size_t)num_ipc_filters +
                              ((src_e == VM_PROC_NR) ? 1u : 0u);
    if (filters_capacity > SIZE_MAX / IPCF_MAX_ELEMENTS ||
        IPCF_MAX_ELEMENTS > SIZE_MAX / sizeof(ipc_filter_el_t) ||
        filters_capacity * IPCF_MAX_ELEMENTS > SIZE_MAX / sizeof(ipc_filter_el_t)) {
      if (dst_rs_state_data->eval_addr) {
        free(dst_rs_state_data->eval_addr);
        dst_rs_state_data->eval_addr = NULL;
        dst_rs_state_data->eval_len = 0;
      }
      return E2BIG;
    }
    ipcf_els_buff_size = filters_capacity * IPCF_MAX_ELEMENTS * sizeof(ipc_filter_el_t);
  }

  ipcf_els_buff = malloc(ipcf_els_buff_size);
  if (!ipcf_els_buff) {
    if (dst_rs_state_data->eval_addr) {
      free(dst_rs_state_data->eval_addr);
      dst_rs_state_data->eval_addr = NULL;
      dst_rs_state_data->eval_len = 0;
    }
    return ENOMEM;
  }
  memset(ipcf_els_buff, 0, ipcf_els_buff_size);

  for (i = 0; i < num_ipc_filters; i++) {
    s = sys_datacopy(src_e, (vir_bytes)rs_ipc_filter_els[i],
                     SELF, (vir_bytes)rs_ipc_filter, rs_ipc_filter_size);
    if (s != OK) {
      free(ipcf_els_buff);
      if (dst_rs_state_data->eval_addr) {
        free(dst_rs_state_data->eval_addr);
        dst_rs_state_data->eval_addr = NULL;
        dst_rs_state_data->eval_len = 0;
      }
      return s;
    }
    for (j = 0; j < IPCF_MAX_ELEMENTS && rs_ipc_filter[j].flags; j++) {
      endpoint_t m_source = 0;
      int m_type = 0;
      int flags = rs_ipc_filter[j].flags;

      if (flags & IPCF_MATCH_M_TYPE) {
        m_type = rs_ipc_filter[j].m_type;
      }
      if (flags & IPCF_MATCH_M_SOURCE) {
        if (ds_retrieve_label_endpt(rs_ipc_filter[j].m_label, &m_source) != OK) {
          if (!strcmp("ANY_USR", rs_ipc_filter[j].m_label)) {
            m_source = ANY_USR;
          } else if (!strcmp("ANY_SYS", rs_ipc_filter[j].m_label)) {
            m_source = ANY_SYS;
          } else if (!strcmp("ANY_TSK", rs_ipc_filter[j].m_label)) {
            m_source = ANY_TSK;
          } else {
            char *endp = NULL;
            errno = 0;
            long v = strtol(rs_ipc_filter[j].m_label, &endp, 10);
            if (errno || endp == NULL || *endp != '\0') {
              free(ipcf_els_buff);
              if (dst_rs_state_data->eval_addr) {
                free(dst_rs_state_data->eval_addr);
                dst_rs_state_data->eval_addr = NULL;
                dst_rs_state_data->eval_len = 0;
              }
              return ESRCH;
            }
            m_source = (endpoint_t)v;
          }
        }
      }
      ipcf_els_buff[i][j].flags = flags;
      ipcf_els_buff[i][j].m_source = m_source;
      ipcf_els_buff[i][j].m_type = m_type;
    }
  }

  if (src_e == VM_PROC_NR) {
    ipcf_els_buff[i][0].flags = (IPCF_EL_WHITELIST | IPCF_MATCH_M_SOURCE | IPCF_MATCH_M_TYPE);
    ipcf_els_buff[i][0].m_source = RS_PROC_NR;
    ipcf_els_buff[i][0].m_type = VM_RS_UPDATE;
  }

  dst_rs_state_data->size = src_rs_state_data->size;
  dst_rs_state_data->ipcf_els = ipcf_els_buff;
  dst_rs_state_data->ipcf_els_size = ipcf_els_buff_size;

  return OK;
}

/*===========================================================================*
 *			        build_cmd_dep				     *
 *===========================================================================*/
void build_cmd_dep(struct rproc *rp)
{
    int argc = 0;
    char *p;
    size_t args_sz;

    if (rp == NULL) return;
    if (ARGV_ELEMENTS <= 0) { rp->r_argc = 0; return; }

    args_sz = sizeof(rp->r_args);
    if (args_sz > 0) {
        const char *src = rp->r_cmd ? rp->r_cmd : "";
        int n = snprintf(rp->r_args, args_sz, "%s", src);
        if (n < 0) rp->r_args[0] = '\0';
    }

    rp->r_argv[argc++] = rp->r_args;
    p = rp->r_args;

    for (; *p != '\0'; ++p) {
        if (*p == ' ') {
            *p = '\0';
            while (*(p + 1) == ' ') ++p;
            if (*(p + 1) == '\0') break;
            if (argc >= ARGV_ELEMENTS - 1) {
                printf("RS: build_cmd_dep: too many args\n");
                break;
            }
            rp->r_argv[argc++] = p + 1;
        }
    }

    rp->r_argv[argc] = NULL;
    rp->r_argc = argc;
}

/*===========================================================================*
 *				end_srv_init				     *
 *===========================================================================*/
void end_srv_init(struct rproc *rp)
{
    if (rp == NULL) {
        return;
    }

    late_reply(rp, OK);

    if (rp->r_prev_rp != NULL) {
        struct rproc *prev = rp->r_prev_rp;

        if (SRV_IS_UPD_SCHEDULED(prev)) {
            rupdate_upd_move(prev, rp);
        }

        cleanup_service(prev);
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
int kill_service_debug(char *file, int line, struct rproc *rp, char *errstr, int err)
{
    if (errstr != NULL && !shutting_down) {
        printf("RS: %s (error %d)\n", errstr, err);
    }

    if (rp != NULL) {
        rp->r_flags |= RS_EXITING;
        crash_service_debug(file, line, rp);
    }

    return err;
}

/*===========================================================================*
 *			    crash_service_debug				     *
 *===========================================================================*/
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>

int crash_service_debug(char *file, int line, struct rproc *rp)
{
  struct rprocpub *rpub;
  const char *file_str = file ? file : "(unknown)";

  if (rp == NULL || (rpub = rp->r_pub) == NULL) {
    if (rs_verbose) {
      printf("RS: service kill requested at %s:%d (invalid service)\n", file_str, line);
    }
    return EINVAL;
  }

  if (rs_verbose) {
    printf("RS: %s %skilled at %s:%d\n",
           srv_to_string(rp),
           (rp->r_flags & RS_EXITING) ? "lethally " : "",
           file_str,
           line);
  }

  if (rpub->endpoint == RS_PROC_NR) {
    exit(1);
  }

  return sys_kill(rpub->endpoint, SIGKILL);
}

/*===========================================================================*
 *			  cleanup_service_debug				     *
 *===========================================================================*/
static void unlink_service_references(struct rproc *rp) {
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
}

void cleanup_service_debug(const char *file, int line, struct rproc *rp) {
    struct rprocpub *rpub;

    if (rp == NULL) {
        return;
    }

    rpub = rp->r_pub;
    if (rpub == NULL) {
        return;
    }

    if (!(rp->r_flags & RS_DEAD)) {
        if (rs_verbose) {
            printf("RS: %s marked for cleanup at %s:%d\n", srv_to_string(rp), file, line);
        }

        unlink_service_references(rp);
        rp->r_flags |= RS_DEAD;

        sys_privctl(rpub->endpoint, SYS_PRIV_DISALLOW, NULL);
        sys_privctl(rpub->endpoint, SYS_PRIV_CLEAR_IPC_REFS, NULL);
        rp->r_flags &= ~RS_ACTIVE;

        late_reply(rp, OK);
        return;
    }

    {
        int cleanup_script = (rp->r_flags & RS_CLEANUP_SCRIPT) != 0;
        int detach = (rp->r_flags & RS_CLEANUP_DETACH) != 0;

        if (!detach) {
            if (rs_verbose) {
                printf("RS: %s cleaned up at %s:%d\n", srv_to_string(rp), file, line);
            }

            {
                int s = sched_stop(rp->r_scheduler, rpub->endpoint);
                if (s != OK) {
                    printf("RS: warning: scheduler won't give up process: %d\n", s);
                }
            }

            if (rp->r_pid == -1) {
                printf("RS: warning: attempt to kill pid -1!\n");
            } else {
                srv_kill(rp->r_pid, SIGKILL);
            }
        }

        if (cleanup_script) {
            int s;
            rp->r_flags &= ~RS_CLEANUP_SCRIPT;
            s = run_script(rp);
            if (s != OK) {
                printf("RS: warning: cannot run cleanup script: %d\n", s);
            }
        }

        if (detach) {
            detach_service(rp);
        } else {
            if (!(rp->r_flags & RS_REINCARNATE)) {
                free_slot(rp);
            }
        }
    }
}

/*===========================================================================*
 *			     detach_service_debug			     *
 *===========================================================================*/
void detach_service_debug(char *file, int line, struct rproc *rp)
{
  static unsigned long detach_counter = 0;
  char label[RS_MAX_LABEL_LEN];
  struct rprocpub *rpub;

  if (!rp)
    return;

  rpub = rp->r_pub;
  if (!rpub)
    return;

  (void)snprintf(label, sizeof(label), "%.*s", RS_MAX_LABEL_LEN - 1, rpub->label);
  (void)snprintf(rpub->label, RS_MAX_LABEL_LEN, "%lu.%s", ++detach_counter, label);
  (void)ds_publish_label(rpub->label, rpub->endpoint, DSF_OVERWRITE);

  if (rs_verbose)
    printf("RS: %s detached at %s:%d\n", srv_to_string(rp), file, line);

  rp->r_flags = RS_IN_USE | RS_ACTIVE;
  rpub->sys_flags &= ~(SF_CORE_SRV | SF_DET_RESTART);
  rp->r_period = 0;
  rpub->dev_nr = 0;
  rpub->nr_domain = 0;
  (void)sys_privctl(rpub->endpoint, SYS_PRIV_ALLOW, NULL);
}

/*===========================================================================*
 *				create_service				     *
 *===========================================================================*/
int create_service(struct rproc *rp)
{
  int child_proc_nr_e, child_proc_nr_n;
  pid_t child_pid;
  int s;
  int use_copy, has_replica;
  extern char **environ;
  struct rprocpub *rpub;

  if (rp == NULL || rp->r_pub == NULL) return EINVAL;

  rpub = rp->r_pub;
  use_copy = (rpub->sys_flags & SF_USE_COPY) != 0;
  has_replica = (rp->r_old_rp != NULL) ||
                (rp->r_prev_rp && !(rp->r_prev_rp->r_flags & RS_TERMINATED));

  if (!has_replica && (rpub->sys_flags & SF_NEED_REPL)) {
      printf("RS: unable to create service '%s' without a replica\n", rpub->label);
      free_slot(rp);
      return EPERM;
  }

  if (!use_copy && (rpub->sys_flags & SF_NEED_COPY)) {
      printf("RS: unable to create service '%s' without an in-memory copy\n", rpub->label);
      free_slot(rp);
      return EPERM;
  }

  if (!use_copy && (rp->r_cmd == NULL || rp->r_cmd[0] == '\0')) {
      printf("RS: unable to create service '%s' without a copy or command\n", rpub->label);
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

  if ((s = getprocnr(child_pid, &child_proc_nr_e)) != 0)
      panic("unable to get child endpoint: %d", s);

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

  if ((s = sys_privctl(child_proc_nr_e, SYS_PRIV_SET_SYS, &rp->r_priv)) != OK
      || (s = sys_getpriv(&rp->r_priv, child_proc_nr_e)) != OK) {
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

  if (use_copy) {
      if (rs_verbose) printf("RS: %s uses an in-memory copy\n", srv_to_string(rp));
  } else {
      s = read_exec(rp);
      if (s != OK) {
          printf("RS: read_exec failed: %d\n", s);
          cleanup_service(rp);
          vm_memctl(RS_PROC_NR, VM_RS_MEM_PIN, 0, 0);
          return s;
      }
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
      s = vm_memctl(rpub->endpoint, VM_RS_MEM_PIN, 0, 0);
      if (s != OK) {
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
      s = vm_memctl(rpub->endpoint, VM_RS_MEM_MAKE_VM, 0, 0);
      if (s != OK) {
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
int clone_service(struct rproc *rp, int instance_flag, int init_flags)
{
  struct rproc *replica_rp = NULL;
  struct rprocpub *replica_rpub = NULL;
  struct rproc **rp_link = NULL;
  struct rproc **replica_link = NULL;
  struct rproc *rs_rp;
  int r;

  if (rp == NULL || rp->r_pub == NULL) return EINVAL;

  if (rs_verbose) printf("RS: %s creating a replica\n", srv_to_string(rp));

  if (rp->r_pub->endpoint == VM_PROC_NR && instance_flag == LU_SYS_PROC && rp->r_next_rp) {
      cleanup_service_now(rp->r_next_rp);
      rp->r_next_rp = NULL;
  }

  r = clone_slot(rp, &replica_rp);
  if (r != OK || replica_rp == NULL) return (r != OK) ? r : EFAULT;
  replica_rpub = replica_rp->r_pub;
  if (replica_rpub == NULL) return EFAULT;

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
      rs_rp = rproc_ptr[_ENDPOINT_P(RS_PROC_NR)];
      r = update_sig_mgrs(rs_rp, SELF, replica_rpub->endpoint);
      if (r == OK) r = update_sig_mgrs(replica_rp, SELF, NONE);
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
int publish_service(rp)
struct rproc *rp;
{
  int r;
  const struct rprocpub *rpub;
  struct rs_pci pci_acl;

  rpub = rp->r_pub;

  r = ds_publish_label(rpub->label, rpub->endpoint, DSF_OVERWRITE);
  if (r != OK) {
      return kill_service(rp, "ds_publish_label call failed", r);
  }

  if (rpub->dev_nr > 0 || rpub->nr_domain > 0) {
      (void)setuid(0);

      r = mapdriver(rpub->label, rpub->dev_nr, rpub->domain, rpub->nr_domain);
      if (r != OK) {
          return kill_service(rp, "couldn't map driver", r);
      }
  }

#if USE_PCI
  if (rpub->pci_acl.rsp_nr_device || rpub->pci_acl.rsp_nr_class) {
      pci_acl = rpub->pci_acl;
      snprintf(pci_acl.rsp_label, sizeof(pci_acl.rsp_label), "%s", rpub->label);
      pci_acl.rsp_endpoint = rpub->endpoint;

      r = pci_set_acl(&pci_acl);
      if (r != OK) {
          return kill_service(rp, "pci_set_acl call failed", r);
      }
  }
#endif /* USE_PCI */

  if (rpub->devman_id != 0) {
      endpoint_t ep;
      message m;
      memset(&m, 0, sizeof(m));

      r = ds_retrieve_label_endpt("devman", &ep);
      if (r != OK) {
          return kill_service(rp, "devman not running?", r);
      }
      m.m_type = DEVMAN_BIND;
      m.DEVMAN_ENDPOINT  = rpub->endpoint;
      m.DEVMAN_DEVICE_ID = rpub->devman_id;
      r = ipc_sendrec(ep, &m);
      if (r != OK || m.DEVMAN_RESULT != OK) {
          return kill_service(rp, "devman bind device failed", r);
      }
  }

  if(rs_verbose)
      printf("RS: %s published\n", srv_to_string(rp));

  return OK;
}

/*===========================================================================*
 *			      unpublish_service				     *
 *===========================================================================*/
int unpublish_service(struct rproc *rp)
{
    struct rprocpub *rpub;
    int r, result;
    message m;

    if (rp == NULL) {
        return EINVAL;
    }

    rpub = rp->r_pub;
    if (rpub == NULL) {
        return EINVAL;
    }

    result = OK;

    r = ds_delete_label(rpub->label);
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
#endif /* USE_PCI */

    if (rpub->devman_id != 0) {
        endpoint_t ep;
        memset(&m, 0, sizeof(m));

        r = ds_retrieve_label_endpt("devman", &ep);
        if (r != OK) {
            printf("RS: devman not running?");
        } else {
            m.m_type = DEVMAN_UNBIND;
            m.DEVMAN_ENDPOINT = rpub->endpoint;
            m.DEVMAN_DEVICE_ID = rpub->devman_id;
            r = ipc_sendrec(ep, &m);
            if (r != OK || m.DEVMAN_RESULT != OK) {
                printf("RS: devman unbind device failed");
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
int run_service(struct rproc *rp, int init_type, int init_flags)
{
  int s;
  const struct rprocpub *rpub;

  if (rp == NULL || rp->r_pub == NULL)
    return EINVAL;

  rpub = rp->r_pub;

  s = sys_privctl(rpub->endpoint, SYS_PRIV_ALLOW, NULL);
  if (s != OK)
    return kill_service(rp, "unable to allow the service to run", s);

  s = init_service(rp, init_type, init_flags);
  if (s != OK)
    return kill_service(rp, "unable to initialize service", s);

  if (rs_verbose)
    printf("RS: %s allowed to run\n", srv_to_string(rp));

  return OK;
}

/*===========================================================================*
 *				start_service				     *
 *===========================================================================*/
int start_service(struct rproc *rp, int init_flags)
{
    int r;
    const struct rprocpub *rpub;

    if (rp == NULL) {
        return EINVAL;
    }

    rpub = rp->r_pub;

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
    if (r != OK) {
        return r;
    }

    if (rs_verbose) {
        printf("RS: %s started with major %d\n", srv_to_string(rp),
               rpub ? rpub->dev_nr : 0);
    }

    return OK;
}

/*===========================================================================*
 *				stop_service				     *
 *===========================================================================*/
void stop_service(struct rproc *rp, int how)
{
    struct rprocpub *rpub;
    int signo;

    if (rp == NULL)
        return;

    rpub = rp->r_pub;
    if (rpub == NULL)
        return;

    if (rs_verbose) {
        const char *name = srv_to_string(rp);
        printf("RS: %s signaled with SIGTERM\n", name ? name : "(null)");
    }

    signo = (rpub->endpoint != RS_PROC_NR) ? SIGTERM : SIGHUP;

    rp->r_flags |= how;
    (void) sys_kill(rpub->endpoint, signo);
    rp->r_stop_tm = getticks();
}

/*===========================================================================*
 *			      activate_service				     *
 *===========================================================================*/
void activate_service(struct rproc *rp, struct rproc *ex_rp)
{
    if (rp == NULL) {
        return;
    }

    if (ex_rp != NULL && (ex_rp->r_flags & RS_ACTIVE) != 0) {
        ex_rp->r_flags &= ~RS_ACTIVE;
        if (rs_verbose) {
            printf("RS: %s becomes inactive\n", srv_to_string(ex_rp));
        }
    }

    if ((rp->r_flags & RS_ACTIVE) == 0) {
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
  struct rproc *rp = NULL;
  int status;
  int restarts;

  status = clone_slot(old_rp, &rp);
  if (status != OK || rp == NULL) {
      printf("RS: Failed to clone the slot: %d\n", status);
      return;
  }

  rp->r_flags = RS_IN_USE;

  if (rp->r_pub != NULL) {
      int idx = _ENDPOINT_P(rp->r_pub->endpoint);
      if (idx >= 0) {
          rproc_ptr[idx] = NULL;
      }
  }

  restarts = rp->r_restarts;
  (void)start_service(rp, SEF_INIT_FRESH);
  rp->r_restarts = restarts + 1;
}

/*===========================================================================*
 *			      terminate_service				     *
 *===========================================================================*/
void terminate_service(struct rproc *rp)
{
  struct rproc **rps = NULL;
  struct rprocpub *rpub;
  unsigned int sys_flags;
  int nr_rps = 0;
  int norestart = 0;
  int i, r;

  if (!rp || !(rpub = rp->r_pub))
    return;

  sys_flags = rpub->sys_flags;

  if (rs_verbose)
    printf("RS: %s terminated\n", srv_to_string(rp));

  if (rp->r_flags & RS_INITIALIZING) {
    if (SRV_IS_UPDATING(rp)) {
      printf("RS: update failed: state transfer failed. Rolling back...\n");
      end_update(rp->r_init_err, RS_REPLY);
      rp->r_init_err = ERESTART;
      return;
    }

    if (sys_flags & SF_NO_BIN_EXP) {
      if (rs_verbose)
        printf("RS: service '%s' exited during initialization; refreshing\n", rpub->label);
      rp->r_flags |= RS_REFRESHING;
    } else {
      if (rs_verbose)
        printf("RS: service '%s' exited during initialization; exiting\n", rpub->label);
      rp->r_flags |= RS_EXITING;
    }
  }

  if (RUPDATE_IS_UPDATING()) {
    printf("RS: aborting the update after a crash...\n");
    abort_update_proc(ERESTART);
  }

  norestart = !(rp->r_flags & RS_EXITING) && (sys_flags & SF_NORESTART);
  if (norestart) {
    rp->r_flags |= RS_EXITING;

    if ((sys_flags & SF_DET_RESTART) && (rp->r_restarts < MAX_DET_RESTART))
      rp->r_flags |= RS_CLEANUP_DETACH;

    if (rp->r_script[0] != '\0')
      rp->r_flags |= RS_CLEANUP_SCRIPT;
  }

  if (rp->r_flags & RS_EXITING) {
    if ((sys_flags & SF_CORE_SRV) && !shutting_down) {
      printf("core system service died: %s\n", srv_to_string(rp));
      _exit(1);
    }

    if (SRV_IS_UPD_SCHEDULED(rp)) {
      printf("RS: aborting the scheduled update, one of the services part of it is exiting...\n");
      abort_update_proc(EDEADSRCDST);
    }

    r = (rp->r_caller_request == RS_DOWN ||
        (rp->r_caller_request == RS_REFRESH && norestart)) ? OK : EDEADEPT;
    late_reply(rp, r);

    unpublish_service(rp);

    get_service_instances(rp, &rps, &nr_rps);
    if (rps && nr_rps > 0) {
      for (i = 0; i < nr_rps; i++)
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
      if (!(sys_flags & SF_NO_BIN_EXP)) {
        rp->r_backoff = 1 << MIN(rp->r_restarts, (BACKOFF_BITS - 2));
        rp->r_backoff = MIN(rp->r_backoff, MAX_BACKOFF);
        if ((sys_flags & SF_USE_COPY) && rp->r_backoff > 1)
          rp->r_backoff = 1;
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
static int run_script(struct rproc *rp)
{
	int r, endpoint;
	pid_t pid;
	const char *reason;
	char incarnation_str[20];
	char *envp[] = { NULL };
	struct rprocpub *rpub;

	rpub = rp->r_pub;

	if (rp->r_flags & RS_REFRESHING)
		reason = "restart";
	else if (rp->r_flags & RS_NOPINGREPLY)
		reason = "no-heartbeat";
	else
		reason = "terminated";

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
		char *argv[] = { "sh", rp->r_script, rpub->label, (char *)reason, incarnation_str, NULL };
		execve(_PATH_BSHELL, argv, envp);
		printf("RS: run_script: execl '%s' failed: %s\n", rp->r_script, strerror(errno));
		_exit(1);
	} else {
		if ((r = getprocnr(pid, &endpoint)) != 0)
			panic("unable to get child endpoint: %d", r);
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
	}
	return OK;
}

/*===========================================================================*
 *			      restart_service				     *
 *===========================================================================*/
void restart_service(struct rproc *rp)
{
  int r;
  struct rproc *replica_rp;

  if (rp == NULL) {
    return;
  }

  late_reply(rp, OK);

  if (rp->r_script[0] != '\0') {
    r = run_script(rp);
    if (r != OK) {
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
    if (replica_rp == NULL) {
      kill_service(rp, "unable to clone service", EINVAL);
      return;
    }
  }

  r = update_service(&rp, &replica_rp, RS_SWAP, 0);
  if (r != OK) {
    kill_service(rp, "unable to update into new replica", r);
    return;
  }

  r = run_service(replica_rp, SEF_INIT_RESTART, 0);
  if (r != OK) {
    kill_service(rp, "unable to let the replica run", r);
    return;
  }

  if (rp->r_pub && (rp->r_pub->sys_flags & SF_DET_RESTART) && (rp->r_restarts < MAX_DET_RESTART)) {
    rp->r_flags |= RS_CLEANUP_DETACH;
  }

  if (rs_verbose) {
    printf("RS: %s restarted into %s\n", srv_to_string(rp), srv_to_string(replica_rp));
  }
}

/*===========================================================================*
 *		         inherit_service_defaults			     *
 *===========================================================================*/
void inherit_service_defaults(struct rproc *def_rp, struct rproc *rp)
{
    if (def_rp == NULL || rp == NULL) {
        return;
    }
    if (def_rp->r_pub == NULL || rp->r_pub == NULL) {
        return;
    }

    const struct rprocpub *def_rpub = def_rp->r_pub;
    struct rprocpub *rpub = rp->r_pub;

    rpub->dev_nr = def_rpub->dev_nr;

    rpub->nr_domain = def_rpub->nr_domain;
    if (def_rpub->nr_domain > 0) {
        int i;
        for (i = 0; i < def_rpub->nr_domain; i++) {
            rpub->domain[i] = def_rpub->domain[i];
        }
    }

    rpub->pci_acl = def_rpub->pci_acl;

    rpub->sys_flags = (rpub->sys_flags & ~IMM_SF) | (def_rpub->sys_flags & IMM_SF);
    rp->r_priv.s_flags = (rp->r_priv.s_flags & ~IMM_F) | (def_rp->r_priv.s_flags & IMM_F);

    rp->r_priv.s_trap_mask = def_rp->r_priv.s_trap_mask;
}

/*===========================================================================*
 *		           get_service_instances			     *
 *===========================================================================*/
void get_service_instances(struct rproc *rp, struct rproc ***rps, int *length)
{
    enum { MAX_INSTANCES = 5 };
    static struct rproc *instances[MAX_INSTANCES];
    size_t i, nr_instances = 0;

    for (i = 0; i < MAX_INSTANCES; ++i) {
        instances[i] = NULL;
    }

    if (rp != NULL) {
        struct rproc *candidates[MAX_INSTANCES] = {
            rp,
            rp->r_prev_rp,
            rp->r_next_rp,
            rp->r_old_rp,
            rp->r_new_rp
        };

        for (i = 0; i < MAX_INSTANCES && nr_instances < MAX_INSTANCES; ++i) {
            if (candidates[i] != NULL) {
                instances[nr_instances++] = candidates[i];
            }
        }
    }

    if (rps != NULL) {
        *rps = instances;
    }
    if (length != NULL) {
        *length = (int)nr_instances;
    }
}

/*===========================================================================*
 *				share_exec				     *
 *===========================================================================*/
void share_exec(struct rproc *rp_dst, struct rproc *rp_src)
{
    if (rp_dst == NULL || rp_src == NULL) {
        if (rs_verbose) {
            const char *dst = (rp_dst != NULL) ? srv_to_string(rp_dst) : "(null)";
            const char *src = (rp_src != NULL) ? srv_to_string(rp_src) : "(null)";
            printf("RS: cannot share exec image: dst=%s src=%s\n", dst, src);
        }
        return;
    }

    if (rs_verbose) {
        const char *dst_str = srv_to_string(rp_dst);
        const char *src_str = srv_to_string(rp_src);
        printf("RS: %s shares exec image with %s\n", dst_str, src_str);
    }

    rp_dst->r_exec_len = rp_src->r_exec_len;
    rp_dst->r_exec = rp_src->r_exec;
}

/*===========================================================================*
 *				read_exec				     *
 *===========================================================================*/
int read_exec(rp)
struct rproc *rp;
{
  const char *e_name;
  struct stat sb;
  int fd;

  if (rp == NULL || rp->r_pub == NULL || rp->r_pub->label == NULL ||
      rp->r_argv == NULL || rp->r_argv[0] == NULL)
      return EINVAL;

  e_name = rp->r_argv[0];
  if (rs_verbose)
      printf("RS: service '%s' reads exec image from: %s\n", rp->r_pub->label, e_name);

  fd = open(e_name, O_RDONLY);
  if (fd == -1)
      return -errno;

  if (fstat(fd, &sb) != 0) {
      int saved = errno;
      close(fd);
      return -saved;
  }

  if (sb.st_size < (off_t)sizeof(Elf_Ehdr)) {
      close(fd);
      return ENOEXEC;
  }

  if (sb.st_size < 0 || (off_t)(size_t)sb.st_size != sb.st_size) {
      close(fd);
      return EFBIG;
  }

  rp->r_exec_len = (size_t)sb.st_size;
  rp->r_exec = malloc(rp->r_exec_len);
  if (rp->r_exec == NULL) {
      printf("RS: read_exec: unable to allocate %zu bytes\n", rp->r_exec_len);
      close(fd);
      return ENOMEM;
  }

  {
      size_t total = 0;
      while (total < rp->r_exec_len) {
          ssize_t r = read(fd, (char *)rp->r_exec + total, rp->r_exec_len - total);
          if (r > 0) {
              total += (size_t)r;
              continue;
          }
          if (r == 0) {
              printf("RS: read_exec: read failed %zd, errno %d\n", (ssize_t)total, EIO);
              close(fd);
              free_exec(rp);
              return EIO;
          }
          if (errno == EINTR)
              continue;

          {
              int e = errno;
              printf("RS: read_exec: read failed %zd, errno %d\n", r, e);
              close(fd);
              free_exec(rp);
              return -e;
          }
      }
  }

  close(fd);
  return OK;
}

/*===========================================================================*
 *				free_exec				     *
 *===========================================================================*/
void free_exec(struct rproc *rp)
{
    int slot_nr;
    int has_shared_exec = 0;
    struct rproc *other_rp = NULL;
    void *exec_ptr;

    if (rp == NULL) {
        return;
    }

    exec_ptr = rp->r_exec;

    for (slot_nr = 0; slot_nr < NR_SYS_PROCS; slot_nr++) {
        struct rproc *candidate = &rproc[slot_nr];
        if ((candidate->r_flags & RS_IN_USE) &&
            candidate != rp &&
            candidate->r_exec == exec_ptr) {
            has_shared_exec = 1;
            other_rp = candidate;
            break;
        }
    }

    if (!has_shared_exec) {
        if (rs_verbose)
            printf("RS: %s frees exec image\n", srv_to_string(rp));
        free(exec_ptr);
    } else {
        if (rs_verbose)
            printf("RS: %s no longer sharing exec image with %s\n",
                   srv_to_string(rp), srv_to_string(other_rp));
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
int clone_slot(struct rproc *rp, struct rproc **clone_rpp)
{
  int r;
  struct rproc *clone_rp;
  struct rprocpub *rpub, *clone_rpub;

  if (clone_rpp == NULL || rp == NULL) {
      return EINVAL;
  }
  *clone_rpp = NULL;

  r = alloc_slot(&clone_rp);
  if (r != OK) {
      printf("RS: clone_slot: unable to allocate a new slot: %d\n", r);
      return r;
  }

  rpub = rp->r_pub;
  clone_rpub = clone_rp->r_pub;

  if ((r = sys_getpriv(&(rp->r_priv), rpub->endpoint)) != OK) {
      panic("unable to synch privilege structure: %d", r);
  }

  *clone_rp = *rp;
  *clone_rpub = *rpub;

  clone_rp->r_init_err = ERESTART;
  clone_rp->r_flags &= ~RS_ACTIVE;
  clone_rp->r_pid = -1;
  clone_rpub->endpoint = -1;
  clone_rp->r_pub = clone_rpub;
  build_cmd_dep(clone_rp);
  if ((clone_rpub->sys_flags & SF_USE_COPY) != 0) {
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
static void swap_slot_pointer(struct rproc **rpp, struct rproc *src_rp, struct rproc *dst_rp)
{
    if (rpp == NULL) {
        return;
    }

    struct rproc *current = *rpp;

    if (current == src_rp) {
        *rpp = dst_rp;
        return;
    }

    if (current == dst_rp) {
        *rpp = src_rp;
    }
}

/*===========================================================================*
 *				swap_slot				     *
 *===========================================================================*/
void swap_slot(struct rproc **src_rpp, struct rproc **dst_rpp)
{
  struct rproc *src_rp, *dst_rp;
  struct rprocpub *src_rpub, *dst_rpub;
  struct rprocupd *src_rupd, *dst_rupd;
  struct rproc tmp_rproc;
  struct rprocpub tmp_rprocpub;
  struct rprocupd *prev_rpupd, *rpupd;

  if (src_rpp == NULL || dst_rpp == NULL)
    return;

  src_rp = *src_rpp;
  dst_rp = *dst_rpp;

  if (src_rp == NULL || dst_rp == NULL || src_rp == dst_rp)
    return;

  src_rpub = src_rp->r_pub;
  dst_rpub = dst_rp->r_pub;
  if (src_rpub == NULL || dst_rpub == NULL)
    return;

  src_rupd = src_rp->r_upd;
  dst_rupd = dst_rp->r_upd;

  tmp_rproc = *src_rp;
  *src_rp = *dst_rp;
  *dst_rp = tmp_rproc;

  tmp_rprocpub = *src_rpub;
  *src_rpub = *dst_rpub;
  *dst_rpub = tmp_rprocpub;

  src_rp->r_pub = src_rpub;
  dst_rp->r_pub = dst_rpub;
  src_rp->r_upd = src_rupd;
  dst_rp->r_upd = dst_rupd;

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

  RUPDATE_ITER(rupdate.first_rpupd, prev_rpupd, rpupd,
    swap_slot_pointer(&rpupd->rp, src_rp, dst_rp);
  );

  swap_slot_pointer(&rproc_ptr[_ENDPOINT_P(src_rpub->endpoint)], src_rp, dst_rp);
  swap_slot_pointer(&rproc_ptr[_ENDPOINT_P(dst_rpub->endpoint)], src_rp, dst_rp);

  *src_rpp = dst_rp;
  *dst_rpp = src_rp;
}

/*===========================================================================*
 *			   lookup_slot_by_label				     *
 *===========================================================================*/
struct rproc* lookup_slot_by_label(char *label)
{
    int slot_nr;
    struct rproc *rp;
    struct rprocpub *rpub;
    const char *rlabel;

    if (label == NULL) {
        return NULL;
    }

    for (slot_nr = 0; slot_nr < NR_SYS_PROCS; slot_nr++) {
        rp = &rproc[slot_nr];

        if ((rp->r_flags & RS_ACTIVE) == 0) {
            continue;
        }

        rpub = rp->r_pub;
        if (rpub == NULL) {
            continue;
        }

        rlabel = rpub->label;
        if (rlabel == NULL) {
            continue;
        }

        if (strcmp(rlabel, label) == 0) {
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
    int slot_nr;

    if (pid < 0) {
        return NULL;
    }

    for (slot_nr = 0; slot_nr < NR_SYS_PROCS; slot_nr++) {
        struct rproc *rp = &rproc[slot_nr];
        if ((rp->r_flags & RS_IN_USE) && rp->r_pid == pid) {
            return rp;
        }
    }

    return NULL;
}

/*===========================================================================*
 *			   lookup_slot_by_dev_nr			     *
 *===========================================================================*/
struct rproc* lookup_slot_by_dev_nr(dev_t dev_nr)
{
  int slot_nr;
  struct rproc *rp;
  struct rprocpub *rpub;

  if (dev_nr <= 0) {
    return NULL;
  }

  for (slot_nr = 0; slot_nr < NR_SYS_PROCS; slot_nr++) {
    rp = &rproc[slot_nr];
    if (!(rp->r_flags & RS_IN_USE)) {
      continue;
    }
    rpub = rp->r_pub;
    if (rpub != NULL && rpub->dev_nr == dev_nr) {
      return rp;
    }
  }

  return NULL;
}

/*===========================================================================*
 *			   lookup_slot_by_domain			     *
 *===========================================================================*/
struct rproc* lookup_slot_by_domain(int domain)
{
    if (domain <= 0) {
        return NULL;
    }

    for (int slot_nr = 0; slot_nr < NR_SYS_PROCS; slot_nr++) {
        struct rproc *rp = &rproc[slot_nr];

        if ((rp->r_flags & RS_IN_USE) == 0) {
            continue;
        }

        struct rprocpub *rpub = rp->r_pub;
        if (rpub == NULL) {
            continue;
        }

        if (rpub->nr_domain <= 0) {
            continue;
        }

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
struct rproc* lookup_slot_by_flags(int flags)
{
    if (flags == 0) {
        return NULL;
    }

    for (int slot_nr = 0; slot_nr < NR_SYS_PROCS; slot_nr++) {
        struct rproc *rp = &rproc[slot_nr];
        int rf = rp->r_flags;
        if ((rf & RS_IN_USE) != 0 && (rf & flags) != 0) {
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
    int slot_nr;

    if (rpp == NULL) {
        return EINVAL;
    }

    for (slot_nr = 0; slot_nr < NR_SYS_PROCS; ++slot_nr) {
        struct rproc *rp = &rproc[slot_nr];
        if (!(rp->r_flags & RS_IN_USE)) {
            *rpp = rp;
            return OK;
        }
    }

    *rpp = NULL;
    return ENOMEM;
}

/*===========================================================================*
 *				free_slot				     *
 *===========================================================================*/
void free_slot(struct rproc *rp)
{
  struct rprocpub *rpub;

  if (rp == NULL) {
    return;
  }

  rpub = rp->r_pub;

  late_reply(rp, OK);

  if (rpub != NULL && (rpub->sys_flags & SF_USE_COPY)) {
    free_exec(rp);
  }

  rp->r_flags = 0;
  rp->r_pid = -1;

  if (rpub != NULL) {
    rpub->in_use = FALSE;
    rproc_ptr[_ENDPOINT_P(rpub->endpoint)] = NULL;
  }
}


/*===========================================================================*
 *				get_next_name				     *
 *===========================================================================*/
static char *get_next_name(char *ptr, char *name, char *caller_label)
{
	char *p, *q;
	size_t len;

	if (ptr == NULL || name == NULL || caller_label == NULL) {
		return NULL;
	}

	p = ptr;
	while (*p != '\0') {
		while (*p != '\0' && isspace((unsigned char)*p)) {
			p++;
		}

		if (*p == '\0') {
			break;
		}

		q = p;
		while (*q != '\0' && !isspace((unsigned char)*q)) {
			q++;
		}

		len = (size_t)(q - p);
		if (len == 0) {
			p = q;
			continue;
		}
		if (len > RS_MAX_LABEL_LEN) {
			printf("rs:get_next_name: bad ipc list entry '%.*s' for %s: too long\n",
			       (int)len, p, caller_label);
			p = q;
			continue;
		}

		memcpy(name, p, len);
		name[len] = '\0';
		return q;
	}

	return NULL;
}

/*===========================================================================*
 *				add_forward_ipc				     *
 *===========================================================================*/
void add_forward_ipc(struct rproc *rp, struct priv *privp)
{
	char name[RS_MAX_LABEL_LEN + 1];
	char *p;
	struct rproc *rrp;
	struct rprocpub *rpub;

	if (rp == NULL || privp == NULL)
		return;

	rpub = rp->r_pub;
	if (rpub == NULL)
		return;

	p = rp->r_ipc_list;
	if (p == NULL)
		return;

	while ((p = get_next_name(p, name, rpub->label)) != NULL) {
		int is_system = (strcmp(name, "SYSTEM") == 0);
		int is_user = (strcmp(name, "USER") == 0);

		if (is_system || is_user) {
			endpoint_t endpoint = is_system ? SYSTEM : INIT_PROC_NR;
			struct priv priv;
			int r = sys_getpriv(&priv, endpoint);

			if (r < 0) {
				printf("add_forward_ipc: unable to get priv_id for '%s': %d\n", name, r);
				continue;
			}

#if PRIV_DEBUG
			printf("  RS: add_forward_ipc: setting sendto bit for %d...\n", endpoint);
#endif
			set_sys_bit(privp->s_ipc_to, priv.s_id);
			continue;
		}

		for (rrp = BEG_RPROC_ADDR; rrp < END_RPROC_ADDR; rrp++) {
			if (!(rrp->r_flags & RS_IN_USE))
				continue;
			if (rrp->r_pub == NULL)
				continue;
			if (strcmp(rrp->r_pub->proc_name, name) != 0)
				continue;

#if PRIV_DEBUG
			printf("  RS: add_forward_ipc: setting sendto bit for %d...\n", rrp->r_pub->endpoint);
#endif
			set_sys_bit(privp->s_ipc_to, rrp->r_priv.s_id);
		}
	}
}


/*===========================================================================*
 *				add_backward_ipc			     *
 *===========================================================================*/
void add_backward_ipc(struct rproc *rp, struct priv *privp)
{
	char name[RS_MAX_LABEL_LEN + 1];
	char *p;
	struct rproc *rrp;
	struct rprocpub *rrpub;
	const char *proc_name;
	int priv_id;
	int is_ipc_all, is_ipc_all_sys, is_target_sys;

	if (rp == NULL || privp == NULL || rp->r_pub == NULL ||
	    rp->r_pub->proc_name == NULL)
		return;

	proc_name = rp->r_pub->proc_name;
	is_target_sys = (privp->s_flags & SYS_PROC) ? 1 : 0;

	for (rrp = BEG_RPROC_ADDR; rrp < END_RPROC_ADDR; rrp++) {
		if (!(rrp->r_flags & RS_IN_USE))
			continue;

		if (!rrp->r_ipc_list[0])
			continue;

		rrpub = rrp->r_pub;
		if (rrpub == NULL)
			continue;

		is_ipc_all = (strcmp(rrp->r_ipc_list, RSS_IPC_ALL) == 0);
		is_ipc_all_sys = (strcmp(rrp->r_ipc_list, RSS_IPC_ALL_SYS) == 0);

		if (is_ipc_all || (is_ipc_all_sys && is_target_sys)) {
#if PRIV_DEBUG
			printf("  RS: add_backward_ipc: setting sendto bit for %d...\n",
				rrpub->endpoint);
#endif
			priv_id = rrp->r_priv.s_id;
			set_sys_bit(privp->s_ipc_to, priv_id);
			continue;
		}

		p = rrp->r_ipc_list;

		while ((p = get_next_name(p, name, rrpub->label)) != NULL) {
			if (strcmp(proc_name, name) == 0) {
#if PRIV_DEBUG
				printf("  RS: add_backward_ipc: setting sendto bit for %d...\n",
					rrpub->endpoint);
#endif
				priv_id = rrp->r_priv.s_id;
				set_sys_bit(privp->s_ipc_to, priv_id);
			}
		}
	}
}


/*===========================================================================*
 *				init_privs				     *
 *===========================================================================*/
static int str_equal(const char *a, const char *b)
{
	return (a != NULL && b != NULL && strcmp(a, b) == 0);
}

void init_privs(struct rproc *rp, struct priv *privp)
{
	int i;
	int is_ipc_all = 0, is_ipc_all_sys = 0;
	const char *ipc_list;

	if (rp == NULL || privp == NULL) {
		return;
	}

	fill_send_mask(&privp->s_ipc_to, FALSE);

	ipc_list = rp->r_ipc_list;
	is_ipc_all = str_equal(ipc_list, RSS_IPC_ALL);
	is_ipc_all_sys = str_equal(ipc_list, RSS_IPC_ALL_SYS);

#if PRIV_DEBUG
	printf("  RS: init_privs: ipc list is '%s'...\n", ipc_list ? ipc_list : "(null)");
#endif

	if (!is_ipc_all && !is_ipc_all_sys) {
		add_forward_ipc(rp, privp);
		add_backward_ipc(rp, privp);
		return;
	}

	for (i = 0; i < NR_SYS_PROCS; i++) {
		if (is_ipc_all || i != USER_PRIV_ID)
			set_sys_bit(privp->s_ipc_to, i);
	}
}

