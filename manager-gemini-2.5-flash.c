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
    const struct rs_state_data *src_rs_state_data,
    struct rs_state_data *dst_rs_state_data)
{
  int s = OK;
  void *eval_addr_ptr = NULL;
  ipc_filter_el_t (*ipcf_els_buff_ptr)[IPCF_MAX_ELEMENTS] = NULL;

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

      eval_addr_ptr = malloc(src_rs_state_data->eval_len + 1);
      if (!eval_addr_ptr) {
          return ENOMEM;
      }

      s = sys_datacopy(src_e, (vir_bytes)src_rs_state_data->eval_addr,
                       SELF, (vir_bytes)eval_addr_ptr,
                       src_rs_state_data->eval_len);
      if (s != OK) {
          goto fail;
      }
      *((char*)eval_addr_ptr + src_rs_state_data->eval_len) = '\0';

      dst_rs_state_data->eval_addr = eval_addr_ptr;
      dst_rs_state_data->eval_len = src_rs_state_data->eval_len;
  }

  const size_t rs_ipc_filter_element_size = sizeof(struct rs_ipc_filter_el) * IPCF_MAX_ELEMENTS;
  int num_ipc_filters = 0;

  if (src_rs_state_data->ipcf_els_size > 0) {
      if (src_rs_state_data->ipcf_els_size % rs_ipc_filter_element_size != 0) {
          s = E2BIG;
          goto fail;
      }
      if (!src_rs_state_data->ipcf_els) {
          s = EINVAL;
          goto fail;
      }
      num_ipc_filters = src_rs_state_data->ipcf_els_size / rs_ipc_filter_element_size;
  }

  int additional_filter_set = (src_e == VM_PROC_NR);
  int total_filter_sets = num_ipc_filters + (additional_filter_set ? 1 : 0);
  size_t ipcf_els_buff_size = 0;

  if (total_filter_sets > 0) {
      ipcf_els_buff_size = sizeof(ipc_filter_el_t) * IPCF_MAX_ELEMENTS * total_filter_sets;
      ipcf_els_buff_ptr = malloc(ipcf_els_buff_size);
      if (!ipcf_els_buff_ptr) {
          s = ENOMEM;
          goto fail;
      }
      memset(ipcf_els_buff_ptr, 0, ipcf_els_buff_size);

      struct rs_ipc_filter_el temp_rs_ipc_filter_set[IPCF_MAX_ELEMENTS];

      for (int i = 0; i < num_ipc_filters; i++) {
          s = sys_datacopy(src_e, (vir_bytes)src_rs_state_data->ipcf_els[i],
                           SELF, (vir_bytes)temp_rs_ipc_filter_set, rs_ipc_filter_element_size);
          if (s != OK) {
              goto fail;
          }

          for (int j = 0; j < IPCF_MAX_ELEMENTS && temp_rs_ipc_filter_set[j].flags; j++) {
              endpoint_t m_source = 0;
              int m_type = 0;
              int flags = temp_rs_ipc_filter_set[j].flags;

              if (flags & IPCF_MATCH_M_TYPE) {
                  m_type = temp_rs_ipc_filter_set[j].m_type;
              }

              if (flags & IPCF_MATCH_M_SOURCE) {
                  if (ds_retrieve_label_endpt(temp_rs_ipc_filter_set[j].m_label, &m_source) != OK) {
                      const char *label = temp_rs_ipc_filter_set[j].m_label;
                      if (!strcmp("ANY_USR", label)) {
                          m_source = ANY_USR;
                      } else if (!strcmp("ANY_SYS", label)) {
                          m_source = ANY_SYS;
                      } else if (!strcmp("ANY_TSK", label)) {
                          m_source = ANY_TSK;
                      } else {
                          char *endptr;
                          errno = 0;
                          long val = strtol(label, &endptr, 10);
                          if (errno != 0 || *endptr != '\0') {
                              s = ESRCH;
                              goto fail;
                          }
                          m_source = (endpoint_t)val;
                      }
                  }
              }
              ipcf_els_buff_ptr[i][j].flags = flags;
              ipcf_els_buff_ptr[i][j].m_source = m_source;
              ipcf_els_buff_ptr[i][j].m_type = m_type;
          }
      }

      if (additional_filter_set) {
          ipcf_els_buff_ptr[num_ipc_filters][0].flags = (IPCF_EL_WHITELIST | IPCF_MATCH_M_SOURCE | IPCF_MATCH_M_TYPE);
          ipcf_els_buff_ptr[num_ipc_filters][0].m_source = RS_PROC_NR;
          ipcf_els_buff_ptr[num_ipc_filters][0].m_type = VM_RS_UPDATE;
      }

      dst_rs_state_data->ipcf_els = ipcf_els_buff_ptr;
      dst_rs_state_data->ipcf_els_size = ipcf_els_buff_size;
  }

  dst_rs_state_data->size = src_rs_state_data->size;

  return OK;

fail:
  if (eval_addr_ptr) {
      free(eval_addr_ptr);
  }
  if (ipcf_els_buff_ptr) {
      free(ipcf_els_buff_ptr);
  }
  dst_rs_state_data->size = 0;
  dst_rs_state_data->eval_addr = NULL;
  dst_rs_state_data->eval_len = 0;
  dst_rs_state_data->ipcf_els = NULL;
  dst_rs_state_data->ipcf_els_size = 0;
  return s;
}

/*===========================================================================*
 *			        build_cmd_dep				     *
 *===========================================================================*/
#include <string.h>
#include <assert.h>

void build_cmd_dep(struct rproc *rp)
{
  int arg_count;
  char *cmd_ptr;

  strncpy(rp->r_args, rp->r_cmd, sizeof(rp->r_args) - 1);
  rp->r_args[sizeof(rp->r_args) - 1] = '\0';

  arg_count = 0;
  rp->r_argv[arg_count++] = rp->r_args;
  cmd_ptr = rp->r_args;

  while(*cmd_ptr != '\0') {
      if (*cmd_ptr == ' ') {
          *cmd_ptr = '\0';
          while (*++cmd_ptr == ' ') ;
          if (*cmd_ptr == '\0') {
            break;
          }

          if (arg_count >= ARGV_ELEMENTS - 1) {
              break;
          }
          assert(arg_count < ARGV_ELEMENTS);
          rp->r_argv[arg_count++] = cmd_ptr;
      }
      cmd_ptr ++;
  }
  assert(arg_count < ARGV_ELEMENTS);
  rp->r_argv[arg_count] = NULL;
  rp->r_argc = arg_count;
}

/*===========================================================================*
 *				end_srv_init				     *
 *===========================================================================*/
void end_srv_init(struct rproc *rp)
{
  late_reply(rp, OK);

  if(rp->r_prev_rp) {
      if(SRV_IS_UPD_SCHEDULED(rp->r_prev_rp)) {
          rupdate_upd_move(rp->r_prev_rp, rp);
      }
      cleanup_service(rp->r_prev_rp);
      rp->r_prev_rp = NULL;
      rp->r_restarts += 1;

      if(rs_verbose)
          printf("RS: %s completed restart\n", srv_to_string(rp));
  }
  rp->r_next_rp = NULL;
}

/*===========================================================================*
 *			     kill_service_debug				     *
 *===========================================================================*/
int kill_service_debug(const char *file, int line, struct rproc *rp, const char *errstr, int err)
{
    if (rp == NULL) {
        return err;
    }

    if (errstr != NULL && !shutting_down) {
        printf("RS: %s (error %d)\n", errstr, err);
    }

    rp->r_flags |= RS_EXITING;
    crash_service_debug(file, line, rp);

    return err;
}

/*===========================================================================*
 *			    crash_service_debug				     *
 *===========================================================================*/
int crash_service_debug(char *file, int line, struct rproc *rp) {
  struct rprocpub *rpub;

  if (rp == NULL || rp->r_pub == NULL) {
    return -1;
  }

  rpub = rp->r_pub;

  if (rs_verbose) {
    printf("RS: %s %skilled at %s:%d\n",
           srv_to_string(rp),
           (rp->r_flags & RS_EXITING) ? "lethally " : "",
           file ? file : "<unknown file>",
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
void cleanup_service_debug(char *file, int line, struct rproc *rp)
{
  struct rprocpub *rpub = rp->r_pub;

  if (!(rp->r_flags & RS_DEAD)) {
      if (rs_verbose)
          printf("RS: %s marked for cleanup at %s:%d\n", srv_to_string(rp),
              file, line);

      /* Unlink service the first time. */
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

      /* Make sure the service can no longer run and unblock IPC callers. */
      sys_privctl(rpub->endpoint, SYS_PRIV_DISALLOW, NULL);
      sys_privctl(rpub->endpoint, SYS_PRIV_CLEAR_IPC_REFS, NULL);
      rp->r_flags &= ~RS_ACTIVE;

      /* Send a late reply if there is any pending. */
      late_reply(rp, OK);
  } else {
      /* Subsequent cleanup logic when the service is already marked dead. */
      int cleanup_script_flag = (rp->r_flags & RS_CLEANUP_SCRIPT) != 0;
      int detach_flag = (rp->r_flags & RS_CLEANUP_DETACH) != 0;

      /* Cleanup the service when not detaching. */
      if (!detach_flag) {
          if (rs_verbose)
              printf("RS: %s cleaned up at %s:%d\n", srv_to_string(rp),
                  file, line);

          /* Tell scheduler this process is finished */
          int s_sched_stop;
          if ((s_sched_stop = sched_stop(rp->r_scheduler, rpub->endpoint)) != OK) {
                printf("RS: warning: scheduler won't give up process: %d\n", s_sched_stop);
          }

          /* Ask PM to exit the service */
          if (rp->r_pid == -1) {
              printf("RS: warning: attempt to kill pid -1!\n");
          }
          else {
              srv_kill(rp->r_pid, SIGKILL);
          }
      }

      /* See if we need to run a script now. */
      if (cleanup_script_flag) {
          rp->r_flags &= ~RS_CLEANUP_SCRIPT;
          int s_run_script;
          if ((s_run_script = run_script(rp)) != OK) {
              printf("RS: warning: cannot run cleanup script: %d\n", s_run_script);
          }
      }

      if (detach_flag) {
          /* Detach service when asked to. */
          detach_service(rp);
      }
      else {
          /* Free slot otherwise, unless we're about to reuse it */
          if (!(rp->r_flags & RS_REINCARNATE))
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
  char label[RS_MAX_LABEL_LEN];
  struct rprocpub *rpub;

  rpub = rp->r_pub;

  rpub->label[RS_MAX_LABEL_LEN - 1] = '\0';

  strncpy(label, rpub->label, RS_MAX_LABEL_LEN - 1);
  label[RS_MAX_LABEL_LEN - 1] = '\0';

  snprintf(rpub->label, RS_MAX_LABEL_LEN, "%lu.%s", ++detach_counter, label);
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
int create_service(rp)
struct rproc *rp;
{
  int r = OK;
  int child_proc_nr_e;
  pid_t child_pid;
  int s;
  int use_copy;
  int has_replica;
  extern char **environ;
  struct rprocpub *rpub;
  int child_forked = FALSE;
  int exec_image_read = FALSE;
  int rs_mem_unpin_needed = FALSE;

  rpub = rp->r_pub;
  use_copy = (rpub->sys_flags & SF_USE_COPY);
  has_replica = (rp->r_old_rp || (rp->r_prev_rp && !(rp->r_prev_rp->r_flags & RS_TERMINATED)));

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

  if (!use_copy && !strcmp(rp->r_cmd, "")) {
      printf("RS: unable to create service '%s' without a copy or command\n", rpub->label);
      free_slot(rp);
      return EPERM;
  }

  if (rs_verbose) {
      printf("RS: forking child with srv_fork()...\n");
  }

  child_pid = srv_fork(rp->r_uid, 0);
  if (child_pid < 0) {
      printf("RS: srv_fork() failed (error %d)\n", child_pid);
      free_slot(rp);
      return child_pid;
  }
  child_forked = TRUE;
  rs_mem_unpin_needed = TRUE;

  s = getprocnr(child_pid, &child_proc_nr_e);
  if (s != OK) {
	panic("unable to get child endpoint: %d", s);
  }

  int child_proc_nr_n = _ENDPOINT_P(child_proc_nr_e);
  rp->r_flags = RS_IN_USE;
  rpub->endpoint = child_proc_nr_e;
  rp->r_pid = child_pid;
  rp->r_check_tm = 0;
  rp->r_alive_tm = getticks();
  rp->r_stop_tm = 0;
  rp->r_backoff = 0;
  rproc_ptr[child_proc_nr_n] = rp;
  rpub->in_use = TRUE;

  s = sys_privctl(child_proc_nr_e, SYS_PRIV_SET_SYS, &rp->r_priv);
  if (s == OK) {
    s = sys_getpriv(&rp->r_priv, child_proc_nr_e);
  }
  if (s != OK) {
    printf("RS: unable to set privilege structure: %d\n", s);
    r = ENOMEM;
    goto cleanup_forked;
  }

  s = sched_init_proc(rp);
  if (s != OK) {
    printf("RS: unable to start scheduling: %d\n", s);
    r = s;
    goto cleanup_forked;
  }

  if (!use_copy) {
      if (rs_verbose) {
          printf("RS: %s does not use an in-memory copy, reading exec\n", srv_to_string(rp));
      }
      s = read_exec(rp);
      if (s != OK) {
          printf("RS: read_exec failed: %d\n", s);
          r = s;
          goto cleanup_forked;
      }
      exec_image_read = TRUE;
  } else {
      if (rs_verbose) {
          printf("RS: %s uses an in-memory copy\n", srv_to_string(rp));
      }
  }

  if (rs_verbose) {
        printf("RS: execing child with srv_execve()...\n");
  }
  s = srv_execve(child_proc_nr_e, rp->r_exec, rp->r_exec_len, rpub->proc_name, rp->r_argv, environ);

  if (rs_mem_unpin_needed) {
      vm_memctl(RS_PROC_NR, VM_RS_MEM_PIN, 0, 0);
      rs_mem_unpin_needed = FALSE;
  }

  if (s != OK) {
        printf("RS: srv_execve failed: %d\n", s);
        r = s;
        goto cleanup_forked;
  }

  if (!use_copy && exec_image_read) {
        free_exec(rp);
        exec_image_read = FALSE;
  }

  setuid(0);

  if (rp->r_priv.s_flags & ROOT_SYS_PROC) {
      if (rs_verbose) {
          printf("RS: pinning memory of RS instance %s\n", srv_to_string(rp));
      }

      s = vm_memctl(rpub->endpoint, VM_RS_MEM_PIN, 0, 0);
      if (s != OK) {
          printf("vm_memctl failed: %d\n", s);
          r = s;
          goto cleanup_forked;
      }
  }

  if (rp->r_priv.s_flags & VM_SYS_PROC) {
      struct rproc *rs_rp;
      struct rproc **rs_rps = NULL;
      int i;
      int nr_rs_rps = 0;

      if (rs_verbose) {
          printf("RS: informing VM of instance %s\n", srv_to_string(rp));
      }

      s = vm_memctl(rpub->endpoint, VM_RS_MEM_MAKE_VM, 0, 0);
      if (s != OK) {
          printf("vm_memctl failed: %d\n", s);
          r = s;
          goto cleanup_forked;
      }

      rs_rp = rproc_ptr[_ENDPOINT_P(RS_PROC_NR)];
      get_service_instances(rs_rp, &rs_rps, &nr_rs_rps);
      for (i = 0; i < nr_rs_rps; i++) {
          if (rs_rps[i] != NULL) {
              vm_memctl(rs_rps[i]->r_pub->endpoint, VM_RS_MEM_PIN, 0, 0);
          }
      }
  }

  s = vm_set_priv(rpub->endpoint, &rpub->vm_call_mask[0], TRUE);
  if (s != OK) {
      printf("RS: vm_set_priv failed: %d\n", s);
      r = s;
      goto cleanup_forked;
  }

  if (rs_verbose) {
      printf("RS: %s created\n", srv_to_string(rp));
  }

  return OK;

cleanup_forked:
  if (child_forked) {
      cleanup_service(rp);
  }
  if (exec_image_read) {
      free_exec(rp);
  }
  if (rs_mem_unpin_needed) {
      vm_memctl(RS_PROC_NR, VM_RS_MEM_PIN, 0, 0);
  }
  return r;
}

/*===========================================================================*
 *				clone_service				     *
 *===========================================================================*/
int clone_service(struct rproc *rp, int instance_flag, int init_flags)
{
  struct rproc *replica_rp = NULL;
  struct rprocpub *replica_rpub;
  struct rproc **rp_link = NULL;
  struct rproc **replica_link;
  struct rproc *rs_rp;
  int rs_flags;
  int r;

  if (rs_verbose)
      printf("RS: %s creating a replica\n", srv_to_string(rp));

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
      kill_service(replica_rp, "create_service failed", r);
      goto fail_unlink_parent;
  }

  rs_flags = (ROOT_SYS_PROC | RST_SYS_PROC);
  if ((replica_rp->r_priv.s_flags & rs_flags) == rs_flags) {
      rs_rp = rproc_ptr[_ENDPOINT_P(RS_PROC_NR)];

      r = update_sig_mgrs(rs_rp, SELF, replica_rpub->endpoint);
      if (r == OK) {
          r = update_sig_mgrs(replica_rp, SELF, NONE);
      }
      if (r != OK) {
          kill_service(replica_rp, "update_sig_mgrs failed", r);
          goto fail_unlink_parent;
      }
  }

  return OK;

fail_unlink_parent:
  if (rp_link != NULL && *rp_link == replica_rp) {
      *rp_link = NULL;
  }
  return r;
}

/*===========================================================================*
 *				publish_service				     *
 *===========================================================================*/
int publish_service(struct rproc *rp) {
  int r;
  struct rprocpub *rpub = rp->r_pub;
  struct rs_pci pci_acl_local;
  message m;
  endpoint_t ep;

  r = ds_publish_label(rpub->label, rpub->endpoint, DSF_OVERWRITE);
  if (r != OK) {
    return kill_service(rp, "ds_publish_label call failed", r);
  }

  if (rpub->dev_nr > 0 || rpub->nr_domain > 0) {
    setuid(0);

    if ((r = mapdriver(rpub->label, rpub->dev_nr, rpub->domain,
      rpub->nr_domain)) != OK) {
      return kill_service(rp, "couldn't map driver", r);
    }
  }

#if USE_PCI
  if (rpub->pci_acl.rsp_nr_device || rpub->pci_acl.rsp_nr_class) {
    pci_acl_local = rpub->pci_acl;
    
    strncpy(pci_acl_local.rsp_label, rpub->label, sizeof(pci_acl_local.rsp_label) - 1);
    pci_acl_local.rsp_label[sizeof(pci_acl_local.rsp_label) - 1] = '\0';

    pci_acl_local.rsp_endpoint = rpub->endpoint;

    r = pci_set_acl(&pci_acl_local);
    if (r != OK) {
      return kill_service(rp, "pci_set_acl call failed", r);
    }
  }
#endif

  if (rpub->devman_id != 0) {
    r = ds_retrieve_label_endpt("devman", &ep);
    if (r != OK) {
      return kill_service(rp, "devman not running?", r);
    }

    m.m_type = DEVMAN_BIND;
    m.DEVMAN_ENDPOINT = rpub->endpoint;
    m.DEVMAN_DEVICE_ID = rpub->devman_id;
    
    r = ipc_sendrec(ep, &m);
    if (r != OK || m.DEVMAN_RESULT != OK) {
      return kill_service(rp, "devman bind device failed", r);
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
  struct rprocpub *rpub;
  int r;
  int final_result = OK;
  message m;
  endpoint_t ep;

  rpub = rp->r_pub;

  /* Unregister label with DS. */
  r = ds_delete_label(rpub->label);
  if (r != OK) {
    if (!shutting_down) {
      printf("RS: ds_delete_label failed (error %d)\n", r);
    }
    final_result = r;
  }

  /* No need to inform VFS and VM, cleanup is done on exit automatically. */

#if USE_PCI
  /* If PCI properties are set, inform the PCI driver. */
  if (rpub->pci_acl.rsp_nr_device || rpub->pci_acl.rsp_nr_class) {
    r = pci_del_acl(rpub->endpoint);
    if (r != OK) {
      if (!shutting_down) {
        printf("RS: pci_del_acl failed (error %d)\n", r);
      }
      if (final_result == OK) {
        final_result = r;
      }
    }
  }
#endif /* USE_PCI */

  /* Inform Device Manager to unbind the device */
  if (rpub->devman_id != 0) {
    r = ds_retrieve_label_endpt("devman", &ep);

    if (r != OK) {
      if (!shutting_down) {
        printf("RS: ds_retrieve_label_endpt for 'devman' failed (error %d)\n", r);
      }
      if (final_result == OK) {
        final_result = r;
      }
    } else {
      m.m_type = DEVMAN_UNBIND;
      m.DEVMAN_ENDPOINT = rpub->endpoint;
      m.DEVMAN_DEVICE_ID = rpub->devman_id;
      r = ipc_sendrec(ep, &m);

      if (r != OK || m.DEVMAN_RESULT != OK) {
        if (!shutting_down) {
          printf("RS: devman unbind failed: ipc_sendrec error %d, DEVMAN_RESULT %d\n", r, m.DEVMAN_RESULT);
        }
        if (final_result == OK) {
          final_result = (r != OK ? r : m.DEVMAN_RESULT);
        }
      }
    }
  }

  if (rs_verbose) {
    printf("RS: %s unpublished\n", srv_to_string(rp));
  }

  return final_result;
}

/*===========================================================================*
 *				run_service				     *
 *===========================================================================*/
int run_service(struct rproc *rp, int init_type, int init_flags)
{
  struct rprocpub *rpub;
  int rv;

  rpub = rp->r_pub;

  rv = sys_privctl(rpub->endpoint, SYS_PRIV_ALLOW, NULL);
  if (rv != OK) {
      return kill_service(rp, "unable to allow the service to run", rv);
  }

  rv = init_service(rp, init_type, init_flags);
  if (rv != OK) {
      return kill_service(rp, "unable to initialize service", rv);
  }

  if (rs_verbose) {
      printf("RS: %s allowed to run\n", srv_to_string(rp));
  }

  return OK;
}

/*===========================================================================*
 *				start_service				     *
 *===========================================================================*/
#include <errno.h>

int start_service(struct rproc *rp, int init_flags)
{
  int r;

  if (rp == NULL) {
      return EINVAL;
  }

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
      int dev_nr_to_log = -1;
      if (rp->r_pub != NULL) {
          dev_nr_to_log = rp->r_pub->dev_nr;
      }
      printf("RS: %s started with major %d\n", srv_to_string(rp),
             dev_nr_to_log);
  }

  return OK;
}

/*===========================================================================*
 *				stop_service				     *
 *===========================================================================*/
void stop_service(struct rproc *rp, int how)
{
    if (rp == NULL) {
        fprintf(stderr, "ERROR: stop_service received NULL rproc pointer.\n");
        return;
    }

    struct rprocpub *rpub = rp->r_pub;

    if (rpub == NULL) {
        fprintf(stderr, "ERROR: rproc for %s has NULL r_pub pointer.\n", srv_to_string(rp));
        return;
    }

    int signo;
    int kill_result;

    if (rs_verbose) {
        printf("RS: %s signaled with SIGTERM\n", srv_to_string(rp));
    }

    signo = (rpub->endpoint != RS_PROC_NR) ? SIGTERM : SIGHUP;

    rp->r_flags |= how;
    kill_result = sys_kill(rpub->endpoint, signo);

    if (kill_result == -1) {
        fprintf(stderr, "ERROR: Failed to send signal %d to endpoint %d (%s): %s\n",
                signo, rpub->endpoint, srv_to_string(rp), strerror(errno));
    }

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

    if (ex_rp != NULL && (ex_rp->r_flags & RS_ACTIVE)) {
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
void reincarnate_service(struct rproc *old_rp)
{
  struct rproc *rp;
  int r, restarts;

  r = clone_slot(old_rp, &rp);

  if (r != OK) {
    printf("RS: Failed to clone the slot: %d\n", r);
    return;
  }

  if (rp == NULL) {
    printf("RS: Internal error: clone_slot succeeded but returned NULL rproc.\n");
    return;
  }

  if (rp->r_pub == NULL) {
    printf("RS: Internal error: rproc->r_pub is NULL for newly cloned rproc.\n");
    return;
  }

  rp->r_flags = RS_IN_USE;
  rproc_ptr[_ENDPOINT_P(rp->r_pub->endpoint)] = NULL;

  restarts = rp->r_restarts;
  start_service(rp, SEF_INIT_FRESH);
  rp->r_restarts = restarts + 1;
}

/*===========================================================================*
 *			      terminate_service				     *
 *===========================================================================*/
typedef enum {
    TERM_CONTINUE,
    TERM_EARLY_EXIT
} TerminationAction;

static TerminationAction handle_initialization_phase(struct rproc *rp);
static void apply_norestart_policy(struct rproc *rp, int initial_norestart_flag);
static void perform_exit_actions(struct rproc *rp, int initial_norestart_flag);
static void handle_default_restart_or_backoff(struct rproc *rp);

void terminate_service(struct rproc *rp)
{
    struct rprocpub *rpub = rp->r_pub;

    if (rs_verbose) {
        printf("RS: %s terminated\n", srv_to_string(rp));
    }

    if (rp->r_flags & RS_INITIALIZING) {
        if (handle_initialization_phase(rp) == TERM_EARLY_EXIT) {
            return;
        }
    }

    if (RUPDATE_IS_UPDATING()) {
        printf("RS: aborting the update after a crash...\n");
        abort_update_proc(ERESTART);
    }

    int initial_norestart_flag = (!(rp->r_flags & RS_EXITING) && (rpub->sys_flags & SF_NORESTART));

    apply_norestart_policy(rp, initial_norestart_flag);

    if (rp->r_flags & RS_EXITING) {
        perform_exit_actions(rp, initial_norestart_flag);
    } else if (rp->r_flags & RS_REFRESHING) {
        restart_service(rp);
    } else {
        handle_default_restart_or_backoff(rp);
    }
}

static TerminationAction handle_initialization_phase(struct rproc *rp)
{
    struct rprocpub *rpub = rp->r_pub;

    if (SRV_IS_UPDATING(rp)) {
        printf("RS: update failed: state transfer failed. Rolling back...\n");
        end_update(rp->r_init_err, RS_REPLY);
        rp->r_init_err = ERESTART;
        return TERM_EARLY_EXIT;
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
    return TERM_CONTINUE;
}

static void apply_norestart_policy(struct rproc *rp, int initial_norestart_flag)
{
    struct rprocpub *rpub = rp->r_pub;

    if (initial_norestart_flag) {
        rp->r_flags |= RS_EXITING;

        if ((rpub->sys_flags & SF_DET_RESTART) && (rp->r_restarts < MAX_DET_RESTART)) {
            rp->r_flags |= RS_CLEANUP_DETACH;
        }
        if (rp->r_script[0] != '\0') {
            rp->r_flags |= RS_CLEANUP_SCRIPT;
        }
    }
}

static void perform_exit_actions(struct rproc *rp, int initial_norestart_flag)
{
    struct rprocpub *rpub = rp->r_pub;

    if ((rpub->sys_flags & SF_CORE_SRV) && !shutting_down) {
        printf("core system service died: %s\n", srv_to_string(rp));
        _exit(1);
    }

    if (SRV_IS_UPD_SCHEDULED(rp)) {
        printf("RS: aborting the scheduled update, one of the services part of it is exiting...\n");
        abort_update_proc(EDEADSRCDST);
    }

    int reply_status = ((rp->r_caller_request == RS_DOWN) ||
                        (rp->r_caller_request == RS_REFRESH && initial_norestart_flag))
                       ? OK : EDEADEPT;
    late_reply(rp, reply_status);

    unpublish_service(rp);

    struct rproc **rps_instances;
    int nr_rps_instances;
    get_service_instances(rp, &rps_instances, &nr_rps_instances);
    for (int i = 0; i < nr_rps_instances; i++) {
        cleanup_service(rps_instances[i]);
    }

    if (rp->r_flags & RS_REINCARNATE) {
        rp->r_flags &= ~RS_REINCARNATE;
        reincarnate_service(rp);
    }
}

static void handle_default_restart_or_backoff(struct rproc *rp)
{
    struct rprocpub *rpub = rp->r_pub;

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

/*===========================================================================*
 *				run_script				     *
 *===========================================================================*/
static int run_script(struct rproc *rp)
{
	int r;
	pid_t pid;
	const char *reason;
	char incarnation_str[20];
	char *envp[] = { NULL };
	struct rprocpub *rpub = rp->r_pub;

	if (rp->r_flags & RS_REFRESHING) {
		reason = "restart";
	} else if (rp->r_flags & RS_NOPINGREPLY) {
		reason = "no-heartbeat";
	} else {
		reason = "terminated";
	}

	snprintf(incarnation_str, sizeof(incarnation_str), "%d", rp->r_restarts);

 	if (rs_verbose) {
		printf("RS: %s:\n", srv_to_string(rp));
		printf("RS:     calling script '%s'\n", rp->r_script);
		printf("RS:     reason: '%s'\n", reason);
		printf("RS:     incarnation: '%s'\n", incarnation_str);
	}

	pid = fork();
	switch (pid) {
	case -1:
		return errno;
	case 0:
		execle(_PATH_BSHELL, "sh", rp->r_script, rpub->label, reason,
			incarnation_str, (char*) NULL, envp);
		printf("RS: run_script: execle '%s' failed: %s\n",
			rp->r_script, strerror(errno));
		exit(1);
	default: {
		int endpoint;

		if ((r = getprocnr(pid, &endpoint)) != 0) {
			kill(pid, SIGTERM);
			return kill_service(rp, "unable to get child endpoint", r);
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

		if ((r = vm_memctl(RS_PROC_NR, VM_RS_MEM_PIN, 0, 0)) != OK) {
			return kill_service(rp, "can't re-pin RS memory", r);
		}
	}
	}
	return OK;
}

/*===========================================================================*
 *			      restart_service				     *
 *===========================================================================*/
void restart_service(struct rproc *rp)
{
  struct rproc *replica_process = NULL;
  int result;

  late_reply(rp, OK);

  if (rp->r_script[0] != '\0') {
      result = run_script(rp);
      if (result != OK) {
          kill_service(rp, "unable to run script", errno);
      }
      return;
  }

  if (rp->r_next_rp == NULL) {
      result = clone_service(rp, RST_SYS_PROC, 0);
      if (result != OK) {
          kill_service(rp, "unable to clone service", result);
          return;
      }
  }
  replica_process = rp->r_next_rp;

  result = update_service(&rp, &replica_process, RS_SWAP, 0);
  if (result != OK) {
      kill_service(rp, "unable to update into new replica", result);
      return;
  }

  result = run_service(replica_process, SEF_INIT_RESTART, 0);
  if (result != OK) {
      kill_service(rp, "unable to let the replica run", result);
      return;
  }

  if ((rp->r_pub->sys_flags & SF_DET_RESTART) &&
      (rp->r_restarts < MAX_DET_RESTART)) {
      rp->r_flags |= RS_CLEANUP_DETACH;
  }

  if (rs_verbose) {
      printf("RS: %s restarted into %s\n",
          srv_to_string(rp), srv_to_string(replica_process));
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

  struct rprocpub *def_rpub = def_rp->r_pub;
  struct rprocpub *rpub = rp->r_pub;

  if (def_rpub == NULL || rpub == NULL) {
    return;
  }

  rpub->dev_nr = def_rpub->dev_nr;
  rpub->nr_domain = def_rpub->nr_domain;
  memcpy(rpub->domain, def_rpub->domain, def_rpub->nr_domain * sizeof(int));
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
#include <stdlib.h> // Required for malloc

void get_service_instances(const struct rproc *rp, struct rproc ***rps, int *length)
{
    if (rp == NULL || rps == NULL || length == NULL) {
        if (rps != NULL) {
            *rps = NULL;
        }
        if (length != NULL) {
            *length = 0;
        }
        return;
    }

    struct rproc **instances = (struct rproc **) malloc(5 * sizeof(struct rproc *));
    if (instances == NULL) {
        *rps = NULL;
        *length = 0;
        return;
    }

    int nr_instances = 0;

    instances[nr_instances++] = (struct rproc *)rp;

    if (rp->r_prev_rp) {
        instances[nr_instances++] = rp->r_prev_rp;
    }
    if (rp->r_next_rp) {
        instances[nr_instances++] = rp->r_next_rp;
    }
    if (rp->r_old_rp) {
        instances[nr_instances++] = rp->r_old_rp;
    }
    if (rp->r_new_rp) {
        instances[nr_instances++] = rp->r_new_rp;
    }

    *rps = instances;
    *length = nr_instances;
}

/*===========================================================================*
 *				share_exec				     *
 *===========================================================================*/
void share_exec(struct rproc *rp_dst, struct rproc *rp_src)
{
  if (rp_dst == NULL) {
    fprintf(stderr, "Error: share_exec called with NULL destination rproc pointer.\n");
    return;
  }
  if (rp_src == NULL) {
    fprintf(stderr, "Error: share_exec called with NULL source rproc pointer.\n");
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
int read_exec(rp)
struct rproc *rp;
{
  int r;
  int error_code = 0;
  int fd = -1;
  char *e_name;
  struct stat sb;

  e_name = rp->r_argv[0];
  if (rs_verbose)
      printf("RS: service '%s' reads exec image from: %s\n", rp->r_pub->label, e_name);

  r = stat(e_name, &sb);
  if (r != 0) {
      error_code = errno;
      goto error_exit;
  }

  if (sb.st_size < sizeof(Elf_Ehdr)) {
      error_code = ENOEXEC;
      goto error_exit;
  }

  fd = open(e_name, O_RDONLY);
  if (fd == -1) {
      error_code = errno;
      goto error_exit;
  }

  rp->r_exec_len = (size_t)sb.st_size;
  rp->r_exec = malloc(rp->r_exec_len);
  if (rp->r_exec == NULL) {
      printf("RS: read_exec: unable to allocate %zu bytes\n", rp->r_exec_len);
      error_code = ENOMEM;
      goto error_close_fd;
  }

  r = read(fd, rp->r_exec, rp->r_exec_len);
  if (r == -1) {
      error_code = errno;
      printf("RS: read_exec: read failed %d, errno %d\n", r, error_code);
      goto error_free_exec;
  } else if ((size_t)r != rp->r_exec_len) {
      error_code = EIO;
      printf("RS: read_exec: read failed %d, errno %d\n", r, error_code);
      goto error_free_exec;
  }

  close(fd);
  return OK;

error_free_exec:
  free_exec(rp);
error_close_fd:
  if (fd != -1) {
      close(fd);
  }
error_exit:
  return error_code;
}

/*===========================================================================*
 *				free_exec				     *
 *===========================================================================*/
void free_exec(struct rproc *rp)
{
  bool has_shared_exec = false;
  struct rproc *first_sharer = NULL;

  for (int slot_nr = 0; slot_nr < NR_SYS_PROCS; slot_nr++) {
      struct rproc *current_rp_in_loop = &rproc[slot_nr];
      if ((current_rp_in_loop->r_flags & RS_IN_USE) &&
          (current_rp_in_loop != rp) &&
          (current_rp_in_loop->r_exec == rp->r_exec)) {
          
          has_shared_exec = true;
          first_sharer = current_rp_in_loop;
          break;
      }
  }

  if (!has_shared_exec) {
      if (rs_verbose && rp->r_exec != NULL) {
          printf("RS: %s frees exec image\n", srv_to_string(rp));
      }
      free(rp->r_exec);
  } else {
      if (rs_verbose) {
          printf("RS: %s no longer sharing exec image with %s\n",
              srv_to_string(rp), srv_to_string(first_sharer));
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
int clone_slot(struct rproc *rp, struct rproc **clone_rpp)
{
    int r;
    struct rproc *clone_rp = NULL;
    struct rprocpub *source_rpub = NULL;
    struct rprocpub *allocated_clone_rpub = NULL;

    r = alloc_slot(&clone_rp);
    if (r != OK) {
        printf("RS: clone_slot: unable to allocate a new slot: %d\n", r);
        return r;
    }

    allocated_clone_rpub = clone_rp->r_pub;
    source_rpub = rp->r_pub;

    if ((r = sys_getpriv(&(rp->r_priv), source_rpub->endpoint)) != OK) {
        printf("RS: clone_slot: unable to synch privilege structure: %d\n", r);
        goto cleanup;
    }

    *clone_rp = *rp;

    clone_rp->r_pub = allocated_clone_rpub;

    *allocated_clone_rpub = *source_rpub;

    clone_rp->r_init_err = ERESTART;
    clone_rp->r_flags &= ~RS_ACTIVE;
    clone_rp->r_pid = -1;
    allocated_clone_rpub->endpoint = -1;

    build_cmd_dep(clone_rp);

    if (allocated_clone_rpub->sys_flags & SF_USE_COPY) {
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

cleanup:
    if (clone_rp != NULL) {
        free_slot(clone_rp);
    }
    return r;
}

/*===========================================================================*
 *			    swap_slot_pointer				     *
 *===========================================================================*/
static void swap_slot_pointer(struct rproc **rpp, struct rproc *src_rp,
    struct rproc *dst_rp)
{
  if (rpp == NULL) {
    return;
  }

  if (*rpp == src_rp) {
      *rpp = dst_rp;
  }
  else if (*rpp == dst_rp) {
      *rpp = src_rp;
  }
}

/*===========================================================================*
 *				swap_slot				     *
 *===========================================================================*/
void swap_slot(struct rproc **src_rpp, struct rproc **dst_rpp)
{
  struct rproc *src_rp;
  struct rproc *dst_rp;
  struct rprocpub *src_rpub;
  struct rprocpub *dst_rpub;

  struct rprocpub *src_rp_pub_preserved;
  struct rprocupd *src_rp_upd_preserved;
  struct rprocpub *dst_rp_pub_preserved;
  struct rprocupd *dst_rp_upd_preserved;

  struct rproc temp_rproc;
  struct rprocpub temp_rprocpub;
  struct rproc *temp_slot_ptr;

  struct rprocupd *prev_rpupd;
  struct rprocupd *rpupd;

  src_rp = *src_rpp;
  dst_rp = *dst_rpp;
  src_rpub = src_rp->r_pub;
  dst_rpub = dst_rp->r_pub;

  /* Save r_pub and r_upd pointers; these are fixed to the slot, not part of swappable rproc state. */
  src_rp_pub_preserved = src_rp->r_pub;
  src_rp_upd_preserved = src_rp->r_upd;
  dst_rp_pub_preserved = dst_rp->r_pub;
  dst_rp_upd_preserved = dst_rp->r_upd;

  /* Swap rproc struct contents. This will temporarily overwrite r_pub and r_upd fields. */
  temp_rproc = *src_rp;
  *src_rp = *dst_rp;
  *dst_rp = temp_rproc;

  /* Restore the r_pub and r_upd pointers to their original, slot-fixed values. */
  src_rp->r_pub = src_rp_pub_preserved;
  src_rp->r_upd = src_rp_upd_preserved;
  dst_rp->r_pub = dst_rp_pub_preserved;
  dst_rp->r_upd = dst_rp_upd_preserved;

  /* Swap rprocpub struct contents. */
  temp_rprocpub = *src_rpub;
  *src_rpub = *dst_rpub;
  *dst_rpub = temp_rprocpub;

  /* Rebuild command dependencies. */
  build_cmd_dep(src_rp);
  build_cmd_dep(dst_rp);

  /* Swap local slot pointers using an array for cleaner, more maintainable code. */
  struct rproc **local_ptrs[] = {
      &src_rp->r_prev_rp, &src_rp->r_next_rp, &src_rp->r_old_rp, &src_rp->r_new_rp,
      &dst_rp->r_prev_rp, &dst_rp->r_next_rp, &dst_rp->r_old_rp, &dst_rp->r_new_rp
  };
  size_t num_local_ptrs = sizeof(local_ptrs) / sizeof(local_ptrs[0]);

  for (size_t i = 0; i < num_local_ptrs; ++i) {
      swap_slot_pointer(local_ptrs[i], src_rp, dst_rp);
  }

  /* Swap global slot pointers. RUPDATE_ITER is assumed to manage loop variables internally or use declared ones. */
  RUPDATE_ITER(rupdate.first_rpupd, prev_rpupd, rpupd,
      swap_slot_pointer(&rpupd->rp, src_rp, dst_rp);
  );
  swap_slot_pointer(&rproc_ptr[_ENDPOINT_P(src_rp->r_pub->endpoint)], src_rp, dst_rp);
  swap_slot_pointer(&rproc_ptr[_ENDPOINT_P(dst_rp->r_pub->endpoint)], src_rp, dst_rp);

  /* Adjust input pointers to reflect the swapped slots. */
  temp_slot_ptr = *src_rpp;
  *src_rpp = *dst_rpp;
  *dst_rpp = temp_slot_ptr;
}

/*===========================================================================*
 *			   lookup_slot_by_label				     *
 *===========================================================================*/
struct rproc* lookup_slot_by_label(char *label)
{
  if (label == NULL) {
    return NULL;
  }

  for (int slot_nr = 0; slot_nr < NR_SYS_PROCS; slot_nr++) {
    struct rproc *rp = &rproc[slot_nr];

    if (!(rp->r_flags & RS_ACTIVE)) {
      continue;
    }

    if (rp->r_pub == NULL) {
      continue;
    }
    
    struct rprocpub *rpub = rp->r_pub;

    if (strcmp(rpub->label, label) == 0) {
      return rp;
    }
  }

  return NULL;
}

/*===========================================================================*
 *			   lookup_slot_by_pid				     *
 *===========================================================================*/
struct rproc* lookup_slot_by_pid(const pid_t pid)
{
  int slot_nr;
  struct rproc *rp;

  if (pid < 0) {
      return NULL;
  }

  for (slot_nr = 0; slot_nr < NR_SYS_PROCS; slot_nr++) {
      rp = &rproc[slot_nr];
      if (!(rp->r_flags & RS_IN_USE)) {
          continue;
      }
      if (rp->r_pid == pid) {
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
      if (rpub == NULL) {
          continue;
      }

      if (rpub->dev_nr == dev_nr) {
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
  int i;
  int slot_nr;
  struct rproc *rp;
  struct rprocpub *rpub;

  if (domain <= 0) {
      return NULL;
  }

  for (slot_nr = 0; slot_nr < NR_SYS_PROCS; slot_nr++) {
      rp = &rproc[slot_nr];

      if (!(rp->r_flags & RS_IN_USE)) {
          continue;
      }

      rpub = rp->r_pub;
      if (rpub == NULL) {
          continue;
      }

      if (rpub->nr_domain < 0) {
          continue;
      }

      for (i = 0; i < rpub->nr_domain; i++) {
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
  size_t slot_nr;
  struct rproc *rp;

  if (flags == 0) {
      return NULL;
  }

  for (slot_nr = 0; slot_nr < NR_SYS_PROCS; slot_nr++) {
      rp = &rproc[slot_nr];
      if (!(rp->r_flags & RS_IN_USE)) {
          continue;
      }
      if (rp->r_flags & flags) {
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

  for (slot_nr = 0; slot_nr < NR_SYS_PROCS; slot_nr++) {
      if (!(rproc[slot_nr].r_flags & RS_IN_USE)) {
          *rpp = &rproc[slot_nr];
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
  if (rp == NULL) {
    return;
  }

  struct rprocpub *rpub = rp->r_pub;

  late_reply(rp, OK);

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
static char *get_next_name(char *ptr, char *name, char *caller_label)
{
    if (ptr == NULL || name == NULL) {
        return NULL;
    }

    char *current_pos = ptr;
    char *word_start;
    char *word_end;
    size_t word_len;

    while (*current_pos != '\0') {
        while (*current_pos != '\0' && isspace((unsigned char)*current_pos)) {
            current_pos++;
        }

        if (*current_pos == '\0') {
            break;
        }

        word_start = current_pos;

        word_end = current_pos;
        while (*word_end != '\0' && !isspace((unsigned char)*word_end)) {
            word_end++;
        }

        word_len = word_end - word_start;

        if (word_len > RS_MAX_LABEL_LEN) {
            printf(
                "rs:get_next_name: bad ipc list entry '%.*s' for %s: too long\n",
                (int)word_len, word_start, caller_label ? caller_label : "(null)");
            current_pos = word_end;
            continue;
        }

        memcpy(name, word_start, word_len);
        name[word_len] = '\0';

        return word_end;
    }

    return NULL;
}

/*===========================================================================*
 *				add_forward_ipc				     *
 *===========================================================================*/
#define IPC_TARGET_SYSTEM_STR "SYSTEM"
#define IPC_TARGET_USER_STR "USER"

static void set_ipc_permission_for_endpoint(struct priv *privp, const char *name, endpoint_t target_endpoint) {
    struct priv target_priv;
    int r;
    int priv_id;

    if ((r = sys_getpriv(&target_priv, target_endpoint)) < 0) {
        printf("add_forward_ipc: unable to get priv_id for '%s' (endpoint %d): %d\n", name, target_endpoint, r);
        return;
    }

#if PRIV_DEBUG
    printf("  RS: add_forward_ipc: setting sendto bit for %s (endpoint %d)...\n", name, target_endpoint);
#endif
    priv_id = target_priv.s_id;
    set_sys_bit(privp->s_ipc_to, priv_id);
}

static void set_ipc_permission_for_named_processes(struct priv *privp, const char *target_name) {
    struct rproc *rrp;
    int priv_id;

    for (rrp = BEG_RPROC_ADDR; rrp < END_RPROC_ADDR; rrp++) {
        if (!(rrp->r_flags & RS_IN_USE)) {
            continue;
        }

        if (!strcmp(rrp->r_pub->proc_name, target_name)) {
#if PRIV_DEBUG
            printf("  RS: add_forward_ipc: setting sendto bit for named process '%s' (endpoint %d)...\n", target_name, rrp->r_pub->endpoint);
#endif
            priv_id = rrp->r_priv.s_id;
            set_sys_bit(privp->s_ipc_to, priv_id);
        }
    }
}

void add_forward_ipc(rp, privp)
struct rproc *rp;
struct priv *privp;
{
    char name[RS_MAX_LABEL_LEN + 1];
    char *p;
    struct rprocpub *rpub;

    rpub = rp->r_pub;
    p = rp->r_ipc_list;

    while ((p = get_next_name(p, name, rpub->label)) != NULL) {
        if (strcmp(name, IPC_TARGET_SYSTEM_STR) == 0) {
            set_ipc_permission_for_endpoint(privp, name, SYSTEM);
        } else if (strcmp(name, IPC_TARGET_USER_STR) == 0) {
            set_ipc_permission_for_endpoint(privp, name, INIT_PROC_NR);
        } else {
            set_ipc_permission_for_named_processes(privp, name);
        }
    }
}


/*===========================================================================*
 *				add_backward_ipc			     *
 *===========================================================================*/
void add_backward_ipc(struct rproc *rp, struct priv *privp) {
    char *proc_name = rp->r_pub->proc_name;
    struct rproc *rrp;

    for (rrp = BEG_RPROC_ADDR; rrp < END_RPROC_ADDR; rrp++) {
        if (!(rrp->r_flags & RS_IN_USE)) {
            continue;
        }

        if (!rrp->r_ipc_list[0]) {
            continue;
        }

        struct rprocpub *rrpub = rrp->r_pub;
        int priv_id;

        int is_ipc_all = !strcmp(rrp->r_ipc_list, RSS_IPC_ALL);
        int is_ipc_all_sys = !strcmp(rrp->r_ipc_list, RSS_IPC_ALL_SYS);

        if (is_ipc_all || (is_ipc_all_sys && (privp->s_flags & SYS_PROC))) {
            priv_id = rrp->r_priv.s_id;
            set_sys_bit(privp->s_ipc_to, priv_id);
            continue;
        }

        char name[RS_MAX_LABEL_LEN + 1];
        char *p_list = rrp->r_ipc_list;

        while ((p_list = get_next_name(p_list, name, rrpub->label)) != NULL) {
            if (!strcmp(proc_name, name)) {
                priv_id = rrp->r_priv.s_id;
                set_sys_bit(privp->s_ipc_to, priv_id);
                break;
            }
        }
    }
}


/*===========================================================================*
 *				init_privs				     *
 *===========================================================================*/
void init_privs(rp, privp)
struct rproc *rp;
struct priv *privp;
{
	int i;
	int is_ipc_all;
	int is_ipc_all_sys;

	fill_send_mask(&privp->s_ipc_to, FALSE);

	is_ipc_all = !strcmp(rp->r_ipc_list, RSS_IPC_ALL);
	is_ipc_all_sys = !strcmp(rp->r_ipc_list, RSS_IPC_ALL_SYS);

#if PRIV_DEBUG
	printf("  RS: init_privs: ipc list is '%s'...\n", rp->r_ipc_list);
#endif

	if (!is_ipc_all && !is_ipc_all_sys)
	{
		add_forward_ipc(rp, privp);
		add_backward_ipc(rp, privp);
	}
	else
	{
		if (is_ipc_all)
		{
			for (i = 0; i < NR_SYS_PROCS; i++)
			{
				set_sys_bit(privp->s_ipc_to, i);
			}
		}
		else /* is_ipc_all_sys must be true */
		{
			for (i = 0; i < NR_SYS_PROCS; i++)
			{
				if (i != USER_PRIV_ID)
				{
					set_sys_bit(privp->s_ipc_to, i);
				}
			}
		}
	}
}

