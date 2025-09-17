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
#define SEF_LU_STATE_EVAL 1
#define IPCF_EL_WHITELIST 0x1
#define IPCF_MATCH_M_SOURCE 0x2
#define IPCF_MATCH_M_TYPE 0x4

static void init_dst_state_data(struct rs_state_data *dst_rs_state_data)
{
    dst_rs_state_data->size = 0;
    dst_rs_state_data->eval_addr = NULL;
    dst_rs_state_data->eval_len = 0;
    dst_rs_state_data->ipcf_els = NULL;
    dst_rs_state_data->ipcf_els_size = 0;
}

static int validate_state_data_size(struct rs_state_data *src_rs_state_data)
{
    if(src_rs_state_data->size != sizeof(struct rs_state_data)) {
        return E2BIG;
    }
    return OK;
}

static int copy_eval_expression(endpoint_t src_e, int prepare_state,
    struct rs_state_data *src_rs_state_data,
    struct rs_state_data *dst_rs_state_data)
{
    int s;
    
    if(prepare_state != SEF_LU_STATE_EVAL) {
        return OK;
    }
    
    if(src_rs_state_data->eval_len == 0 || !src_rs_state_data->eval_addr) {
        return EINVAL;
    }
    
    dst_rs_state_data->eval_addr = malloc(src_rs_state_data->eval_len + 1);
    dst_rs_state_data->eval_len = src_rs_state_data->eval_len;
    
    if(!dst_rs_state_data->eval_addr) {
        return ENOMEM;
    }
    
    s = sys_datacopy(src_e, (vir_bytes) src_rs_state_data->eval_addr,
        SELF, (vir_bytes) dst_rs_state_data->eval_addr,
        dst_rs_state_data->eval_len);
    
    if(s != OK) {
        return s;
    }
    
    *((char*)dst_rs_state_data->eval_addr + dst_rs_state_data->eval_len) = '\0';
    dst_rs_state_data->size = src_rs_state_data->size;
    
    return OK;
}

static int parse_endpoint_label(const char *label, endpoint_t *m_source)
{
    char *buff;
    
    if(!strcmp("ANY_USR", label)) {
        *m_source = ANY_USR;
        return OK;
    }
    if(!strcmp("ANY_SYS", label)) {
        *m_source = ANY_SYS;
        return OK;
    }
    if(!strcmp("ANY_TSK", label)) {
        *m_source = ANY_TSK;
        return OK;
    }
    
    errno = 0;
    *m_source = strtol(label, &buff, 10);
    if(errno || strcmp(buff, "")) {
        return ESRCH;
    }
    
    return OK;
}

static int get_m_source(struct rs_ipc_filter_el *filter_el, endpoint_t *m_source)
{
    if(ds_retrieve_label_endpt(filter_el->m_label, m_source) == OK) {
        return OK;
    }
    
    return parse_endpoint_label(filter_el->m_label, m_source);
}

static int process_filter_element(struct rs_ipc_filter_el *filter_el,
    ipc_filter_el_t *ipcf_el)
{
    endpoint_t m_source = 0;
    int m_type = 0;
    int flags = filter_el->flags;
    
    if(flags & IPCF_MATCH_M_TYPE) {
        m_type = filter_el->m_type;
    }
    
    if(flags & IPCF_MATCH_M_SOURCE) {
        int result = get_m_source(filter_el, &m_source);
        if(result != OK) {
            return result;
        }
    }
    
    ipcf_el->flags = flags;
    ipcf_el->m_source = m_source;
    ipcf_el->m_type = m_type;
    
    return OK;
}

static int copy_single_filter(endpoint_t src_e, 
    struct rs_ipc_filter_el (*rs_ipc_filter_els)[IPCF_MAX_ELEMENTS],
    int filter_idx, ipc_filter_el_t (*ipcf_els_buff)[IPCF_MAX_ELEMENTS])
{
    struct rs_ipc_filter_el rs_ipc_filter[IPCF_MAX_ELEMENTS];
    size_t rs_ipc_filter_size = sizeof(rs_ipc_filter);
    int s, j;
    
    s = sys_datacopy(src_e, (vir_bytes) rs_ipc_filter_els[filter_idx],
        SELF, (vir_bytes) rs_ipc_filter, rs_ipc_filter_size);
    if(s != OK) {
        return s;
    }
    
    for(j = 0; j < IPCF_MAX_ELEMENTS && rs_ipc_filter[j].flags; j++) {
        s = process_filter_element(&rs_ipc_filter[j], &ipcf_els_buff[filter_idx][j]);
        if(s != OK) {
            return s;
        }
    }
    
    return OK;
}

static void add_vm_filter(ipc_filter_el_t (*ipcf_els_buff)[IPCF_MAX_ELEMENTS], int idx)
{
    ipcf_els_buff[idx][0].flags = (IPCF_EL_WHITELIST | IPCF_MATCH_M_SOURCE | IPCF_MATCH_M_TYPE);
    ipcf_els_buff[idx][0].m_source = RS_PROC_NR;
    ipcf_els_buff[idx][0].m_type = VM_RS_UPDATE;
}

static size_t calculate_buffer_size(endpoint_t src_e, int num_ipc_filters)
{
    size_t base_size = sizeof(ipc_filter_el_t) * IPCF_MAX_ELEMENTS * num_ipc_filters;
    
    if(src_e == VM_PROC_NR) {
        base_size += sizeof(ipc_filter_el_t) * IPCF_MAX_ELEMENTS;
    }
    
    return base_size;
}

static int init_ipc_filters(endpoint_t src_e,
    struct rs_state_data *src_rs_state_data,
    struct rs_state_data *dst_rs_state_data)
{
    int s, i, num_ipc_filters;
    struct rs_ipc_filter_el (*rs_ipc_filter_els)[IPCF_MAX_ELEMENTS];
    ipc_filter_el_t (*ipcf_els_buff)[IPCF_MAX_ELEMENTS];
    size_t ipcf_els_buff_size;
    size_t rs_ipc_filter_size = sizeof(struct rs_ipc_filter_el[IPCF_MAX_ELEMENTS]);
    
    if(src_rs_state_data->ipcf_els_size % rs_ipc_filter_size) {
        return E2BIG;
    }
    
    rs_ipc_filter_els = src_rs_state_data->ipcf_els;
    num_ipc_filters = src_rs_state_data->ipcf_els_size / rs_ipc_filter_size;
    
    if(!rs_ipc_filter_els) {
        return OK;
    }
    
    ipcf_els_buff_size = calculate_buffer_size(src_e, num_ipc_filters);
    ipcf_els_buff = malloc(ipcf_els_buff_size);
    
    if(!ipcf_els_buff) {
        return ENOMEM;
    }
    
    memset(ipcf_els_buff, 0, ipcf_els_buff_size);
    
    for(i = 0; i < num_ipc_filters; i++) {
        s = copy_single_filter(src_e, rs_ipc_filter_els, i, ipcf_els_buff);
        if(s != OK) {
            free(ipcf_els_buff);
            return s;
        }
    }
    
    if(src_e == VM_PROC_NR) {
        add_vm_filter(ipcf_els_buff, i);
    }
    
    dst_rs_state_data->size = src_rs_state_data->size;
    dst_rs_state_data->ipcf_els = ipcf_els_buff;
    dst_rs_state_data->ipcf_els_size = ipcf_els_buff_size;
    
    return OK;
}

int init_state_data(endpoint_t src_e, int prepare_state,
    struct rs_state_data *src_rs_state_data,
    struct rs_state_data *dst_rs_state_data)
{
    int s;
    
    init_dst_state_data(dst_rs_state_data);
    
    s = validate_state_data_size(src_rs_state_data);
    if(s != OK) {
        return s;
    }
    
    s = copy_eval_expression(src_e, prepare_state, src_rs_state_data, dst_rs_state_data);
    if(s != OK) {
        return s;
    }
    
    s = init_ipc_filters(src_e, src_rs_state_data, dst_rs_state_data);
    if(s != OK) {
        return s;
    }
    
    return OK;
}

/*===========================================================================*
 *			        build_cmd_dep				     *
 *===========================================================================*/
void build_cmd_dep(struct rproc *rp)
{
    struct rprocpub *rpub;
    int arg_count;
    char *cmd_ptr;

    rpub = rp->r_pub;

    strcpy(rp->r_args, rp->r_cmd);
    arg_count = 0;
    rp->r_argv[arg_count++] = rp->r_args;
    cmd_ptr = rp->r_args;
    
    parse_command_arguments(rp, &cmd_ptr, &arg_count);
    
    assert(arg_count < ARGV_ELEMENTS);
    rp->r_argv[arg_count] = NULL;
    rp->r_argc = arg_count;
}

static void parse_command_arguments(struct rproc *rp, char **cmd_ptr, int *arg_count)
{
    while (**cmd_ptr != '\0') {
        if (**cmd_ptr == ' ') {
            if (!handle_space_separator(rp, cmd_ptr, arg_count)) {
                break;
            }
        }
        (*cmd_ptr)++;
    }
}

static int handle_space_separator(struct rproc *rp, char **cmd_ptr, int *arg_count)
{
    **cmd_ptr = '\0';
    (*cmd_ptr)++;
    
    skip_consecutive_spaces(cmd_ptr);
    
    if (**cmd_ptr == '\0') {
        return 0;
    }
    
    if (*arg_count >= ARGV_ELEMENTS - 1) {
        printf("RS: build_cmd_dep: too many args\n");
        return 0;
    }
    
    assert(*arg_count < ARGV_ELEMENTS);
    rp->r_argv[(*arg_count)++] = *cmd_ptr;
    return 1;
}

static void skip_consecutive_spaces(char **cmd_ptr)
{
    while (**cmd_ptr == ' ') {
        (*cmd_ptr)++;
    }
}

/*===========================================================================*
 *				end_srv_init				     *
 *===========================================================================*/
void end_srv_init(struct rproc *rp)
{
  struct rprocpub *rpub;
  int r;

  rpub = rp->r_pub;

  late_reply(rp, OK);

  if(rp->r_prev_rp) {
      handle_previous_instance(rp);
  }
  
  rp->r_next_rp = NULL;
}

static void handle_previous_instance(struct rproc *rp)
{
  if(SRV_IS_UPD_SCHEDULED(rp->r_prev_rp)) {
      rupdate_upd_move(rp->r_prev_rp, rp);
  }
  
  cleanup_service(rp->r_prev_rp);
  rp->r_prev_rp = NULL;
  rp->r_restarts += 1;

  if(rs_verbose) {
      printf("RS: %s completed restart\n", srv_to_string(rp));
  }
}

/*===========================================================================*
 *			     kill_service_debug				     *
 *===========================================================================*/
int kill_service_debug(file, line, rp, errstr, err)
char *file;
int line;
struct rproc *rp;
char *errstr;
int err;
{
  if(errstr && !shutting_down) {
      printf("RS: %s (error %d)\n", errstr, err);
  }
  rp->r_flags |= RS_EXITING;
  crash_service_debug(file, line, rp);

  return err;
}

/*===========================================================================*
 *			    crash_service_debug				     *
 *===========================================================================*/
int crash_service_debug(char *file, int line, struct rproc *rp)
{
  struct rprocpub *rpub;

  rpub = rp->r_pub;

  if(rs_verbose)
      printf("RS: %s %skilled at %s:%d\n", srv_to_string(rp),
          rp->r_flags & RS_EXITING ? "lethally " : "", file, line);

  if(rpub->endpoint == RS_PROC_NR) {
      exit(1);
  }

  return sys_kill(rpub->endpoint, SIGKILL);
}

/*===========================================================================*
 *			  cleanup_service_debug				     *
 *===========================================================================*/
void cleanup_service_debug(file, line, rp)
char *file;
int line;
struct rproc *rp;
{
    struct rprocpub *rpub;
    int detach, cleanup_script;
    int s;

    rpub = rp->r_pub;

    if(!(rp->r_flags & RS_DEAD)) {
        mark_service_for_cleanup(file, line, rp);
        return;
    }

    cleanup_script = rp->r_flags & RS_CLEANUP_SCRIPT;
    detach = rp->r_flags & RS_CLEANUP_DETACH;

    if(!detach) {
        perform_service_cleanup(file, line, rp, rpub);
    }

    if(cleanup_script) {
        execute_cleanup_script(rp);
    }

    finalize_service(rp, detach);
}

static void mark_service_for_cleanup(char *file, int line, struct rproc *rp)
{
    struct rprocpub *rpub = rp->r_pub;

    if(rs_verbose) {
        printf("RS: %s marked for cleanup at %s:%d\n", srv_to_string(rp),
            file, line);
    }

    unlink_service_connections(rp);
    rp->r_flags |= RS_DEAD;

    sys_privctl(rpub->endpoint, SYS_PRIV_DISALLOW, NULL);
    sys_privctl(rpub->endpoint, SYS_PRIV_CLEAR_IPC_REFS, NULL);
    rp->r_flags &= ~RS_ACTIVE;

    late_reply(rp, OK);
}

static void unlink_service_connections(struct rproc *rp)
{
    unlink_connection(&rp->r_next_rp, &rp->r_prev_rp);
    unlink_connection(&rp->r_prev_rp, &rp->r_next_rp);
    unlink_connection(&rp->r_new_rp, &rp->r_old_rp);
    unlink_connection(&rp->r_old_rp, &rp->r_new_rp);
}

static void unlink_connection(struct rproc **primary, struct rproc **secondary)
{
    if(*primary) {
        if(secondary == &(*primary)->r_next_rp) {
            (*primary)->r_prev_rp = NULL;
        } else if(secondary == &(*primary)->r_prev_rp) {
            (*primary)->r_next_rp = NULL;
        } else if(secondary == &(*primary)->r_new_rp) {
            (*primary)->r_old_rp = NULL;
        } else if(secondary == &(*primary)->r_old_rp) {
            (*primary)->r_new_rp = NULL;
        }
        *primary = NULL;
    }
}

static void perform_service_cleanup(char *file, int line, struct rproc *rp, struct rprocpub *rpub)
{
    int s;

    if(rs_verbose) {
        printf("RS: %s cleaned up at %s:%d\n", srv_to_string(rp),
            file, line);
    }

    if ((s = sched_stop(rp->r_scheduler, rpub->endpoint)) != OK) {
        printf("RS: warning: scheduler won't give up process: %d\n", s);
    }

    terminate_service_process(rp);
}

static void terminate_service_process(struct rproc *rp)
{
    if(rp->r_pid == -1) {
        printf("RS: warning: attempt to kill pid -1!\n");
    } else {
        srv_kill(rp->r_pid, SIGKILL);
    }
}

static void execute_cleanup_script(struct rproc *rp)
{
    int s;
    
    rp->r_flags &= ~RS_CLEANUP_SCRIPT;
    s = run_script(rp);
    if(s != OK) {
        printf("RS: warning: cannot run cleanup script: %d\n", s);
    }
}

static void finalize_service(struct rproc *rp, int detach)
{
    if(detach) {
        detach_service(rp);
    } else if (!(rp->r_flags & RS_REINCARNATE)) {
        free_slot(rp);
    }
}

/*===========================================================================*
 *			     detach_service_debug			     *
 *===========================================================================*/
void detach_service_debug(char *file, int line, struct rproc *rp)
{
    static unsigned long detach_counter = 0;
    struct rprocpub *rpub = rp->r_pub;
    
    publish_new_service_label(rpub, ++detach_counter);
    log_service_detachment(rp, file, line);
    activate_detached_service(rp, rpub);
}

static void publish_new_service_label(struct rprocpub *rpub, unsigned long counter)
{
    char label[RS_MAX_LABEL_LEN];
    
    rpub->label[RS_MAX_LABEL_LEN - 1] = '\0';
    strcpy(label, rpub->label);
    snprintf(rpub->label, RS_MAX_LABEL_LEN, "%lu.%s", counter, label);
    ds_publish_label(rpub->label, rpub->endpoint, DSF_OVERWRITE);
}

static void log_service_detachment(struct rproc *rp, char *file, int line)
{
    if (!rs_verbose) {
        return;
    }
    
    printf("RS: %s detached at %s:%d\n", srv_to_string(rp), file, line);
}

static void activate_detached_service(struct rproc *rp, struct rprocpub *rpub)
{
    #define DETACHED_SERVICE_FLAGS (RS_IN_USE | RS_ACTIVE)
    #define CLEARED_SYS_FLAGS (SF_CORE_SRV | SF_DET_RESTART)
    
    rp->r_flags = DETACHED_SERVICE_FLAGS;
    rpub->sys_flags &= ~CLEARED_SYS_FLAGS;
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
  int child_proc_nr_e, child_proc_nr_n;
  pid_t child_pid;
  int s, use_copy, has_replica;
  extern char **environ;
  struct rprocpub *rpub;

  rpub = rp->r_pub;
  use_copy = (rpub->sys_flags & SF_USE_COPY);
  has_replica = (rp->r_old_rp
      || (rp->r_prev_rp && !(rp->r_prev_rp->r_flags & RS_TERMINATED)));

  if ((s = validate_service_requirements(rp, rpub, has_replica, use_copy)) != OK) {
      return s;
  }

  if ((child_pid = fork_service_child(rp)) < 0) {
      free_slot(rp);
      return child_pid;
  }

  if ((s = getprocnr(child_pid, &child_proc_nr_e)) != 0)
      panic("unable to get child endpoint: %d", s);

  child_proc_nr_n = _ENDPOINT_P(child_proc_nr_e);
  initialize_child_process(rp, rpub, child_pid, child_proc_nr_e, child_proc_nr_n);

  if ((s = setup_child_privileges(rp, child_proc_nr_e)) != OK) {
      return s;
  }

  if ((s = sched_init_proc(rp)) != OK) {
      printf("RS: unable to start scheduling: %d\n", s);
      cleanup_service(rp);
      vm_memctl(RS_PROC_NR, VM_RS_MEM_PIN, 0, 0);
      return s;
  }

  if ((s = prepare_and_execute_child(rp, rpub, child_proc_nr_e, use_copy, environ)) != OK) {
      return s;
  }

  setuid(0);

  if ((s = handle_special_process_types(rp, rpub)) != OK) {
      return s;
  }

  if ((s = vm_set_priv(rpub->endpoint, &rpub->vm_call_mask[0], TRUE)) != OK) {
      printf("RS: vm_set_priv failed: %d\n", s);
      cleanup_service(rp);
      return s;
  }

  if(rs_verbose)
      printf("RS: %s created\n", srv_to_string(rp));

  return OK;
}

int validate_service_requirements(rp, rpub, has_replica, use_copy)
struct rproc *rp;
struct rprocpub *rpub;
int has_replica;
int use_copy;
{
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

  return OK;
}

pid_t fork_service_child(rp)
struct rproc *rp;
{
  pid_t child_pid;

  if (rs_verbose)
      printf("RS: forking child with srv_fork()...\n");

  child_pid = srv_fork(rp->r_uid, 0);

  if (child_pid < 0) {
      printf("RS: srv_fork() failed (error %d)\n", child_pid);
  }

  return child_pid;
}

void initialize_child_process(rp, rpub, child_pid, child_proc_nr_e, child_proc_nr_n)
struct rproc *rp;
struct rprocpub *rpub;
pid_t child_pid;
int child_proc_nr_e;
int child_proc_nr_n;
{
  rp->r_flags = RS_IN_USE;
  rpub->endpoint = child_proc_nr_e;
  rp->r_pid = child_pid;
  rp->r_check_tm = 0;
  rp->r_alive_tm = getticks();
  rp->r_stop_tm = 0;
  rp->r_backoff = 0;
  rproc_ptr[child_proc_nr_n] = rp;
  rpub->in_use = TRUE;
}

int setup_child_privileges(rp, child_proc_nr_e)
struct rproc *rp;
int child_proc_nr_e;
{
  int s;

  if ((s = sys_privctl(child_proc_nr_e, SYS_PRIV_SET_SYS, &rp->r_priv)) != OK
      || (s = sys_getpriv(&rp->r_priv, child_proc_nr_e)) != OK) {
      printf("RS: unable to set privilege structure: %d\n", s);
      cleanup_service(rp);
      vm_memctl(RS_PROC_NR, VM_RS_MEM_PIN, 0, 0);
      return ENOMEM;
  }

  return OK;
}

int prepare_and_execute_child(rp, rpub, child_proc_nr_e, use_copy, environ)
struct rproc *rp;
struct rprocpub *rpub;
int child_proc_nr_e;
int use_copy;
char **environ;
{
  int s;

  if (use_copy) {
      if (rs_verbose)
          printf("RS: %s uses an in-memory copy\n", srv_to_string(rp));
  } else {
      if ((s = read_exec(rp)) != OK) {
          printf("RS: read_exec failed: %d\n", s);
          cleanup_service(rp);
          vm_memctl(RS_PROC_NR, VM_RS_MEM_PIN, 0, 0);
          return s;
      }
  }

  if (rs_verbose)
      printf("RS: execing child with srv_execve()...\n");

  s = srv_execve(child_proc_nr_e, rp->r_exec, rp->r_exec_len, rpub->proc_name,
      rp->r_argv, environ);
  vm_memctl(RS_PROC_NR, VM_RS_MEM_PIN, 0, 0);

  if (s != OK) {
      printf("RS: srv_execve failed: %d\n", s);
      cleanup_service(rp);
      return s;
  }

  if (!use_copy) {
      free_exec(rp);
  }

  return OK;
}

int handle_special_process_types(rp, rpub)
struct rproc *rp;
struct rprocpub *rpub;
{
  int s;

  if (rp->r_priv.s_flags & ROOT_SYS_PROC) {
      if ((s = pin_rs_instance_memory(rp, rpub)) != OK) {
          return s;
      }
  }

  if (rp->r_priv.s_flags & VM_SYS_PROC) {
      if ((s = setup_vm_instance(rp, rpub)) != OK) {
          return s;
      }
  }

  return OK;
}

int pin_rs_instance_memory(rp, rpub)
struct rproc *rp;
struct rprocpub *rpub;
{
  int s;

  if (rs_verbose)
      printf("RS: pinning memory of RS instance %s\n", srv_to_string(rp));

  s = vm_memctl(rpub->endpoint, VM_RS_MEM_PIN, 0, 0);
  if (s != OK) {
      printf("vm_memctl failed: %d\n", s);
      cleanup_service(rp);
  }

  return s;
}

int setup_vm_instance(rp, rpub)
struct rproc *rp;
struct rprocpub *rpub;
{
  struct rproc *rs_rp;
  struct rproc **rs_rps;
  int i, nr_rs_rps, s;

  if (rs_verbose)
      printf("RS: informing VM of instance %s\n", srv_to_string(rp));

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

  return OK;
}

/*===========================================================================*
 *				clone_service				     *
 *===========================================================================*/
int clone_service(struct rproc *rp, int instance_flag, int init_flags)
{
    struct rproc *replica_rp;
    struct rproc **rp_link;
    struct rproc **replica_link;
    int r;

    if(rs_verbose)
        printf("RS: %s creating a replica\n", srv_to_string(rp));

    handle_vm_single_replica(rp, instance_flag);

    if((r = clone_slot(rp, &replica_rp)) != OK) {
        return r;
    }

    setup_replica_links(rp, replica_rp, instance_flag, init_flags, &rp_link, &replica_link);

    r = create_service(replica_rp);
    if(r != OK) {
        *rp_link = NULL;
        return r;
    }

    if(is_rs_restart_instance(replica_rp)) {
        r = setup_backup_signal_manager(replica_rp, rp_link);
        if(r != OK) {
            return r;
        }
    }

    return OK;
}

static void handle_vm_single_replica(struct rproc *rp, int instance_flag)
{
    if(rp->r_pub->endpoint == VM_PROC_NR && instance_flag == LU_SYS_PROC && rp->r_next_rp) {
        cleanup_service_now(rp->r_next_rp);
        rp->r_next_rp = NULL;
    }
}

static void setup_replica_links(struct rproc *rp, struct rproc *replica_rp, 
                                int instance_flag, int init_flags,
                                struct rproc ***rp_link, struct rproc ***replica_link)
{
    if(instance_flag == LU_SYS_PROC) {
        *rp_link = &rp->r_new_rp;
        *replica_link = &replica_rp->r_old_rp;
    }
    else {
        *rp_link = &rp->r_next_rp;
        *replica_link = &replica_rp->r_prev_rp;
    }
    
    replica_rp->r_priv.s_flags |= instance_flag;
    replica_rp->r_priv.s_init_flags |= init_flags;
    
    **rp_link = replica_rp;
    **replica_link = rp;
}

static int is_rs_restart_instance(struct rproc *replica_rp)
{
    int rs_flags = (ROOT_SYS_PROC | RST_SYS_PROC);
    return (replica_rp->r_priv.s_flags & rs_flags) == rs_flags;
}

static int setup_backup_signal_manager(struct rproc *replica_rp, struct rproc **rp_link)
{
    struct rproc *rs_rp = rproc_ptr[_ENDPOINT_P(RS_PROC_NR)];
    struct rprocpub *replica_rpub = replica_rp->r_pub;
    int r;
    
    r = update_sig_mgrs(rs_rp, SELF, replica_rpub->endpoint);
    if(r == OK) {
        r = update_sig_mgrs(replica_rp, SELF, NONE);
    }
    
    if(r != OK) {
        *rp_link = NULL;
        return kill_service(replica_rp, "update_sig_mgrs failed", r);
    }
    
    return OK;
}

/*===========================================================================*
 *				publish_service				     *
 *===========================================================================*/
#define DEVMAN_LABEL "devman"

static int register_label_with_ds(struct rprocpub *rpub)
{
    return ds_publish_label(rpub->label, rpub->endpoint, DSF_OVERWRITE);
}

static int map_driver_if_needed(struct rprocpub *rpub)
{
    if (rpub->dev_nr <= 0 && rpub->nr_domain <= 0) {
        return OK;
    }
    
    setuid(0);
    return mapdriver(rpub->label, rpub->dev_nr, rpub->domain, rpub->nr_domain);
}

#if USE_PCI
static int setup_pci_acl(struct rprocpub *rpub)
{
    struct rs_pci pci_acl;
    
    if (!rpub->pci_acl.rsp_nr_device && !rpub->pci_acl.rsp_nr_class) {
        return OK;
    }
    
    pci_acl = rpub->pci_acl;
    strcpy(pci_acl.rsp_label, rpub->label);
    pci_acl.rsp_endpoint = rpub->endpoint;
    
    return pci_set_acl(&pci_acl);
}
#endif

static int bind_devman_device(struct rprocpub *rpub)
{
    endpoint_t ep;
    message m;
    int r;
    
    if (rpub->devman_id == 0) {
        return OK;
    }
    
    r = ds_retrieve_label_endpt(DEVMAN_LABEL, &ep);
    if (r != OK) {
        return r;
    }
    
    m.m_type = DEVMAN_BIND;
    m.DEVMAN_ENDPOINT = rpub->endpoint;
    m.DEVMAN_DEVICE_ID = rpub->devman_id;
    
    r = ipc_sendrec(ep, &m);
    if (r != OK) {
        return r;
    }
    
    return (m.DEVMAN_RESULT == OK) ? OK : m.DEVMAN_RESULT;
}

int publish_service(rp)
struct rproc *rp;
{
    int r;
    struct rprocpub *rpub = rp->r_pub;
    
    r = register_label_with_ds(rpub);
    if (r != OK) {
        return kill_service(rp, "ds_publish_label call failed", r);
    }
    
    r = map_driver_if_needed(rpub);
    if (r != OK) {
        return kill_service(rp, "couldn't map driver", r);
    }
    
#if USE_PCI
    r = setup_pci_acl(rpub);
    if (r != OK) {
        return kill_service(rp, "pci_set_acl call failed", r);
    }
#endif
    
    r = bind_devman_device(rpub);
    if (r != OK) {
        return kill_service(rp, "devman bind device failed", r);
    }
    
    if (rs_verbose) {
        printf("RS: %s published\n", srv_to_string(rp));
    }
    
    return OK;
}

/*===========================================================================*
 *			      unpublish_service				     *
 *===========================================================================*/
int unpublish_service(rp)
struct rproc *rp;
{
    struct rprocpub *rpub;
    int result;

    rpub = rp->r_pub;
    result = OK;

    result = unregister_label(rpub, result);
    result = handle_pci_cleanup(rpub, result);
    result = handle_devman_unbind(rpub, result);

    if(rs_verbose)
        printf("RS: %s unpublished\n", srv_to_string(rp));

    return result;
}

static int unregister_label(rpub, current_result)
struct rprocpub *rpub;
int current_result;
{
    int r;

    r = ds_delete_label(rpub->label);
    if (r != OK && !shutting_down) {
        printf("RS: ds_delete_label call failed (error %d)\n", r);
        return r;
    }
    return current_result;
}

static int handle_pci_cleanup(rpub, current_result)
struct rprocpub *rpub;
int current_result;
{
#if USE_PCI
    int r;

    if(!rpub->pci_acl.rsp_nr_device && !rpub->pci_acl.rsp_nr_class) {
        return current_result;
    }

    r = pci_del_acl(rpub->endpoint);
    if (r != OK && !shutting_down) {
        printf("RS: pci_del_acl call failed (error %d)\n", r);
        return r;
    }
#endif
    return current_result;
}

static int handle_devman_unbind(rpub, current_result)
struct rprocpub *rpub;
int current_result;
{
    endpoint_t ep;
    message m;
    int r;

    if (rpub->devman_id == 0) {
        return current_result;
    }

    r = ds_retrieve_label_endpt("devman", &ep);
    if (r != OK) {
        printf("RS: devman not running?");
        return current_result;
    }

    m.m_type = DEVMAN_UNBIND;
    m.DEVMAN_ENDPOINT = rpub->endpoint;
    m.DEVMAN_DEVICE_ID = rpub->devman_id;
    r = ipc_sendrec(ep, &m);

    if (r != OK || m.DEVMAN_RESULT != OK) {
        printf("RS: devman unbind device failed");
    }

    return current_result;
}

/*===========================================================================*
 *				run_service				     *
 *===========================================================================*/
int run_service(struct rproc *rp, int init_type, int init_flags)
{
    struct rprocpub *rpub;
    int s;

    rpub = rp->r_pub;

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
int start_service(struct rproc *rp, int init_flags)
{
    int r;
    struct rprocpub *rpub = rp->r_pub;

    rp->r_priv.s_init_flags |= init_flags;
    
    r = create_service(rp);
    if(r != OK) {
        return r;
    }
    
    activate_service(rp, NULL);

    r = publish_service(rp);
    if (r != OK) {
        return r;
    }

    r = run_service(rp, SEF_INIT_FRESH, init_flags);
    if(r != OK) {
        return r;
    }

    if(rs_verbose) {
        printf("RS: %s started with major %d\n", srv_to_string(rp), rpub->dev_nr);
    }

    return OK;
}

/*===========================================================================*
 *				stop_service				     *
 *===========================================================================*/
void stop_service(struct rproc *rp, int how)
{
    struct rprocpub *rpub = rp->r_pub;
    
    if (rs_verbose) {
        printf("RS: %s signaled with SIGTERM\n", srv_to_string(rp));
    }
    
    int signo = (rpub->endpoint != RS_PROC_NR) ? SIGTERM : SIGHUP;
    
    rp->r_flags |= how;
    sys_kill(rpub->endpoint, signo);
    rp->r_stop_tm = getticks();
}

/*===========================================================================*
 *			      activate_service				     *
 *===========================================================================*/
void deactivate_service(struct rproc *rp)
{
    if (rp && (rp->r_flags & RS_ACTIVE)) {
        rp->r_flags &= ~RS_ACTIVE;
        if (rs_verbose) {
            printf("RS: %s becomes inactive\n", srv_to_string(rp));
        }
    }
}

void make_service_active(struct rproc *rp)
{
    if (!(rp->r_flags & RS_ACTIVE)) {
        rp->r_flags |= RS_ACTIVE;
        if (rs_verbose) {
            printf("RS: %s becomes active\n", srv_to_string(rp));
        }
    }
}

void activate_service(struct rproc *rp, struct rproc *ex_rp)
{
    deactivate_service(ex_rp);
    make_service_active(rp);
}

/*===========================================================================*
 *			      reincarnate_service			     *
 *===========================================================================*/
void reincarnate_service(struct rproc *old_rp)
{
    struct rproc *rp;
    int r, restarts;

    if ((r = clone_slot(old_rp, &rp)) != OK) {
        printf("RS: Failed to clone the slot: %d\n", r);
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
#define BACKOFF_SHIFT_MIN(restarts) MIN(restarts, (BACKOFF_BITS - 2))
#define CALCULATE_BACKOFF(restarts) (1 << BACKOFF_SHIFT_MIN(restarts))
#define SHOULD_FORCE_EXIT(rp) (!(rp->r_flags & RS_EXITING) && (rp->r_pub->sys_flags & SF_NORESTART))
#define SHOULD_DETACH_ON_CLEANUP(rp) ((rp->r_pub->sys_flags & SF_DET_RESTART) && (rp->r_restarts < MAX_DET_RESTART))
#define HAS_CLEANUP_SCRIPT(rp) (rp->r_script[0] != '\0')
#define IS_CORE_SERVICE(rp) (rp->r_pub->sys_flags & SF_CORE_SRV)
#define SHOULD_USE_BINARY_BACKOFF(rpub) (!(rpub->sys_flags & SF_NO_BIN_EXP))
#define SHOULD_LIMIT_COPY_BACKOFF(rpub) (rpub->sys_flags & SF_USE_COPY)

static void handle_initialization_failure(struct rproc *rp)
{
    struct rprocpub *rpub = rp->r_pub;
    
    if(SRV_IS_UPDATING(rp)) {
        printf("RS: update failed: state transfer failed. Rolling back...\n");
        end_update(rp->r_init_err, RS_REPLY);
        rp->r_init_err = ERESTART;
        return;
    }
    
    if (rpub->sys_flags & SF_NO_BIN_EXP) {
        if(rs_verbose)
            printf("RS: service '%s' exited during initialization; refreshing\n", rpub->label);
        rp->r_flags |= RS_REFRESHING;
    } else {
        if(rs_verbose)
            printf("RS: service '%s' exited during initialization; exiting\n", rpub->label);
        rp->r_flags |= RS_EXITING;
    }
}

static void setup_cleanup_flags(struct rproc *rp)
{
    if(SHOULD_DETACH_ON_CLEANUP(rp)) {
        rp->r_flags |= RS_CLEANUP_DETACH;
    }
    if(HAS_CLEANUP_SCRIPT(rp)) {
        rp->r_flags |= RS_CLEANUP_SCRIPT;
    }
}

static void handle_force_exit(struct rproc *rp)
{
    rp->r_flags |= RS_EXITING;
    setup_cleanup_flags(rp);
}

static void handle_core_service_death(struct rproc *rp)
{
    if (IS_CORE_SERVICE(rp) && !shutting_down) {
        printf("core system service died: %s\n", srv_to_string(rp));
        _exit(1);
    }
}

static void abort_scheduled_update_if_needed(struct rproc *rp)
{
    if(SRV_IS_UPD_SCHEDULED(rp)) {
        printf("RS: aborting the scheduled update, one of the services part of it is exiting...\n");
        abort_update_proc(EDEADSRCDST);
    }
}

static void send_late_reply_if_needed(struct rproc *rp, int norestart)
{
    int r = (rp->r_caller_request == RS_DOWN || 
            (rp->r_caller_request == RS_REFRESH && norestart)) ? OK : EDEADEPT;
    late_reply(rp, r);
}

static void cleanup_all_instances(struct rproc *rp)
{
    struct rproc **rps;
    int nr_rps, i;
    
    get_service_instances(rp, &rps, &nr_rps);
    for(i = 0; i < nr_rps; i++) {
        cleanup_service(rps[i]);
    }
}

static void handle_reincarnation(struct rproc *rp)
{
    if (rp->r_flags & RS_REINCARNATE) {
        rp->r_flags &= ~RS_REINCARNATE;
        reincarnate_service(rp);
    }
}

static void handle_service_exit(struct rproc *rp, int norestart)
{
    handle_core_service_death(rp);
    abort_scheduled_update_if_needed(rp);
    send_late_reply_if_needed(rp, norestart);
    unpublish_service(rp);
    cleanup_all_instances(rp);
    handle_reincarnation(rp);
}

static int calculate_service_backoff(struct rprocpub *rpub, int restarts)
{
    int backoff;
    
    if (!SHOULD_USE_BINARY_BACKOFF(rpub)) {
        return 1;
    }
    
    backoff = CALCULATE_BACKOFF(restarts);
    backoff = MIN(backoff, MAX_BACKOFF);
    
    if (SHOULD_LIMIT_COPY_BACKOFF(rpub) && backoff > 1) {
        backoff = 1;
    }
    
    return backoff;
}

static void handle_unexpected_exit(struct rproc *rp)
{
    if (rp->r_restarts > 0) {
        rp->r_backoff = calculate_service_backoff(rp->r_pub, rp->r_restarts);
        return;
    }
    restart_service(rp);
}

void terminate_service(struct rproc *rp)
{
    int norestart;

    if(rs_verbose)
        printf("RS: %s terminated\n", srv_to_string(rp));

    if(rp->r_flags & RS_INITIALIZING) {
        handle_initialization_failure(rp);
        if(SRV_IS_UPDATING(rp))
            return;
    }

    if(RUPDATE_IS_UPDATING()) {
        printf("RS: aborting the update after a crash...\n");
        abort_update_proc(ERESTART);
    }

    norestart = SHOULD_FORCE_EXIT(rp);
    if(norestart) {
        handle_force_exit(rp);
    }

    if (rp->r_flags & RS_EXITING) {
        handle_service_exit(rp, norestart);
    }
    else if(rp->r_flags & RS_REFRESHING) {
        restart_service(rp);
    }
    else {
        handle_unexpected_exit(rp);
    }
}

/*===========================================================================*
 *				run_script				     *
 *===========================================================================*/
static const char* get_restart_reason(struct rproc *rp)
{
	if (rp->r_flags & RS_REFRESHING)
		return "restart";
	if (rp->r_flags & RS_NOPINGREPLY)
		return "no-heartbeat";
	return "terminated";
}

static void log_script_execution(struct rproc *rp, const char *reason, const char *incarnation_str)
{
	if (!rs_verbose)
		return;
	
	printf("RS: %s:\n", srv_to_string(rp));
	printf("RS:     calling script '%s'\n", rp->r_script);
	printf("RS:     reason: '%s'\n", reason);
	printf("RS:     incarnation: '%s'\n", incarnation_str);
}

static void execute_script(struct rproc *rp, const char *reason, const char *incarnation_str)
{
	char *envp[1] = { NULL };
	struct rprocpub *rpub = rp->r_pub;
	
	execle(_PATH_BSHELL, "sh", rp->r_script, rpub->label, reason,
		incarnation_str, (char*) NULL, envp);
	printf("RS: run_script: execl '%s' failed: %s\n",
		rp->r_script, strerror(errno));
	exit(1);
}

static int set_script_privilege(int endpoint, struct rproc *rp)
{
	int r;
	
	if ((r = sys_privctl(endpoint, SYS_PRIV_SET_USER, NULL)) != OK)
		return kill_service(rp, "can't set script privileges", r);
	
	if ((r = vm_set_priv(endpoint, NULL, FALSE)) != OK)
		return kill_service(rp, "can't set script VM privs", r);
	
	if ((r = sys_privctl(endpoint, SYS_PRIV_ALLOW, NULL)) != OK)
		return kill_service(rp, "can't let the script run", r);
	
	return OK;
}

static int setup_child_process(pid_t pid, struct rproc *rp)
{
	int r, endpoint;
	
	if ((r = getprocnr(pid, &endpoint)) != 0)
		panic("unable to get child endpoint: %d", r);
	
	if ((r = set_script_privilege(endpoint, rp)) != OK)
		return r;
	
	vm_memctl(RS_PROC_NR, VM_RS_MEM_PIN, 0, 0);
	return OK;
}

static int run_script(struct rproc *rp)
{
	pid_t pid;
	char incarnation_str[20];
	const char *reason;
	
	reason = get_restart_reason(rp);
	snprintf(incarnation_str, sizeof(incarnation_str), "%d", rp->r_restarts);
	
	log_script_execution(rp, reason, incarnation_str);
	
	pid = fork();
	switch(pid)
	{
	case -1:
		return errno;
	case 0:
		execute_script(rp, reason, incarnation_str);
		break;
	default:
		return setup_child_process(pid, rp);
	}
	return OK;
}

/*===========================================================================*
 *			      restart_service				     *
 *===========================================================================*/
void restart_service(struct rproc *rp)
{
    late_reply(rp, OK);

    if (rp->r_script[0] != '\0') {
        run_recovery_script(rp);
        return;
    }

    restart_directly(rp);
}

static void run_recovery_script(struct rproc *rp)
{
    int r = run_script(rp);
    if (r != OK) {
        kill_service(rp, "unable to run script", errno);
    }
}

static void restart_directly(struct rproc *rp)
{
    struct rproc *replica_rp = get_or_create_replica(rp);
    if (replica_rp == NULL) {
        return;
    }

    if (!perform_update(rp, replica_rp)) {
        return;
    }

    if (!start_replica(rp, replica_rp)) {
        return;
    }

    check_detach_needed(rp);
    log_restart_if_verbose(rp, replica_rp);
}

static struct rproc* get_or_create_replica(struct rproc *rp)
{
    if (rp->r_next_rp != NULL) {
        return rp->r_next_rp;
    }

    int r = clone_service(rp, RST_SYS_PROC, 0);
    if (r != OK) {
        kill_service(rp, "unable to clone service", r);
        return NULL;
    }
    return rp->r_next_rp;
}

static int perform_update(struct rproc *rp, struct rproc *replica_rp)
{
    int r = update_service(&rp, &replica_rp, RS_SWAP, 0);
    if (r != OK) {
        kill_service(rp, "unable to update into new replica", r);
        return 0;
    }
    return 1;
}

static int start_replica(struct rproc *rp, struct rproc *replica_rp)
{
    int r = run_service(replica_rp, SEF_INIT_RESTART, 0);
    if (r != OK) {
        kill_service(rp, "unable to let the replica run", r);
        return 0;
    }
    return 1;
}

static void check_detach_needed(struct rproc *rp)
{
    if ((rp->r_pub->sys_flags & SF_DET_RESTART) && (rp->r_restarts < MAX_DET_RESTART)) {
        rp->r_flags |= RS_CLEANUP_DETACH;
    }
}

static void log_restart_if_verbose(struct rproc *rp, struct rproc *replica_rp)
{
    if (rs_verbose) {
        printf("RS: %s restarted into %s\n", srv_to_string(rp), srv_to_string(replica_rp));
    }
}

/*===========================================================================*
 *		         inherit_service_defaults			     *
 *===========================================================================*/
void inherit_service_defaults(def_rp, rp)
struct rproc *def_rp;
struct rproc *rp;
{
  struct rprocpub *def_rpub;
  struct rprocpub *rpub;
  int i;

  def_rpub = def_rp->r_pub;
  rpub = rp->r_pub;

  copy_device_and_domain_settings(def_rpub, rpub);
  copy_immutable_flags(def_rp, rp);
  rp->r_priv.s_trap_mask = def_rp->r_priv.s_trap_mask;
}

static void copy_device_and_domain_settings(def_rpub, rpub)
struct rprocpub *def_rpub;
struct rprocpub *rpub;
{
  int i;
  
  rpub->dev_nr = def_rpub->dev_nr;
  rpub->nr_domain = def_rpub->nr_domain;
  for (i = 0; i < def_rpub->nr_domain; i++)
    rpub->domain[i] = def_rpub->domain[i];
  rpub->pci_acl = def_rpub->pci_acl;
}

static void copy_immutable_flags(def_rp, rp)
struct rproc *def_rp;
struct rproc *rp;
{
  struct rprocpub *def_rpub = def_rp->r_pub;
  struct rprocpub *rpub = rp->r_pub;
  
  rpub->sys_flags &= ~IMM_SF;
  rpub->sys_flags |= (def_rpub->sys_flags & IMM_SF);
  rp->r_priv.s_flags &= ~IMM_F;
  rp->r_priv.s_flags |= (def_rp->r_priv.s_flags & IMM_F);
}

/*===========================================================================*
 *		           get_service_instances			     *
 *===========================================================================*/
void get_service_instances(rp, rps, length)
struct rproc *rp;
struct rproc ***rps;
int *length;
{
  static struct rproc *instances[5];
  int nr_instances;
  struct rproc *related_procs[4];
  int i;

  related_procs[0] = rp->r_prev_rp;
  related_procs[1] = rp->r_next_rp;
  related_procs[2] = rp->r_old_rp;
  related_procs[3] = rp->r_new_rp;

  nr_instances = 0;
  instances[nr_instances++] = rp;
  
  for(i = 0; i < 4; i++) {
    if(related_procs[i]) {
      instances[nr_instances++] = related_procs[i];
    }
  }

  *rps = instances;
  *length = nr_instances;
}

/*===========================================================================*
 *				share_exec				     *
 *===========================================================================*/
void share_exec(rp_dst, rp_src)
struct rproc *rp_dst, *rp_src;
{
  if(rs_verbose)
      printf("RS: %s shares exec image with %s\n",
          srv_to_string(rp_dst), srv_to_string(rp_src));

  rp_dst->r_exec_len = rp_src->r_exec_len;
  rp_dst->r_exec = rp_src->r_exec;
}

/*===========================================================================*
 *				read_exec				     *
 *===========================================================================*/
int read_exec(rp)
struct rproc *rp;
{
  char *e_name;
  struct stat sb;
  int fd;

  e_name = rp->r_argv[0];
  
  if (rs_verbose)
      printf("RS: service '%s' reads exec image from: %s\n", 
             rp->r_pub->label, e_name);

  if (validate_exec_file(e_name, &sb) != OK)
      return get_validation_error(e_name, &sb);

  fd = open(e_name, O_RDONLY);
  if (fd == -1)
      return -errno;

  return load_exec_image(rp, fd, sb.st_size);
}

int validate_exec_file(e_name, sb)
char *e_name;
struct stat *sb;
{
  if (stat(e_name, sb) != 0)
      return -1;
  
  if (sb->st_size < sizeof(Elf_Ehdr))
      return -2;
  
  return OK;
}

int get_validation_error(e_name, sb)
char *e_name;
struct stat *sb;
{
  if (stat(e_name, sb) != 0)
      return -errno;
  
  return ENOEXEC;
}

int load_exec_image(rp, fd, file_size)
struct rproc *rp;
int fd;
size_t file_size;
{
  int result;

  if (allocate_exec_memory(rp, file_size) != OK) {
      close(fd);
      return ENOMEM;
  }

  result = read_exec_data(rp, fd);
  close(fd);
  
  return result;
}

int allocate_exec_memory(rp, size)
struct rproc *rp;
size_t size;
{
  rp->r_exec_len = size;
  rp->r_exec = malloc(rp->r_exec_len);
  
  if (rp->r_exec == NULL) {
      printf("RS: read_exec: unable to allocate %zu bytes\n", 
             rp->r_exec_len);
      return -1;
  }
  
  return OK;
}

int read_exec_data(rp, fd)
struct rproc *rp;
int fd;
{
  int bytes_read, saved_errno;

  bytes_read = read(fd, rp->r_exec, rp->r_exec_len);
  saved_errno = errno;
  
  if (bytes_read == rp->r_exec_len)
      return OK;

  printf("RS: read_exec: read failed %d, errno %d\n", 
         bytes_read, saved_errno);
  
  free_exec(rp);
  
  if (bytes_read >= 0)
      return EIO;
  
  return -saved_errno;
}

/*===========================================================================*
 *				free_exec				     *
 *===========================================================================*/
void free_exec(rp)
struct rproc *rp;
{
  int slot_nr;
  struct rproc *other_rp;

  for (slot_nr = 0; slot_nr < NR_SYS_PROCS; slot_nr++) {
      other_rp = &rproc[slot_nr];
      if (other_rp->r_flags & RS_IN_USE && other_rp != rp
          && other_rp->r_exec == rp->r_exec) {
          if(rs_verbose)
              printf("RS: %s no longer sharing exec image with %s\n",
                  srv_to_string(rp), srv_to_string(other_rp));
          rp->r_exec = NULL;
          rp->r_exec_len = 0;
          return;
      }
  }

  if(rs_verbose)
      printf("RS: %s frees exec image\n", srv_to_string(rp));
  free(rp->r_exec);
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
int clone_slot(rp, clone_rpp)
struct rproc *rp;
struct rproc **clone_rpp;
{
  int r;
  struct rproc *clone_rp;
  struct rprocpub *rpub, *clone_rpub;

  r = alloc_slot(&clone_rp);
  if(r != OK) {
      printf("RS: clone_slot: unable to allocate a new slot: %d\n", r);
      return r;
  }

  rpub = rp->r_pub;
  clone_rpub = clone_rp->r_pub;

  if ((r = sys_getpriv(&(rp->r_priv), rpub->endpoint)) != OK) {
      panic("unable to synch privilege structure: %d", r);
  }

  copy_base_structures(clone_rp, clone_rpub, rp, rpub);
  initialize_clone_fields(clone_rp, clone_rpub);
  setup_clone_relationships(clone_rp, clone_rpub, rp);
  configure_clone_privileges(clone_rp);

  *clone_rpp = clone_rp;
  return OK;
}

static void copy_base_structures(clone_rp, clone_rpub, rp, rpub)
struct rproc *clone_rp;
struct rprocpub *clone_rpub;
struct rproc *rp;
struct rprocpub *rpub;
{
  *clone_rp = *rp;
  *clone_rpub = *rpub;
}

static void initialize_clone_fields(clone_rp, clone_rpub)
struct rproc *clone_rp;
struct rprocpub *clone_rpub;
{
  clone_rp->r_init_err = ERESTART;
  clone_rp->r_flags &= ~RS_ACTIVE;
  clone_rp->r_pid = -1;
  clone_rpub->endpoint = -1;
  clone_rp->r_pub = clone_rpub;
}

static void setup_clone_relationships(clone_rp, clone_rpub, rp)
struct rproc *clone_rp;
struct rprocpub *clone_rpub;
struct rproc *rp;
{
  build_cmd_dep(clone_rp);
  
  if(clone_rpub->sys_flags & SF_USE_COPY) {
      share_exec(clone_rp, rp);
  }
  
  clone_rp->r_old_rp = NULL;
  clone_rp->r_new_rp = NULL;
  clone_rp->r_prev_rp = NULL;
  clone_rp->r_next_rp = NULL;
}

static void configure_clone_privileges(clone_rp)
struct rproc *clone_rp;
{
  clone_rp->r_priv.s_flags |= DYN_PRIV_ID;
  clone_rp->r_priv.s_flags &= ~(LU_SYS_PROC | RST_SYS_PROC);
  clone_rp->r_priv.s_init_flags = 0;
}

/*===========================================================================*
 *			    swap_slot_pointer				     *
 *===========================================================================*/
static void swap_slot_pointer(struct rproc **rpp, struct rproc *src_rp,
    struct rproc *dst_rp)
{
  if(*rpp == src_rp) {
      *rpp = dst_rp;
      return;
  }
  if(*rpp == dst_rp) {
      *rpp = src_rp;
  }
}

/*===========================================================================*
 *				swap_slot				     *
 *===========================================================================*/
void swap_slot(src_rpp, dst_rpp)
struct rproc **src_rpp;
struct rproc **dst_rpp;
{
  struct rproc *src_rp, *dst_rp;
  struct rprocpub *src_rpub, *dst_rpub;
  struct rproc orig_src_rproc, orig_dst_rproc;
  struct rprocpub orig_src_rprocpub, orig_dst_rprocpub;
  struct rprocupd *prev_rpupd, *rpupd;

  src_rp = *src_rpp;
  dst_rp = *dst_rpp;
  src_rpub = src_rp->r_pub;
  dst_rpub = dst_rp->r_pub;

  orig_src_rproc = *src_rp;
  orig_src_rprocpub = *src_rpub;
  orig_dst_rproc = *dst_rp;
  orig_dst_rprocpub = *dst_rpub;

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

  swap_rproc_slot_pointers(src_rp, dst_rp);
  swap_global_slot_pointers(src_rp, dst_rp);

  *src_rpp = dst_rp;
  *dst_rpp = src_rp;
}

static void swap_rproc_slot_pointers(src_rp, dst_rp)
struct rproc *src_rp;
struct rproc *dst_rp;
{
  swap_slot_pointer(&src_rp->r_prev_rp, src_rp, dst_rp);
  swap_slot_pointer(&src_rp->r_next_rp, src_rp, dst_rp);
  swap_slot_pointer(&src_rp->r_old_rp, src_rp, dst_rp);
  swap_slot_pointer(&src_rp->r_new_rp, src_rp, dst_rp);
  swap_slot_pointer(&dst_rp->r_prev_rp, src_rp, dst_rp);
  swap_slot_pointer(&dst_rp->r_next_rp, src_rp, dst_rp);
  swap_slot_pointer(&dst_rp->r_old_rp, src_rp, dst_rp);
  swap_slot_pointer(&dst_rp->r_new_rp, src_rp, dst_rp);
}

static void swap_global_slot_pointers(src_rp, dst_rp)
struct rproc *src_rp;
struct rproc *dst_rp;
{
  struct rprocupd *prev_rpupd, *rpupd;
  
  RUPDATE_ITER(rupdate.first_rpupd, prev_rpupd, rpupd,
      swap_slot_pointer(&rpupd->rp, src_rp, dst_rp);
  );
  swap_slot_pointer(&rproc_ptr[_ENDPOINT_P(src_rp->r_pub->endpoint)],
      src_rp, dst_rp);
  swap_slot_pointer(&rproc_ptr[_ENDPOINT_P(dst_rp->r_pub->endpoint)],
      src_rp, dst_rp);
}

/*===========================================================================*
 *			   lookup_slot_by_label				     *
 *===========================================================================*/
struct rproc* lookup_slot_by_label(char *label)
{
    int slot_nr;
    struct rproc *rp;
    struct rprocpub *rpub;

    for (slot_nr = 0; slot_nr < NR_SYS_PROCS; slot_nr++) {
        rp = &rproc[slot_nr];
        if (!(rp->r_flags & RS_ACTIVE)) {
            continue;
        }
        rpub = rp->r_pub;
        if (strcmp(rpub->label, label) == 0) {
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
    if(pid < 0) {
        return NULL;
    }

    for (int slot_nr = 0; slot_nr < NR_SYS_PROCS; slot_nr++) {
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
    if(dev_nr <= 0) {
        return NULL;
    }

    return find_rproc_by_dev_nr(dev_nr);
}

static struct rproc* find_rproc_by_dev_nr(dev_t dev_nr)
{
    int slot_nr;
    struct rproc *rp;

    for (slot_nr = 0; slot_nr < NR_SYS_PROCS; slot_nr++) {
        rp = &rproc[slot_nr];
        if (is_matching_rproc(rp, dev_nr)) {
            return rp;
        }
    }

    return NULL;
}

static int is_matching_rproc(struct rproc *rp, dev_t dev_nr)
{
    if (!(rp->r_flags & RS_IN_USE)) {
        return 0;
    }
    return rp->r_pub->dev_nr == dev_nr;
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
        
        if (!(rp->r_flags & RS_IN_USE)) {
            continue;
        }
        
        if (has_domain(rp->r_pub, domain)) {
            return rp;
        }
    }

    return NULL;
}

static int has_domain(struct rprocpub *rpub, int domain)
{
    for (int i = 0; i < rpub->nr_domain; i++) {
        if (rpub->domain[i] == domain) {
            return 1;
        }
    }
    return 0;
}

/*===========================================================================*
 *			   lookup_slot_by_flags				     *
 *===========================================================================*/
struct rproc* lookup_slot_by_flags(int flags)
{
    if (!flags) {
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
int alloc_slot(struct rproc **rpp)
{
    int slot_nr;

    for (slot_nr = 0; slot_nr < NR_SYS_PROCS; slot_nr++) {
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
void free_slot(rp)
struct rproc *rp;
{
  struct rprocpub *rpub;

  rpub = rp->r_pub;

  late_reply(rp, OK);

  if(rpub->sys_flags & SF_USE_COPY) {
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
static char *skip_whitespace(char *p) {
    while (p[0] != '\0' && isspace((unsigned char)p[0]))
        p++;
    return p;
}

static char *find_word_end(char *p) {
    while (p[0] != '\0' && !isspace((unsigned char)p[0]))
        p++;
    return p;
}

static int validate_name_length(size_t len, char *p, char *caller_label) {
    if (len > RS_MAX_LABEL_LEN) {
        printf("rs:get_next_name: bad ipc list entry '%.*s' for %s: too long\n",
               (int) len, p, caller_label);
        return 0;
    }
    return 1;
}

static void copy_name(char *name, char *p, size_t len) {
    memcpy(name, p, len);
    name[len] = '\0';
}

static char *get_next_name(ptr, name, caller_label)
char *ptr;
char *name;
char *caller_label;
{
    char *p, *q;
    size_t len;

    for (p = ptr; p[0] != '\0'; p = q) {
        p = skip_whitespace(p);
        q = find_word_end(p);
        
        if (q == p)
            continue;
            
        len = q - p;
        
        if (!validate_name_length(len, p, caller_label))
            continue;
            
        copy_name(name, p, len);
        return q;
    }

    return NULL;
}

/*===========================================================================*
 *				add_forward_ipc				     *
 *===========================================================================*/
void add_forward_ipc(rp, privp)
struct rproc *rp;
struct priv *privp;
{
	char name[RS_MAX_LABEL_LEN+1], *p;
	struct rprocpub *rpub;

	rpub = rp->r_pub;
	p = rp->r_ipc_list;

	while ((p = get_next_name(p, name, rpub->label)) != NULL) {
		process_ipc_name(name, privp);
	}
}

static void process_ipc_name(name, privp)
char *name;
struct priv *privp;
{
	endpoint_t endpoint;

	if (strcmp(name, "SYSTEM") == 0) {
		endpoint = SYSTEM;
		set_privilege_for_endpoint(endpoint, privp);
	} else if (strcmp(name, "USER") == 0) {
		endpoint = INIT_PROC_NR;
		set_privilege_for_endpoint(endpoint, privp);
	} else {
		set_privilege_for_matching_processes(name, privp);
	}
}

static void set_privilege_for_endpoint(endpoint, privp)
endpoint_t endpoint;
struct priv *privp;
{
	struct priv priv;
	int r;
	int priv_id;

	if ((r = sys_getpriv(&priv, endpoint)) < 0) {
		printf("add_forward_ipc: unable to get priv_id for endpoint %d: %d\n",
			endpoint, r);
		return;
	}

#if PRIV_DEBUG
	printf("  RS: add_forward_ipc: setting sendto bit for %d...\n", endpoint);
#endif
	priv_id = priv.s_id;
	set_sys_bit(privp->s_ipc_to, priv_id);
}

static void set_privilege_for_matching_processes(name, privp)
char *name;
struct priv *privp;
{
	struct rproc *rrp;

	for (rrp = BEG_RPROC_ADDR; rrp < END_RPROC_ADDR; rrp++) {
		if (process_matches(rrp, name)) {
			set_privilege_bit(rrp, privp);
		}
	}
}

static int process_matches(rrp, name)
struct rproc *rrp;
char *name;
{
	if (!(rrp->r_flags & RS_IN_USE))
		return 0;
	
	return !strcmp(rrp->r_pub->proc_name, name);
}

static void set_privilege_bit(rrp, privp)
struct rproc *rrp;
struct priv *privp;
{
	int priv_id;

#if PRIV_DEBUG
	printf("  RS: add_forward_ipc: setting sendto bit for %d...\n",
		rrp->r_pub->endpoint);
#endif

	priv_id = rrp->r_priv.s_id;
	set_sys_bit(privp->s_ipc_to, priv_id);
}


/*===========================================================================*
 *				add_backward_ipc			     *
 *===========================================================================*/
#define IPC_ALL_MATCH 1
#define IPC_ALL_SYS_MATCH 2
#define IPC_NO_MATCH 0

static int check_ipc_all_permission(struct rproc *rrp, struct priv *privp)
{
	int is_ipc_all = !strcmp(rrp->r_ipc_list, RSS_IPC_ALL);
	int is_ipc_all_sys = !strcmp(rrp->r_ipc_list, RSS_IPC_ALL_SYS);
	
	if (is_ipc_all) {
		return IPC_ALL_MATCH;
	}
	
	if (is_ipc_all_sys && (privp->s_flags & SYS_PROC)) {
		return IPC_ALL_SYS_MATCH;
	}
	
	return IPC_NO_MATCH;
}

static void grant_ipc_permission(struct priv *privp, struct rproc *rrp)
{
#if PRIV_DEBUG
	printf("  RS: add_backward_ipc: setting sendto bit for %d...\n", 
		rrp->r_pub->endpoint);
#endif
	int priv_id = rrp->r_priv.s_id;
	set_sys_bit(privp->s_ipc_to, priv_id);
}

static void check_named_ipc_permission(struct rproc *rrp, struct priv *privp, 
	const char *proc_name)
{
	char name[RS_MAX_LABEL_LEN+1];
	char *p = rrp->r_ipc_list;
	
	while ((p = get_next_name(p, name, rrp->r_pub->label)) != NULL) {
		if (!strcmp(proc_name, name)) {
			grant_ipc_permission(privp, rrp);
		}
	}
}

static void process_rproc_ipc(struct rproc *rrp, struct priv *privp, 
	const char *proc_name)
{
	if (!(rrp->r_flags & RS_IN_USE)) {
		return;
	}
	
	if (!rrp->r_ipc_list[0]) {
		return;
	}
	
	int ipc_match = check_ipc_all_permission(rrp, privp);
	
	if (ipc_match != IPC_NO_MATCH) {
		grant_ipc_permission(privp, rrp);
		return;
	}
	
	check_named_ipc_permission(rrp, privp, proc_name);
}

void add_backward_ipc(rp, privp)
struct rproc *rp;
struct priv *privp;
{
	char *proc_name = rp->r_pub->proc_name;
	struct rproc *rrp;
	
	for (rrp = BEG_RPROC_ADDR; rrp < END_RPROC_ADDR; rrp++) {
		process_rproc_ipc(rrp, privp, proc_name);
	}
}


/*===========================================================================*
 *				init_privs				     *
 *===========================================================================*/
void init_privs(rp, privp)
struct rproc *rp;
struct priv *privp;
{
	fill_send_mask(&privp->s_ipc_to, FALSE);

	if (is_custom_ipc_list(rp->r_ipc_list)) {
		setup_custom_ipc(rp, privp);
	} else {
		setup_system_ipc(rp->r_ipc_list, privp);
	}

#if PRIV_DEBUG
	printf("  RS: init_privs: ipc list is '%s'...\n", rp->r_ipc_list);
#endif
}

int is_custom_ipc_list(const char *ipc_list)
{
	return strcmp(ipc_list, RSS_IPC_ALL) != 0 && 
	       strcmp(ipc_list, RSS_IPC_ALL_SYS) != 0;
}

void setup_custom_ipc(struct rproc *rp, struct priv *privp)
{
	add_forward_ipc(rp, privp);
	add_backward_ipc(rp, privp);
}

void setup_system_ipc(const char *ipc_list, struct priv *privp)
{
	int is_ipc_all = !strcmp(ipc_list, RSS_IPC_ALL);
	int i;

	for (i = 0; i < NR_SYS_PROCS; i++) {
		if (should_set_ipc_bit(is_ipc_all, i)) {
			set_sys_bit(privp->s_ipc_to, i);
		}
	}
}

int should_set_ipc_bit(int is_ipc_all, int proc_id)
{
	return is_ipc_all || proc_id != USER_PRIV_ID;
}

