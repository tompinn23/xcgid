#define _GNU_SOURCE

#include <stdint.h>
#define OPTPARSE_IMPLEMENTATION
#define OPTPARSE_API static
#include "optparse.h"

#include "list.h"
#include "log.h"
#include "util.h"

#include <sched.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <stdatomic.h>

#include <sys/poll.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <arpa/inet.h>

static void usage() {
    printf("usage: xcgid [options] [prog] [arg0...]\n");
    printf("options:\n");
    printf("    -h, --help          Print this help message\n");
    printf("    -v, --verbose       Print debugging information\n");
    printf("    -f, --fork          Fork and daemonize\n");
    printf("    -r, --dynamic-pool  Use management extensions to dynamically manage workers\n");
    printf("    -n, --workers       Minimum workers\n");
    printf("    -m, --max-workers   Max workers\n");
    printf("    -s, --socket        Socket path\n");
    printf("    -w, --kill-time     Idle time to wait before killing a child\n");
}

static int get_nproc() {
    cpu_set_t cs;
    CPU_ZERO(&cs);
    sched_getaffinity(0, sizeof(cs), &cs);
    return CPU_COUNT(&cs);
}

/* parse a string containing either a unix socket path e.g /tmp/xcgid.sock 
  or an inet address in the format e.g 127.0.0.1:8080
  then create a socket ready for listening set to nonblock
*/
static int setup_socket(const char *socketpath) {
  int fd;
  struct sockaddr_un unaddr;
  struct sockaddr_in inaddr;

  if(strchr(socketpath, '/')) {
    // Create Unix socket
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if(fd == -1) {
        log_errno(LOG_ERROR, "socket");
        return -1;
    }

    // Set socket to non-blocking mode
    int flags = fcntl(fd, F_GETFL, 0);
    if(flags == -1) {
      log_errno(LOG_ERROR, "fcntl");
      close(fd);
      return -1;
    }
    if(fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
      log_errno(LOG_ERROR, "fcntl");
      close(fd);
      return -1;
    }
    // Bind Unix socket
    if(unlink(socketpath) < 0) {
      if(errno != ENOENT) {
        log_errno(LOG_ERROR, "unlink");
        close(fd);
        return -1;
      }
    }
    memset(&unaddr, 0, sizeof(unaddr));
    unaddr.sun_family = AF_UNIX;
    strncpy(unaddr.sun_path, socketpath, sizeof(unaddr.sun_path) - 1);

    if(bind(fd, (struct sockaddr *)&unaddr, sizeof(unaddr)) == -1) {
        log_errno(LOG_ERROR, "bind");
        close(fd);
        return -1;
    }
  } else {
    int port = 8080;
    const char *ip = "127.0.0.1";

    char *addr = strdup(socketpath);
    if(!addr) {
      log_errno(LOG_ERROR, "strdup");
      return -1;
    }
    char *colon = strrchr(addr, ':');
    if(colon) {
      *colon = '\0';
      port = strtol(colon + 1, NULL, 10);
    }

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if(fd == -1) {
      log_errno(LOG_ERROR, "socket");
      free(addr);
      return -1;
    }

    int flags = fcntl(fd, F_GETFL, 0);
    if(flags == -1) {
      log_errno(LOG_ERROR, "fcntl");
      close(fd);
      free(addr);
      return -1;
    }
    if(fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
      log_errno(LOG_ERROR, "fcntl");
      close(fd);
      free(addr);
      return -1;
    }

    memset(&inaddr, 0, sizeof(inaddr));
    inaddr.sin_family = AF_INET;
    inaddr.sin_port = htons(port);
    if(inet_pton(AF_INET, ip, &inaddr.sin_addr) != 1) {
      log_errno(LOG_ERROR, "inet_pton");
      close(fd);
      free(addr);
      return -1;
    }

    if(bind(fd, (struct sockaddr *)&inaddr, sizeof(inaddr)) == -1) {
      log_errno(LOG_ERROR, "bind");
      close(fd);
      return -1;
    }
    free(addr);   
  }

  // Listen on the socket
  if (listen(fd, 4) == -1) {
      log_errno(LOG_ERROR, "listen");
      close(fd);
      return -1;
  }

  return fd;
}

static char *default_socketpath = "/tmp/xcgid.sock";

int serve_variable(int workers, int max_workers, int waittime, int fd, char **worker_argv);

int main(int argc, char **argv) {
    struct optparse_long longopts[] = {
        {"help",         'h', OPTPARSE_NONE},
        {"verbose",      'v', OPTPARSE_NONE},
        {"fork",         'f', OPTPARSE_NONE},
        {"dynamic-pool", 'r', OPTPARSE_NONE},
        {"workers",      'n', OPTPARSE_REQUIRED},
        {"max-workers",  'm', OPTPARSE_REQUIRED},
        {"socket",       's', OPTPARSE_REQUIRED},
        {"kill-time",    'w', OPTPARSE_REQUIRED},
        {0}
    };

    bool dynamic, forking = false;
    int workers = get_nproc() / 4 == 0 ? 1 : get_nproc() / 4;
    int max_workers = get_nproc() / 2 == 0 ? 1 : get_nproc() / 2;
    int kill_time = 300;
    int verbose = 0;
    char *socketpath = NULL;

    char *arg;
    int option;
    log_set_level(LOG_DEBUG);
    log_enable_syslog();
#define PARSE_INT(var, msg) \
    var = strtol(options.optarg, &end, 10); \
    if(end == options.optarg || *end != '\0') { \
        fprintf(stderr, "'%s' is not a valid integer for %s\n", options.optarg, msg); \
        exit(EXIT_FAILURE); \
    }
    char *end;
    struct optparse options;
    optparse_init(&options, argv);
    while((option = optparse_long(&options, longopts, NULL)) != -1) {
        switch(option) {
            case 'h':
                usage();
                exit(EXIT_SUCCESS);
            case 'f':
                forking = true;
                break;
            case 'r':
                dynamic = true;
                break;
            case 'n':
                PARSE_INT(workers, "minimum workers")
                break;
            case 'm':
                PARSE_INT(max_workers, "maximum workers")
                break;
            case 'w':
                PARSE_INT(kill_time, "wait time")
                break;
            case 's':
                socketpath = strdup(options.optarg);
                break;
            case 'v':
                verbose++;
                break;
            case '?':
                fprintf(stderr, "%s: %s\n", argv[0], options.errmsg);
                exit(EXIT_FAILURE);
        }
    }

    printf("fork: %s\n", forking ? "true" : "false");
    printf("dynamic: %s\n", dynamic ? "true" : "false");
    printf("workers: %d\n", workers);
    printf("max-workers: %d\n", max_workers);
    printf("waittime: %d\n", kill_time);
    printf("socket: %s\n", socketpath ? socketpath : default_socketpath);
    char **subargv = argv + options.optind;
    printf("subargv0:\n");
    while(*subargv != NULL) {
        printf("    %s\n", *subargv);
        subargv++;
    }

  int fd = setup_socket(socketpath ? socketpath : default_socketpath);
  if(fd < 0) {
    return -1;
  }
    
  serve_variable(workers, max_workers, kill_time, fd, argv + options.optind);
}

struct worker {
    int ready;
    time_t last_activity;
    int fd;
    int ctrl;
    int info;
    pid_t pid;

  uint64_t cookie;
};


static int xsockpair(int *sock) {
    int ret;
    sock[0] = sock[1] = -1;
    ret = socketpair(AF_UNIX, SOCK_STREAM, 0, sock);
    if(ret < 0) {
        log_errno(LOG_ERROR, "failed to create socketpair");

        return 0;
    }
    int flags;
    if((flags = fcntl(sock[0], F_GETFL, 0)) < 0) {
        log_errno(LOG_ERROR, "failed to get socket flags");
        return 0;
    } else if(fcntl(sock[0], F_SETFL, flags | O_NONBLOCK) < 0) {
        log_errno(LOG_ERROR, "failed to set nonblock flags");
        return 0;
    }
  return 1;
}

static int xpipe(int *pipes) {
    int ret;
    pipes[0] = pipes[1] = -1;
    ret = pipe(pipes);
    if(ret < 0) {
        log_errno(LOG_ERROR, "failed to create pipe");
        return 0;
    }
    int flags;
    if((flags = fcntl(pipes[0], F_GETFL, 0)) < 0) {
        log_errno(LOG_ERROR, "failed to get socket flags");
        return 0;
    } else if(fcntl(pipes[0], F_SETFL, flags | O_NONBLOCK) < 0) {
        log_errno(LOG_ERROR, "failed to set nonblock flags");
        return 0;
    }
  return 1;
}

static int xread(int fd, void *buf, size_t bufsz) {
  ssize_t       ssz;
  size_t        sz;
  struct pollfd pfd;
  int           rc;

  pfd.fd = fd;
  pfd.events = POLLIN;

  for(sz = 0; sz < bufsz; sz += ssz) {
    if((rc = poll(&pfd, 1, -1)) < 0) {
      return 0;
    } else if(rc == 0) {
      ssz = 0;
      continue;
    } else if(!(POLLIN & pfd.revents)) {
      return 0;
    } else if((ssz = read(fd, buf + sz, bufsz - sz)) < 0) {
      return 0;
    } else if(ssz == 0 && sz > 0) {
      return 0;
    } else if(0 == ssz && sz == 0) {
      return 0;
    } else if(sz > SIZE_MAX - ssz) {
      return 0;
    }
  }
  return 1;
}

static char *xreadline(int fd) {
  size_t buffer_size = 256;
  char *buffer = malloc(buffer_size);
  if (!buffer) {
      return NULL;
  }

  size_t buffer_pos = 0;
  ssize_t bytes_read;
  char c;
  struct pollfd pfd;
  pfd.fd = fd;
  pfd.events = POLLIN;

again:
  int rc = poll(&pfd, 1, 1000);
  if(rc < 0) {
    if(errno == EINTR) {
      goto again;
    }
    free(buffer);
    return NULL;
  } else if(rc == 0) {
    free(buffer);
    return NULL;
  } else if(!(POLLIN & pfd.revents)) {
    free(buffer);
    return NULL;
  }

  bytes_read = read(fd, &c, 1);
  if(bytes_read < 0) {
    if(errno == EAGAIN || errno == EWOULDBLOCK) {
      if(buffer_pos == 0) {
        free(buffer);
        return NULL;
      }
      goto again;
    } else if(errno == EINTR) {
      goto again;
    } else {
      free(buffer);
      return NULL;
    }
  } else if(bytes_read == 0) {
    if(buffer_pos == 0) {
      free(buffer);
      return NULL;
    }
    buffer[buffer_pos] = '\0';
    return buffer;
  }

  buffer[buffer_pos++] = c;

    // Resize the buffer if necessary
  if (buffer_pos >= buffer_size) {
      buffer_size *= 2;
      char *new_buffer = realloc(buffer, buffer_size);
      if (!new_buffer) {
          free(buffer);
          return NULL;
      }
      buffer = new_buffer;
  }

    // Check for newline character
  if (c == '\n') {
      buffer[buffer_pos] = '\0';
      return buffer;
  }
  goto again;
}

static int xwritefd(int fd, int sendfd, void *buffer, size_t len) {
  struct msghdr  msg;
  int            rc;
  char           buf[CMSG_SPACE(sizeof(fd))];
  struct iovec   io;
  struct cmsghdr *cmsg;
  struct pollfd  pfd;

  memset(buf, 0, sizeof(buf));
  memset(&msg, 0, sizeof(struct msghdr));
  memset(&io, 0, sizeof(struct iovec));

  io.iov_base = buffer;
  io.iov_len = len;

  msg.msg_iov = &io;
  msg.msg_iovlen = 1;
  msg.msg_control = buf;
  msg.msg_controllen = sizeof(buf);

  cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN(sizeof(fd));
  
  *((int *)CMSG_DATA(cmsg)) = sendfd;

  msg.msg_controllen = cmsg->cmsg_len;

  pfd.fd = fd;
  pfd.events = POLLOUT;

again:
  if((rc = poll(&pfd, 1, -1)) < 0) {
    return 0;
  } else if(rc == 0) {
    goto again;
  } else if( ! (POLLOUT & pfd.revents)) {
    return 0;
  } else if(sendmsg(fd, &msg, 0) < 0) {
    return 0;
  }
  return 1;
}

static void xclosepair(int* fds) {
    close(fds[0]);
    close(fds[1]);
}



int worker_new(struct worker *w, struct worker *ws, size_t nws, char **argv) {
    log_info("starting worker");
    int socks[2];
    if(!xsockpair(socks)) {
        return -1;
    }
    int info_pipes[2];
    if(!xpipe(info_pipes)) {
        xclosepair(socks);
        return -1;
    }
    w->fd = -1;
    w->pid = -1;
    w->ctrl = socks[0];
    w->info = info_pipes[0];
    if((w->pid = fork()) < 0) {
        log_errno(LOG_ERROR, "fork: worker");
        xclosepair(socks);
        xclosepair(info_pipes);
        w->ctrl = -1;
        return -1;
    } else if(w->pid == 0) {
        for(size_t i = 0; i < nws; i++) {
            if(ws[i].ctrl != -1 && close(ws[i].ctrl) < 0) {
                log_errno(LOG_ERROR, "close: fd cleanup %d", ws[i].ctrl);
            }
        }
        char *arg0 = xaprintf("XCGID_ARGV0=%s", argv[0]);
        char buf[64];
        snprintf(buf, sizeof(buf), "XCGI_LISTENSOCK=%d", socks[1]);
        char buf1[64];
        snprintf(buf1, sizeof(buf1), "XCGI_INFOSOCK=%d", info_pipes[1]);
        char *env[] = {
            "PATH=/usr/local/bin:/usr/bin:/bin",
            arg0,
            buf,
            buf1,
            NULL
        };
        if(execvpe(argv[0], argv, env) < 0) {
          log_errno(LOG_ERROR, "execvpe: ");
        }
        exit(EXIT_FAILURE);
    }
  return 1;
}

static volatile sig_atomic_t term = 0;
static volatile sig_atomic_t child = 0;
static volatile sig_atomic_t hup = 0;

static void sighandlehup(int sig) {
  hup = 1;
}

static void sighandleterm(int sig) {
  term = 1;
}

static void sighandlechild(int sig) {
  child = 1;
}

int serve_variable(int workers, int max_workers, int waittime, int fd, char **worker_argv) {
  log_info("Starting variable worker pool with %d workers", workers);

  struct worker *ws, *exit;
  size_t           maxexit, maxpfd;
  size_t           nws, nexit, 
                   npfd, napfd;
  sigset_t         set,pollset;
  struct pollfd    *pfd, *apfd;
  int              rc, afd;
  bool             accepting;
  struct sigaction sa;
  time_t           t;
  void             *pp;
  struct sockaddr_storage ss;
  socklen_t        sslen;
  uint64_t cookie;

  npfd = 0;
  maxpfd = (max_workers * 2) + 1;
  
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_RESTART;


  sa.sa_handler = sighandleterm;
  if(sigaction(SIGTERM, &sa, NULL) == -1) {
    log_errno(LOG_ERROR, "signal: set TERM");
    goto out;
  }
  sa.sa_handler = sighandlehup;
  if(sigaction(SIGHUP, &sa, NULL) == -1) {
    log_errno(LOG_ERROR, "signal: set HUP");
    goto out;
  }
  sa.sa_handler = sighandlechild;
  if(sigaction(SIGCHLD, &sa, NULL) == -1) {
    log_errno(LOG_ERROR, "signal: set CHILD");
    goto out;
  }

  sigemptyset(&pollset);
  sigemptyset(&set);
  sigaddset(&set, SIGTERM);
  sigaddset(&set, SIGCHLD);
  sigaddset(&set, SIGHUP);

  sigprocmask(SIG_BLOCK, &set, NULL);

again:
  term = child = hup = 0;

  ws = calloc(max_workers, sizeof(struct worker));
  nws = 0;
  maxexit = (max_workers - workers) * 2;
  exit = calloc(maxexit, sizeof(struct worker));
  pfd = calloc(maxpfd, sizeof(struct pollfd));

  if(pfd == NULL || ws == NULL || exit == NULL) {
    log_error("calloc: failure");
    close(fd);
    free(ws);
    free(exit);
    free(pfd);
    return -1;
  }

  for(size_t i = 0; i < max_workers; i++) { 
    ws[i].fd = -1; 
    ws[i].ctrl = -1; 
    ws[i].info = -1;
    ws[i].pid = -1; 
  }

  pfd[0].fd = fd;
  pfd[0].events = POLLIN;

  nexit = 0;
  accepting = true;
  npfd = 1;

  for(size_t i = 0; i < workers; i++) {
    if(!worker_new(&ws[i], ws, max_workers, worker_argv)) {
      log_error("Failed to create worker");
      goto out;
    }
    nws++;
  }
  struct timespec timeout = {
    .tv_sec = 1,
    .tv_nsec = 0,
  };

pollagain:
  apfd = accepting ? pfd : pfd + 1;
  napfd = accepting ? npfd : npfd - 1;

  /** epoll */
  log_debug("polling");
  rc = ppoll(apfd, napfd, &timeout, &pollset);
  if(rc < 0 && errno != EINTR) {
    log_errno(LOG_ERROR, "poll: failure");
  }
  log_debug("poll returned %d", rc);
  log_debug("term: %d, child: %d, hup: %d", term, child, hup);

  if(term) {
    log_info("exiting C-c");
    goto out;
  } else if(child) {
    log_debug("child changed state");
    /* if no workers are exiting something else has happened */
    if(nexit == 0) {
      log_errno(LOG_ERROR, "worker: unexpected exit");
      goto out;
    }

    for(int i = 0; i < nws; i++) {
      rc = waitpid(ws[i].pid, NULL, WNOHANG);
      if(rc < 0) {
        log_errno(LOG_ERROR, "wait: worker-%u", ws[i].pid);
        goto out;
      } else if(rc == 0) {
        continue;
      }

      log_error("worker-%u unexpectedly exit", ws[i].pid);
      if(close(ws[i].ctrl) < 0) {
        log_errno(LOG_WARN, "close: worker-%u ctrl sock", ws[i].pid);
      }
      ws[i].pid = -1;
      goto out;
    }

    child = 0;
    for(int i = 0; i < nexit;) {
      rc = waitpid(exit[i].pid, NULL, WNOHANG);
      if(rc == 0) {
        i++;
        continue;
      } else if(rc < 0) {
        goto out;
      }
      log_debug("releasing worker-%u", exit[i].pid);
      if(i < nexit - 1) {
        exit[i] = exit[i - 1];
      }
      nexit--;
    }
  } else if(hup) {
    log_debug("servicing restart");
    goto out;
  }


  if(nws > workers) {
    log_debug("checking for idle workers");
    t = time(NULL);
    if(ws[nws - 1].fd == -1 &&
       t - ws[nws - 1].last_activity > waittime) {

      if(close(ws[nws -1].ctrl) == -1) {
        goto out;
      }

      if(kill(ws[nws -1].pid, SIGTERM) == -1) {
        goto out;
      }

      exit[nexit++] = ws[nws - 1];
      pp = reallocarray(ws, nws - 1, sizeof(struct worker));
      if(!pp) {
        log_errno(LOG_ERROR, "reallocarray: workers");
        goto out;
      }
      ws = pp;
      nws--;

      pp = reallocarray(pfd, maxpfd - 1, sizeof(struct pollfd));
      if(!pp) {
        log_errno(LOG_ERROR, "reallocarray: descriptors");
        goto out;
      }
      pfd = pp;
      maxpfd--;
    }
  }

  if(rc == 0) {
    goto pollagain;
  }

  for(int i = 1; i < npfd && rc > 0;) {
    log_debug("looking at worker %d", i);
    if(POLLHUP && pfd[i].revents ||
       POLLERR && pfd[i].revents) {
      log_error("poll: worker disconnect");
      goto out;
    } else if(!(POLLIN & pfd[i].revents) && !(POLLIN & pfd[i + 1].revents)) {
      i += 2;
      continue;
    } else if(POLLIN & pfd[i + 1].revents) {
      log_debug("worker %d has output", i);
      char *line = xreadline(pfd[i + 1].fd);
      if(line) {
        log_debug("worker %d: %s", i, line);
      } else {
        log_warn("worker %d: tried to read logging output", i);
      }
      i += 2;
    }

    if(!xread(pfd[i].fd, &cookie, sizeof(uint64_t))) {
      goto out;
    }

    int j;
    for(j = 0; j < nws; j++) {
      if(ws[j].cookie == cookie)
        break;
    }
    
    if(j == nws) {
      goto out;
    }

    rc--;
    close(ws[j].fd);
    if(!accepting) {
      accepting = true;
    }
    ws[j].fd = -1;
    ws[j].last_activity = time(NULL);
    if(npfd - 1 != i) {
      pfd[i] = pfd[npfd - 1];
    }
    pfd[npfd - 1].fd = -1;
    npfd--;
  }

  if(!accepting) {
    log_debug("not accepting polling");
    goto pollagain;
  }

  if(POLLHUP & pfd[0].revents) {
    log_error("poll: socket disconnect");
    goto out;
  } else if(POLLERR & pfd[0].revents) {
    log_error("poll: socket error");
    goto out;
  } else if(!(POLLIN &pfd[0].revents)) {
    goto pollagain;
  }

  log_debug("accepting new connection");
  if(npfd == maxpfd) {
    if(nws + 1 > max_workers) {
      accepting = 0;
      goto pollagain;
    }
    pp = reallocarray(pfd, maxpfd + 1, sizeof(struct pollfd));
    if(!pp) {
      goto out;
    }
    pfd = pp;
    memset(&pfd[maxpfd], 0, sizeof(struct pollfd));
    pfd[maxpfd].fd = -1;

    pp = reallocarray(ws, nws + 1, sizeof(struct worker));
    if(!pp) {
      goto out;
    }
    ws = pp;
    memset(&ws[nws], 0, sizeof(struct worker));

    if(!worker_new(&ws[nws], ws, nws + 1, worker_argv)) {
      goto out;
    }
    maxpfd++;
    nws++;
  }

  sslen = sizeof(ss);
  afd = accept(fd, (struct sockaddr *)&ss, &sslen);
  if(afd < 0) {
    if(errno == EAGAIN || errno == EWOULDBLOCK) {
      goto pollagain;
    }
    log_errno(LOG_ERROR, "accept: new conn");
    goto out;
  }

  for(int i = 0; i < nws; i++) {
    if(ws[i].fd == -1) {
      ws[i].fd = afd;
      arc4random_buf(&ws[i].cookie, sizeof(uint64_t));
      pfd[npfd].events = POLLIN;
      pfd[npfd].fd = ws[i].ctrl;
      npfd++;

      if(xwritefd(ws[i].ctrl, ws[i].fd, &ws[i].cookie, sizeof(uint64_t))) {
        goto pollagain;
      }
      break;
    }
  }
out:
  if(!hup) {
    close(fd);
    fd = -1;
  }


  for(size_t i = 0; i < max_workers; i++) {
    if(ws[i].pid == -1) {
      continue;
    }

    log_debug("worker-%u: terminating", ws[i].pid);
    if(close(ws[i].ctrl)) {
      log_errno(LOG_ERROR, "worker-%u close ctrl", ws[i].pid);
    }
    if(kill(ws[i].pid, SIGTERM)) {
      log_errno(LOG_ERROR, "worker-%u kill", ws[i].pid);
    }
  }

  for(size_t i = 0; i < max_workers; i++) {
    if(ws[i].pid == -1) {
      continue;
    }
    log_debug("worker-%u: reaping", ws[i].pid);
    if(waitpid(ws[i].pid, NULL, 0) < 0) {
      log_errno(LOG_ERROR, "wait: worker-%u", ws[i].pid);
    }
  }

  for(size_t i = 0; i < nexit; i++) {
    waitpid(exit[i].pid, NULL, 0);
  }


  free(ws);
  free(exit);
  free(pfd);

  if(hup)
    goto again;

  if(fd != -1) {
    close(fd);
  }

  return 0;
}
