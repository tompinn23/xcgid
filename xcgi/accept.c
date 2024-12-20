#include "xcgi.h"

#include <stdlib.h>
#include <stdio.h>

#include <unistd.h>
#include <string.h>

#include <sys/poll.h>
#include <errno.h>
#include <sys/socket.h>


int xcgi_init(xcgi *x) {
  char *listensock;
  int rc; 

  x->mpool = xcgi_mpool_create(65535, 16);
  if(!x->mpool) {
    return -1;
  }

  x->ctrl = x->fd = -1;
  x->mode = XCGI_MODE_XCGI;
  if((listensock = getenv(XCGI_LISTENSOCK_ENV)) != NULL) {
    char *endptr;
    x->ctrl = strtol(listensock, &endptr, 10);
    if(endptr == listensock || *endptr != '\0') {
      x->mode = XCGI_MODE_FCGI;
      x->ctrl = STDIN_FILENO;
    }
  }
  return 0;
}


/**
 * This function accepts a connection from the manager process.
 * This follows the more standard fcgi protocol where we would use accept on the listen socket.
 */
static int xcgid_fdaccept(xcgi *x) {
  
}

static int xfullreadfd(int fd, int *recvfd, void *buffer, size_t bufsize) {
  struct msghdr  msg;
  char           buf[CMSG_SPACE(sizeof(fd))];
  struct iovec   io;
  struct cmsghdr *cmsg;
  int            rc;
  struct pollfd  pfd;

  memset(&msg, 0, sizeof(msg));
  memset(&io, 0, sizeof(io));

  io.iov_base = buffer;
  io.iov_len = bufsize;

  msg.msg_iov = &io;
  msg.msg_iovlen = 1;

  msg.msg_control = buf;
  msg.msg_controllen = sizeof(buf);

  pfd.fd = fd;
  pfd.events = POLLIN;

again:
  if((rc = poll(&pfd, 1, -1)) < 0) {
    if(errno == EINTR) {
      goto again;
    }
    return -1;
  } else if(rc == 0) {
    goto again;
  }

  if(!(pfd.revents & POLLIN)) {
    return 0;
  }

  if((rc = recvmsg(fd, &msg, 0)) < 0) {
    if(errno == EINTR) {
      goto again;
    }
    return -1;
  } else if(rc < bufsize) {
    return -1;
  }

  for(cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
    if(cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS && cmsg->cmsg_len == CMSG_LEN(sizeof(int))) {
      *recvfd = *(int *)CMSG_DATA(cmsg);
      return 1;
    }
  }
  return -1;
}

/**
 * return -1 on failure;
 * return 1 on success;
 */
int xcgi_accept(xcgi *x) {

  struct sockaddr_storage ss;
  socklen_t sslen = sizeof(ss);
  struct pollfd pfd;
  int rc;

    /* if we still have a left over file descriptor close it.*/
  if(x->fd >= 0) {
    close(x->fd);
    x->fd = -1;
  }

  pfd.fd = x->ctrl;
  pfd.events = POLLIN;

  for(;;) {
    rc = poll(&pfd, 1, -1);
    if(rc < 0) {
      if(errno == EINTR) {
        continue;
      }
      return -1;
    } else if(rc == 0) {
      continue;
    }

    if((pfd.revents & POLLHUP) || !(pfd.revents & POLLIN)) {
      return -1;
    }

    switch(x->mode) {
      case XCGI_MODE_FCGI:
        x->fd = accept(x->ctrl, &ss, &sslen);
        if(x->fd < 0) {
          if(errno == EAGAIN || errno == EWOULDBLOCK) {
            continue;
          }
        }
      case XCGI_MODE_XCGI:
        if(!xfullreadfd(x->ctrl, &x->fd, &x->cookie, sizeof(x->cookie))) {
          return -1;
        }
        break;
      default:
        return -1;
    }
  }

  return 1;
}

int xcgi_request(xcgi *x, xcgi_request *req) {
  char *buf = xcgi_mpool_alloc(x->mpool);
  
}