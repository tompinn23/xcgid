#include "xcgi/xcgi.h"

#include <unistd.h>
#include <stdio.h>

int main(int argc, char **argv) {
  xcgi ctx;

  char buf[256];
  snprintf(buf, sizeof(buf), "wk-output-%u", getpid());
  FILE *fp = fopen(buf, "w");

  if(xcgi_init(&ctx) < 0) {
    return -1;
  }

  fprintf(fp, "Hello from worker!\n");
  fflush(fp);

  xcgi_info(&ctx, "Hello from worker!\n");

  int rc = 0;
  xcgi_req req;
  while((rc = xcgi_accept(&ctx)) != -1) {
    fprintf(fp, "Accepting!\n");
    if((rc = xcgi_request(&ctx, &req)) == -1) {
      continue;
    }
    printf("Request ID: %d\n", req.id);
    xcgi_req_iter iter;
    char *key, *value;
    if(xcgi_request_params_iter(&iter, &req) == -1) {
      continue;
    }
    while(xcgi_request_params_next(&iter, &key, &value) != -1) {
      fprintf(fp, "Key: %s, Value: %s\n", key, value);
      fflush(fp);
    }
  }
  return 0;
}
