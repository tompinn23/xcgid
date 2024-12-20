#include "xcgi/xcgi.h"

int main(int argc, char **argv) {
  xcgi ctx;

  if(xcgi_init(&ctx) < 0) {
    return -1;
  }

  int rc = 0;
  while((rc = xcgi_accept(&ctx)) != -1) {
    
  }
  return 0;
}
