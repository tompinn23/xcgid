#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv, char **envp) {
  char buf[256];
  snprintf(buf, sizeof(buf), "wk-output-%u", getpid());
  FILE *fp = fopen(buf, "w");
  fprintf(fp, "output");
  for(char **env = envp; *env != 0; env++) {
    fprintf(fp, "ENV: %s\n", *env);
  }
  fflush(fp);
  fclose(fp);
  return 0;
}

