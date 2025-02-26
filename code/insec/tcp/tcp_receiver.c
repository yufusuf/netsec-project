/* simpleserver.c 
   A very simple TCP socket server
 */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

int main(int argc,const char **argv)
{
  int serverPort = 8888;
  int rc;
  struct sockaddr_in serverSa;
  struct sockaddr_in clientSa;
  int clientSaSize;
  int on = 1;
  int c;
  int s = socket(PF_INET,SOCK_STREAM,0);
  rc = setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&on,sizeof on);
  /* initialize the server's sockaddr */
  memset(&serverSa,0,sizeof(serverSa));
  serverSa.sin_family = AF_INET;
  serverSa.sin_addr.s_addr = htonl(INADDR_ANY);
  serverSa.sin_port = htons(serverPort);
  rc = bind(s,(struct sockaddr *)&serverSa,sizeof(serverSa));
  if (rc < 0)
  {
    perror("bind failed");
    exit(1);
  }
  rc = listen(s,10);
  if (rc < 0)
  {
    perror("listen failed");
    exit(1);
  }
  rc = accept(s,(struct sockaddr *)&clientSa,&clientSaSize);
  if (rc < 0)
  {
    perror("accept failed");
    exit(1);
  }
  c = rc;
  rc = write(c,"hello client \n",13);
  close (s);
  close (c);
  return 0;
}