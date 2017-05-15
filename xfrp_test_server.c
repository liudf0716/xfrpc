#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <event2/event.h>
#include <event2/bufferevent.h>

#define PORT 1986
#define BACKLOG 1000

void readcb(struct bufferevent *bufev, void *arg)
{
  char buf[256];
  size_t readlen;
  int res;

  readlen  = bufferevent_read(bufev, buf, sizeof(buf));
  res = bufferevent_write(bufev, buf, readlen);
}

void writecb(struct bufferevent *bufev, void *arg)
{
}

void errorcb(struct bufferevent *bufev, short event, void *arg)
{
  if (event & BEV_EVENT_EOF) {
    bufferevent_free(bufev);
    printf("Disconnect\n");
  } else if (event & BEV_EVENT_ERROR) {
    bufferevent_free(bufev);
    printf("Got error\n");
  } else if (event & BEV_EVENT_TIMEOUT) {
    printf("Timeout\n");
  }
}

void accept_handler(int fd, short event, void *arg)
{
  struct event_base *evbase;
  struct bufferevent *bufev;
  int sock;
  struct sockaddr_in addr;
  socklen_t addrlen;

  evbase = (struct event_base *)arg;

  if (event & EV_READ) {
    sock = accept(fd, (struct sockaddr*)&addr, &addrlen);
    bufev = bufferevent_socket_new(evbase, sock, BEV_OPT_CLOSE_ON_FREE);
    bufferevent_setcb(bufev, readcb, writecb, errorcb, NULL);
    bufferevent_enable(bufev, EV_READ | EV_WRITE);
  }
}

int main(int argc, char** argv)
{
  struct event_base *evbase;
  struct event *ev;
  struct sockaddr_in sin;
  int sock;

  memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = INADDR_ANY;
  sin.sin_port = htons(PORT);

  sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
  bind(sock, (struct sockaddr*)&sin, sizeof(sin));
  listen(sock, BACKLOG);

  evbase = event_base_new();
  ev = event_new(evbase, sock, EV_READ | EV_PERSIST, accept_handler, evbase);
  event_add(ev, NULL);
  event_base_dispatch(evbase);

  event_free(ev);
  event_base_free(evbase);
  return 0;
}
