#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <time.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>

#include <json-c/json.h>

#include <syslog.h>

#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <event2/event.h>
#include <event2/event_struct.h>

#include <openssl/md5.h>

#include "debug.h"
#include "client.h"
#include "uthash.h"
#include "const.h"
#include "session.h"
#include "uthash.h"

void new_session() {

}

void keepalive() {

}