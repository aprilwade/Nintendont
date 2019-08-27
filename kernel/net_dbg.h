#ifndef _NET_DBG_H_
#define _NET_DBG_H_

void NetDbgInit();
void NetDbgCleanUp();

int NetDbgSendMsg(void* msg, int len);

#endif
