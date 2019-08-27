
// #include <stddef.h>
#include "global.h"
#include "alloc.h"
#include "common.h"
#include "debug.h"
#include "ipc.h"
#include "string.h"
#include "syscalls.h"

#define IPC_REG_BASE 0x13026900

#define IPC_REG_CMD_PTR (IPC_REG_BASE + 0)


static int s_ios_ipc_thread;
static int s_ios_ipc_queue;
static u32 s_last_updated_time;
extern char __ios_ipc_stack_addr, __ios_ipc_stack_size;



static u32 IosIpcAlarm()
{
    while(1)
    {
        struct ipcmessage *msg = NULL;
        mqueue_recv(s_ios_ipc_queue, &msg, 0);
        mqueue_ack(msg, 0);
        // dbgprintf("IosIpcAlarm: %p (%d)\n", msg, msg->result);

        u32 cmd = *(u32*)(msg + 1);
        // dbgprintf("HERE! %d %d\n", cmd, msg->fd);
        if(cmd == IOS_READ) {
            if(msg->read.data && msg->read.length) {
                sync_after_write(msg->read.data, (msg->read.length + 31) & ~31u);
            }
        } else if(cmd == IOS_IOCTL) {
            if(msg->ioctl.buffer_io && msg->ioctl.length_io) {
                sync_after_write(msg->ioctl.buffer_io, (msg->ioctl.length_io + 31) & ~31u);
            }
        }  else if(cmd == IOS_IOCTLV) {
            int i;
            // for(i = 0; i < msg->ioctlv.argc_in + msg->ioctlv.argc_io; i++) {
            //     dbgprintf("IosIpcAlarm msgptr->ioctlv.argv[%d].data: %p\n", i, msg->ioctlv.argv[i].data);
            //     dbgprintf("IosIpcAlarm msgptr->ioctlv.argv[%d].len: %d\n", i, msg->ioctlv.argv[i].len);
            //     if(msg->ioctlv.argv[i].data && msg->ioctlv.argv[i].len) {
            //         int k;
            //         for(k = 0; k < msg->ioctlv.argv[i].len / 4; k++) {
            //             dbgprintf("IosIpcAlarm msgptr->ioctlv.argv[%d].data[%d]: %d\n", i, k, ((u32*)msg->ioctlv.argv[i].data)[k]);
            //         }
            //     }
            // }
            for(i = 0; i < msg->ioctlv.argc_in + msg->ioctlv.argc_in; i++) {
                if(msg->ioctlv.argv[i].data && msg->ioctlv.argv[i].len) {
                    sync_after_write(
                        msg->ioctlv.argv[i].data,
                        (msg->ioctlv.argv[i].len + 31) & ~31u
                    );
                }
            }
        } else if(cmd != IOS_OPEN && cmd != IOS_CLOSE) {
            int i;
            for(i = 0; i < (sizeof(struct ipcmessage) + 4) / 4; i++) {
                dbgprintf("msg word %d: %08x\n", i, ((u32*)msg)[i]);
            }
            for(i = 0; i < msg->ioctlv.argc_in + msg->ioctlv.argc_io; i++) {
                dbgprintf("IosIpcAlarm msgptr->ioctlv.argv[%d].data: %p\n", i, msg->ioctlv.argv[i].data);
                dbgprintf("IosIpcAlarm msgptr->ioctlv.argv[%d].len: %d\n", i, msg->ioctlv.argv[i].len);
                if(msg->ioctlv.argv[i].data && msg->ioctlv.argv[i].len) {
                    int k;
                    for(k = 0; k < msg->ioctlv.argv[i].len / 4; k++) {
                        dbgprintf("IosIpcAlarm msgptr->ioctlv.argv[%d].data[%d]: %d\n", i, k, ((u32*)msg->ioctlv.argv[i].data)[k]);
                    }
                }
            }
            break;
        }


        msg->command = 0xFF;
        sync_after_write(msg, sizeof(struct ipcmessage));
    }
    return 0;
}
#define dbgprintf(...)

void IosIpcInit()
{
    write32(IPC_REG_CMD_PTR, 0);
    sync_after_write((void*)IPC_REG_CMD_PTR, 0x20);

    u8 *soheap = malloca(32, 32);
    s_ios_ipc_queue = mqueue_create(soheap, 4);

    s_ios_ipc_thread = thread_create(
        IosIpcAlarm,
        NULL,
        ((u32*)&__ios_ipc_stack_addr),
        ((u32)(&__ios_ipc_stack_size)) / sizeof(u32),
        0x78,
        1
    );
    thread_continue(s_ios_ipc_thread);

    // XXX Is this neccessary?
    mdelay(100);

    s_last_updated_time = read32(HW_TIMER);

}

void IosIpcCleanup()
{
    thread_cancel(s_ios_ipc_thread, 0);
}


void IosIpcUpdate()
{
    // TODO: Only perform this check a fixed number of times per second
    //       Currently this is about 24000 times a second.
    //       Maybe it should be higher/lower?
    if(TimerDiffTicks(s_last_updated_time) > 8000) {
        s_last_updated_time = read32(HW_TIMER);
    } else {
        return;
    }

    sync_before_read((void*)IPC_REG_CMD_PTR, 0x20);
    struct ipcmessage *msg_ptr = (void*)read32(IPC_REG_CMD_PTR);

    if(msg_ptr == NULL){
        return;
    }

    write32(IPC_REG_CMD_PTR, 0);
    sync_after_write((void*)IPC_REG_CMD_PTR, 0x20);

    sync_before_read(msg_ptr, sizeof(struct ipcmessage) * 2);

    dbgprintf("IosIpc msg_ptr: %p\n", msg_ptr);
    dbgprintf("IosIpc msg_ptr->command: %d\n", msg_ptr->command);
    dbgprintf("IosIpc msg_ptr->fd: %d\n", msg_ptr->fd);

    int fd = msg_ptr->fd;

    msg_ptr->fd = msg_ptr->command;
    *(u32*)(msg_ptr + 1) = msg_ptr->command;
    sync_after_write(msg_ptr, sizeof(struct ipcmessage) * 2);

    switch(msg_ptr->command) {
        case IOS_OPEN:
            dbgprintf("msgptr->open.device: %p\n", msg_ptr->open.device);
            dbgprintf("IosIpc msgptr->open.device: \"%s\"\n", msg_ptr->open.device);
            IOS_OpenAsync(msg_ptr->open.device, msg_ptr->open.mode, s_ios_ipc_queue, msg_ptr);
            sync_before_read(msg_ptr->open.device, 0x40);
            break;
        case IOS_CLOSE: {
            IOS_CloseAsync(fd, s_ios_ipc_queue, msg_ptr);
            break;
        }
        case IOS_READ: {
            IOS_ReadAsync(
                fd,
                msg_ptr->read.data, msg_ptr->read.length,
                s_ios_ipc_queue, msg_ptr
            );
            break;
        }
        case IOS_WRITE: {
            IOS_WriteAsync(
                fd,
                msg_ptr->write.data, msg_ptr->write.length,
                s_ios_ipc_queue, msg_ptr
            );
            break;
        }
        case IOS_SEEK: {
            IOS_SeekAsync(
                fd,
                msg_ptr->seek.offset, msg_ptr->seek.offset,
                s_ios_ipc_queue, msg_ptr
            );
            break;
        }
        case IOS_IOCTL: {
            if(msg_ptr->ioctl.buffer_in && msg_ptr->ioctl.length_in) {
                sync_before_read(msg_ptr->ioctl.buffer_in, (msg_ptr->ioctl.length_in + 31) & ~31u);
            }
            if(msg_ptr->ioctl.buffer_io && msg_ptr->ioctl.length_io) {
                sync_before_read(msg_ptr->ioctl.buffer_io, (msg_ptr->ioctl.length_io + 31) & ~31u);
            }
            dbgprintf("IosIpc msgptr->ioctl.command: %d\n", msg_ptr->ioctl.command);
            dbgprintf("IosIpc msgptr->ioctl.length_in: %d\n", msg_ptr->ioctl.length_in);
            dbgprintf("IosIpc msgptr->ioctl.buffer_in: %p\n", msg_ptr->ioctl.buffer_in);
            sync_before_read(msg_ptr->ioctl.buffer_in, (msg_ptr->ioctl.length_in + 31) & ~31u);
            if(msg_ptr->ioctl.buffer_in) {
                int i;
                for(i = 0; i < msg_ptr->ioctl.length_in / 4; i++) {
                    dbgprintf("IosIpc msgptr->ioctl.buffer_in[%d]: %08x\n", i, msg_ptr->ioctl.buffer_in[i]);
                }
            }

            dbgprintf("IosIpc msgptr->ioctl.length_io: %d\n", msg_ptr->ioctl.length_io);
            dbgprintf("IosIpc msgptr->ioctl.buffer_io: %p\n", msg_ptr->ioctl.buffer_io);
            if(msg_ptr->ioctl.buffer_io) {
                int i;
                for(i = 0; i < msg_ptr->ioctl.length_io / 4; i++) {
                    dbgprintf("IosIpc msgptr->ioctl.bufffer_io[%d]: %08x\n", i, msg_ptr->ioctl.buffer_io[i]);
                }
            }
            IOS_IoctlAsync(
                fd,
                msg_ptr->ioctl.command,
                msg_ptr->ioctl.buffer_in, msg_ptr->ioctl.length_in,
                msg_ptr->ioctl.buffer_io, msg_ptr->ioctl.length_io,
                s_ios_ipc_queue, msg_ptr
            );
            break;
        }
        case IOS_IOCTLV: {
            dbgprintf("IosIpc msgptr->ioctlv.command: %d\n", msg_ptr->ioctlv.command);
            dbgprintf("IosIpc msgptr->ioctlv.argc_in: %d\n", msg_ptr->ioctlv.argc_in);
            dbgprintf("IosIpc msgptr->ioctlv.argc_io: %d\n", msg_ptr->ioctlv.argc_io);
            dbgprintf("IosIpc msgptr->ioctlv.argv: %p\n", msg_ptr->ioctlv.argv);
            sync_before_read(
                msg_ptr->ioctlv.argv,
                ((msg_ptr->ioctlv.argc_in + msg_ptr->ioctlv.argc_io) * 8 + 31) & ~31u
            );
            int i;
            for(i = 0; i < msg_ptr->ioctlv.argc_in + msg_ptr->ioctlv.argc_io; i++) {
                if(msg_ptr->ioctlv.argv[i].data && msg_ptr->ioctlv.argv[i].len) {
                    sync_before_read(
                        &msg_ptr->ioctlv.argv[i].data,
                        (msg_ptr->ioctlv.argv[i].len + 31) & ~31u
                    );
                }
            }

            for(i = 0; i < msg_ptr->ioctlv.argc_in + msg_ptr->ioctlv.argc_io; i++) {
                dbgprintf("IosIpc msgptr->ioctlv.argv[i].data: %p\n", msg_ptr->ioctlv.argv[i].data);
                dbgprintf("IosIpc msgptr->ioctlv.argv[i].len: %d\n", msg_ptr->ioctlv.argv[i].len);
            }
            IOS_IoctlvAsync(
                fd,
                msg_ptr->ioctlv.command,
                msg_ptr->ioctlv.argc_in, msg_ptr->ioctlv.argc_io,
                msg_ptr->ioctlv.argv,
                s_ios_ipc_queue, msg_ptr
            );
            break;
        }
        default:
            break;
    }
}
