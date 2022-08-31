#!/bin/python3

from bcc import BPF
import signal
import sys

class ReqData:
    __slots__ = ['timestamp', 'sys_num', 'type', 'flag', 'len', 'issue', 'complete']

    def __init__(self, other):
        for name in self.__slots__:
            self.__setattr__(name, other.__getattribute__(name))

def print_cvs(type, data, file):
    print(','.join(type.__slots__), file=file)
    for event in data:
        data = map(lambda name: str(event.__getattribute__(name)), type.__slots__)
        print(','.join(data), file=file)

if __name__ == '__main__':
    prefix = sys.argv[1]

    with open('trace.c') as file:
        program = file.read()
        bpf = BPF(text=program)

        bpf.attach_kprobe(event='__page_cache_alloc', fn_name='trace_req_start')
        bpf.detach_kprobe(event='__page_cache_alloc', fn_name='trace_req_done')

        write = []

        def handler(sig=None, frame=None):
            print_cvs(ReqData, write, open(prefix + 'req.txt', 'w'))

            exit()

        signal.signal(signal.SIGINT, handler)

        def handle_write(cpu, omg_data, size):
            event = bpf['req_output'].event(omg_data)
            write.append(ReqData(event))

        bpf['req_output'].open_ring_buffer(handle_write)

        try:
            while 1:
                bpf.ring_buffer_poll()
        except KeyboardInterrupt:
            handler()