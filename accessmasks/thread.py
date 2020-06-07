#!/usr/bin/env python3

from accessmask import AccessMask, main


class ThreadAccessMask(AccessMask):

    VALID_RIGHTS = 0x1FFFFF

    RIGHTS = [
        {'abbr': 'GR', 'name': 'GENERIC_READ', 'val': 0x80000000, 'desc': 'Generic right to read, mapped to THREAD_GET_INFORMATION | THREAD_GET_CONTEXT | READ_CONTROL'},
        {'abbr': 'GW', 'name': 'GENERIC_WRITE', 'val': 0x40000000, 'desc': 'Generic right to write, mapped to THREAD_SET_INFORMATION | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_TERMINATE | THREAD_SET_LIMITED_INFORMATION | Unknown bit 0x4 | READ_CONTROL'},
        {'abbr': 'GX', 'name': 'GENERIC_EXECUTE', 'val': 0x20000000, 'desc': 'Generic right to execute, mapped to THREAD_QUERY_LIMITED_INFORMATION | Unknown bit 0x1000 | SYNCHRONIZE | READ_CONTROL'},
        {'abbr': 'GA', 'name': 'GENERIC_ALL', 'val': 0x10000000, 'desc': 'Generic right mapped to every other existing right'},
        {'abbr': None, 'name': 'THREAD_ALL_ACCESS', 'val': 0x1FFFFF, 'desc': 'All rights that existed when the requestor was compiled (was 0x1F03FF before Vista)'},
        {'abbr': 'CC', 'name': 'THREAD_TERMINATE', 'val': 0x1, 'desc': 'Terminate the process'},
        {'abbr': 'DC', 'name': 'THREAD_SUSPEND_RESUME', 'val': 0x2, 'desc': 'Create a thread executing a chosen '},
        {'abbr': 'SW', 'name': 'THREAD_GET_CONTEXT', 'val': 0x8, 'desc': 'Required to read or write to the process memory address space'},
        {'abbr': 'RP', 'name': 'THREAD_SET_CONTEXT', 'val': 0x10, 'desc': 'Read from the process memory address space'},
        {'abbr': 'WP', 'name': 'THREAD_SET_INFORMATION', 'val': 0x20, 'desc': 'Write to the process memory address space'},
        {'abbr': 'DT', 'name': 'THREAD_QUERY_INFORMATION', 'val': 0x40, 'desc': 'Get copies of handles held by the process'},
        {'abbr': 'LO', 'name': 'THREAD_SET_THREAD_TOKEN', 'val': 0x80, 'desc': 'Create child processes inheriting the same primary token'},
        {'abbr': 'CR', 'name': 'THREAD_IMPERSONATE', 'val': 0x100, 'desc': 'Set limits on the amount of memory the process can consume'},
        {'abbr': None, 'name': 'THREAD_DIRECT_IMPERSONATION', 'val': 0x200, 'desc': 'Impersonate the impersonation token held by the thread (or its process primary token, if none)'},
        {'abbr': None, 'name': 'THREAD_SET_LIMITED_INFORMATION', 'val': 0x400, 'desc': 'Open the process primary token and read some properties, implies PROCESS_QUERY_LIMITED_INFORMATION'},
        {'abbr': None, 'name': 'THREAD_QUERY_LIMITED_INFORMATION', 'val': 0x800, 'desc': 'Suspend or resume all threads of the process'},
    ]


AccessMask.TYPES['thread'] = ThreadAccessMask

if __name__ == '__main__':
    main(ThreadAccessMask)
