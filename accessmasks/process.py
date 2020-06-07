#!/usr/bin/env python3

from accessmask import AccessMask, main


class ProcessAccessMask(AccessMask):

    VALID_RIGHTS = 0x1FFFFF

    RIGHTS = [
        {'abbr': 'GR', 'name': 'GENERIC_READ', 'val': 0x00020410, 'desc': 'Generic right to read, mapped to PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | READ_CONTROL'},
        {'abbr': 'GW', 'name': 'GENERIC_WRITE', 'val': 0x00020BEA, 'desc': 'Generic right to write, mapped to PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_DUP_HANDLE | PROCESS_CREATE_PROCESS | PROCESS_SET_QUOTA | PROCESS_SET_INFORMATION | PROCESS_SUSPEND_RESUME | READ_CONTROL'},
        {'abbr': 'GX', 'name': 'GENERIC_EXECUTE', 'val': 0x00121001, 'desc': 'Generic right to execute, mapped to PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | SYNCHRONIZE | READ_CONTROL'},
        {'abbr': 'GA', 'name': 'GENERIC_ALL', 'val': 0x10000000, 'desc': 'Generic right mapped to every other existing right'},
        {'abbr': None, 'name': 'PROCESS_ALL_ACCESS', 'val': 0x1FFFFF, 'desc': 'All rights that existed when the requestor was compiled (was 0x1F0FFF before Vista)'},
        {'abbr': 'CC', 'name': 'PROCESS_TERMINATE', 'val': 0x1, 'desc': 'Terminate the process'},
        {'abbr': 'DC', 'name': 'PROCESS_CREATE_THREAD', 'val': 0x2, 'desc': 'Create a thread executing a chosen function and argument, also requires PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_WRITE and PROCESS_VM_READ'},
        {'abbr': 'LC', 'name': 'PROCESS_SET_SESSIONID', 'val': 0x4, 'desc': 'Undocumented usage'},
        {'abbr': 'SW', 'name': 'PROCESS_VM_OPERATION', 'val': 0x8, 'desc': 'Required to read or write to the process memory address space'},
        {'abbr': 'RP', 'name': 'PROCESS_VM_READ', 'val': 0x10, 'desc': 'Read from the process memory address space'},
        {'abbr': 'WP', 'name': 'PROCESS_VM_WRITE', 'val': 0x20, 'desc': 'Write to the process memory address space'},
        {'abbr': 'DT', 'name': 'PROCESS_DUP_HANDLE', 'val': 0x40, 'desc': 'Get copies of handles held by the process'},
        {'abbr': 'LO', 'name': 'PROCESS_CREATE_PROCESS', 'val': 0x80, 'desc': 'Create child processes inheriting the same primary token'},
        {'abbr': 'CR', 'name': 'PROCESS_SET_QUOTA', 'val': 0x100, 'desc': 'Set limits on the amount of memory the process can consume'},
        {'abbr': None, 'name': 'PROCESS_SET_INFORMATION', 'val': 0x200, 'desc': 'Set properties of the process, e.g. its priority'},
        {'abbr': None, 'name': 'PROCESS_QUERY_INFORMATION', 'val': 0x400, 'desc': 'Open the process primary token and read some properties, implies PROCESS_QUERY_LIMITED_INFORMATION'},
        {'abbr': None, 'name': 'PROCESS_SUSPEND_RESUME', 'val': 0x800, 'desc': 'Suspend or resume all threads of the process'},
        {'abbr': None, 'name': 'PROCESS_QUERY_LIMITED_INFORMATION', 'val': 0x1000, 'desc': 'Read some properties of the process'},
        {'abbr': None, 'name': 'PROCESS_SET_LIMITED_INFORMATION', 'val': 0x2000, 'desc': 'Set some properties of the process'},
    ]


AccessMask.TYPES['process'] = ProcessAccessMask

if __name__ == '__main__':
    main(ProcessAccessMask)
