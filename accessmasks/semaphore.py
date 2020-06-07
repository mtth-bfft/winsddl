#!/usr/bin/env python3

from accessmask import AccessMask, main


class SemaphoreAccessMask(AccessMask):

    VALID_RIGHTS = 0x1F0003

    RIGHTS = [
        {'abbr': 'GR', 'name': 'GENERIC_READ', 'val': 0x80000000, 'desc': 'Generic right to read, mapped to <unknown bit 1> | READ_CONTROL'},
        {'abbr': 'GW', 'name': 'GENERIC_WRITE', 'val': 0x40000000, 'desc': 'Generic right to write, mapped to SEMAPHORE_MODIFY_STATE | READ_CONTROL'},
        {'abbr': 'GX', 'name': 'GENERIC_EXECUTE', 'val': 0x20000000, 'desc': 'Generic right to execute, mapped to SYNCHRONIZE | READ_CONTROL'},
        {'abbr': 'GA', 'name': 'GENERIC_ALL', 'val': 0x10000000, 'desc': 'Generic right mapped to every other existing right'},
        {'abbr': None, 'name': 'SYNCHRONIZE', 'val': 0x100000, 'desc': 'Acquire this semaphore, possibly blocking to wait'},
        {'abbr': None, 'name': 'SEMAPHORE_ALL_ACCESS', 'val': 0x1F0003, 'desc': 'All semaphore rights that existed when the requestor was compiled'},
        {'abbr': 'DC', 'name': 'SEMAPHORE_MODIFY_STATE', 'val': 0x2, 'desc': 'Release this semaphore (acquiring is done through wait functions and the SYNCHRONIZE access right)'},
    ]


AccessMask.TYPES['semaphore'] = SemaphoreAccessMask

if __name__ == '__main__':
    main(SemaphoreAccessMask)
