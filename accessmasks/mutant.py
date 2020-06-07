#!/usr/bin/env python3

from accessmask import AccessMask, main


class MutantAccessMask(AccessMask):

    VALID_RIGHTS = 0x1F0001

    RIGHTS = [
        {'abbr': 'GR', 'name': 'GENERIC_READ', 'val': 0x80000000, 'desc': 'Generic right to read, mapped to MUTANT_QUERY_STATE | READ_CONTROL'},
        {'abbr': 'GW', 'name': 'GENERIC_WRITE', 'val': 0x40000000, 'desc': 'Generic right to write, mapped to READ_CONTROL'},
        {'abbr': 'GX', 'name': 'GENERIC_EXECUTE', 'val': 0x20000000, 'desc': 'Generic right to execute, mapped to SYNCHRONIZE | READ_CONTROL'},
        {'abbr': 'GA', 'name': 'GENERIC_ALL', 'val': 0x10000000, 'desc': 'Generic right mapped to every other existing right'},
        {'abbr': None, 'name': 'MUTEX_ALL_ACCESS', 'val': 0x1F0001, 'desc': 'All mutex rights that existed when the requestor was compiled'},
        {'abbr': 'CC', 'name': 'MUTANT_QUERY_STATE', 'val': 0x1, 'desc': 'Reserved for future use (only SYNCHRONIZE is required to acquire/release a mutex)'},
        {'abbr': 'CC', 'name': 'MUTANT_MODIFY_STATE', 'val': 0x1, 'desc': 'Reserved for future use (only SYNCHRONIZE is required to acquire/release a mutex)'},
        {'abbr': 'CC', 'name': 'MUTEX_QUERY_STATE', 'val': 0x1, 'desc': 'Reserved for future use (only SYNCHRONIZE is required to acquire/release a mutex)'},
        {'abbr': 'CC', 'name': 'MUTEX_MODIFY_STATE', 'val': 0x1, 'desc': 'Reserved for future use (only SYNCHRONIZE is required to acquire/release a mutex)'},
    ]


AccessMask.TYPES['mutant'] = MutantAccessMask
AccessMask.TYPES['mutex'] = MutantAccessMask

if __name__ == '__main__':
    main(MutantAccessMask)
