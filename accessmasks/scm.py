#!/usr/bin/env python3

from accessmask import AccessMask, main


class SCMAccessMask(AccessMask):

    VALID_RIGHTS = 0x1F0003

    RIGHTS = [
        {'abbr': 'GR', 'name': 'GENERIC_READ', 'val': 0x80000000, 'desc': 'Generic right to read, mapped to SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_QUERY_LOCK_STATUS | READ_CONTROL'},
        {'abbr': 'GW', 'name': 'GENERIC_WRITE', 'val': 0x40000000, 'desc': 'Generic right to write, mapped to SC_MANAGER_CREATE_SERVICE | SC_MANAGER_MODIFY_BOOT_CONFIG | READ_CONTROL'},
        {'abbr': 'GX', 'name': 'GENERIC_EXECUTE', 'val': 0x20000000, 'desc': 'Generic right to execute, mapped to SC_MANAGER_CONNECT | SC_MANAGER_LOCK | READ_CONTROL'},
        {'abbr': 'GA', 'name': 'GENERIC_ALL', 'val': 0x10000000, 'desc': 'Generic right mapped to every other existing right'},
        {'abbr': None, 'name': 'SC_MANAGER_ALL_ACCESS', 'val': 0xF003F, 'desc': 'Every SCM right that existed when the requestor was compiled'},
        {'abbr': 'CC', 'name': 'SC_MANAGER_CONNECT', 'val': 0x1, 'desc': 'Connect to the service control manager'},
        {'abbr': 'DC', 'name': 'SC_MANAGER_CREATE_SERVICE', 'val': 0x2, 'desc': 'Create a service and add it to the SCM database'},
        {'abbr': 'LC', 'name': 'SC_MANAGER_ENUMERATE_SERVICE', 'val': 0x4, 'desc': 'Enumerate services and wait for service status changes'},
        {'abbr': 'SW', 'name': 'SC_MANAGER_LOCK', 'val': 0x8, 'desc': 'Acquire a lock on the SCM database'},
        {'abbr': 'RP', 'name': 'SC_MANAGER_QUERY_LOCK_STATUS', 'val': 0x10, 'desc': 'Read the lock status of the SCM database'},
        {'abbr': 'WP', 'name': 'SC_MANAGER_MODIFY_BOOT_CONFIG', 'val': 0x20, 'desc': 'Set the current boot configuration as acceptable/broken'},
    ]


AccessMask.TYPES['scm'] = SCMAccessMask

if __name__ == '__main__':
    main(SCMAccessMask)
