#!/usr/bin/env python3

from accessmask import AccessMask, main


class ServiceAccessMask(AccessMask):

    VALID_RIGHTS = 0x1F0003

    RIGHTS = [
        {'abbr': 'GR', 'name': 'GENERIC_READ', 'val': 0x80000000, 'desc': 'Generic right to read, mapped to SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_INTERROGATE | SERVICE_ENUMERATE_DEPENDENTS | READ_CONTROL'},
        {'abbr': 'GW', 'name': 'GENERIC_WRITE', 'val': 0x40000000, 'desc': 'Generic right to write, mapped to SERVICE_CHANGE_CONFIG | READ_CONTROL'},
        {'abbr': 'GX', 'name': 'GENERIC_EXECUTE', 'val': 0x20000000, 'desc': 'Generic right to execute, mapped to SERVICE_START | SERVICE_STOP | SERVICE_PAUSE_CONTINUE | SERVICE_USER_DEFINED_CONTROL | READ_CONTROL'},
        {'abbr': 'GA', 'name': 'GENERIC_ALL', 'val': 0x10000000, 'desc': 'Generic right mapped to every other existing right'},
        {'abbr': None, 'name': 'SERVICE_ALL_ACCESS', 'val': 0xF01FF, 'desc': 'Every service right that existed when the requestor was compiled'},
        {'abbr': 'CC', 'name': 'SERVICE_QUERY_CONFIG', 'val': 0x1, 'desc': 'Query the service configuration'},
        {'abbr': 'DC', 'name': 'SERVICE_CHANGE_CONFIG', 'val': 0x2, 'desc': 'Modify the service configuration'},
        {'abbr': 'LC', 'name': 'SERVICE_QUERY_STATUS', 'val': 0x4, 'desc': 'Query the service status and wait for it to change'},
        {'abbr': 'SW', 'name': 'SERVICE_ENUMERATE_DEPENDENTS', 'val': 0x8, 'desc': 'Enumerate services which depend on the service'},
        {'abbr': 'RP', 'name': 'SERVICE_START', 'val': 0x10, 'desc': 'Start the service'},
        {'abbr': 'WP', 'name': 'SERVICE_STOP', 'val': 0x20, 'desc': 'Stop the service'},
        {'abbr': 'DT', 'name': 'SERVICE_PAUSE_CONTINUE', 'val': 0x40, 'desc': 'Pause and resume the service'},
        {'abbr': 'LO', 'name': 'SERVICE_INTERROGATE', 'val': 0x80, 'desc': 'Ask the service to report its status immediately'},
        {'abbr': 'CR', 'name': 'SERVICE_USER_DEFINED_CONTROL', 'val': 0x100, 'desc': 'Send the service a user-defined control code'},
    ]


AccessMask.TYPES['service'] = ServiceAccessMask

if __name__ == '__main__':
    main(ServiceAccessMask)
