#!/usr/bin/env python3

from accessmask import AccessMask, main


class COMAccessMask(AccessMask):

    RIGHTS = [
        {'abbr': 'GR', 'name': 'GENERIC_READ', 'val': 0x80000000, 'desc': 'Generic right to read, mapped to READ_PROP | DS_LIST_OBJECT | ACTRL_DS_LIST | READ_CONTROL'},
        {'abbr': 'GW', 'name': 'GENERIC_WRITE', 'val': 0x40000000, 'desc': 'Generic right to write, mapped to WRITE_PROP | DS_SELF | READ_CONTROL'},
        {'abbr': 'GX', 'name': 'GENERIC_EXECUTE', 'val': 0x20000000, 'desc': 'Generic right to execute, mapped to ACTRL_DS_LIST | READ_CONTROL'},
        {'abbr': 'GA', 'name': 'GENERIC_ALL', 'val': 0x10000000, 'desc': 'Generic right mapped to every other existing right'},
        {'abbr': 'CC', 'name': 'COM_RIGHTS_EXECUTE', 'val': 0x1, 'desc': 'Legacy access right which must always be granted'},
        {'abbr': 'DC', 'name': 'COM_RIGHTS_EXECUTE_LOCAL', 'val': 0x2, 'desc': 'Access an existing instance locally'},
        {'abbr': 'LC', 'name': 'COM_RIGHTS_EXECUTE_REMOTE', 'val': 0x4, 'desc': 'Access an existing instance remotely'},
        {'abbr': 'SW', 'name': 'COM_RIGHTS_ACTIVATE_LOCAL', 'val': 0x8, 'desc': 'Create a new instance locally'},
        {'abbr': 'RP', 'name': 'COM_RIGHTS_ACTIVATE_REMOTE', 'val': 0x10, 'desc': 'Create a new instance remotely'},
    ]


AccessMask.TYPES['com'] = COMAccessMask

if __name__ == '__main__':
    main(COMAccessMask)
