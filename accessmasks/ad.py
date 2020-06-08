#!/usr/bin/env python3

from accessmask import AccessMask, main


class ActiveDirectoryAccessMask(AccessMask):

    RIGHTS = [
        {'abbr': 'GR', 'name': 'GENERIC_READ', 'val': 0x80000000, 'desc': 'Generic right to read, mapped to READ_PROP | DS_LIST_OBJECT | ACTRL_DS_LIST | READ_CONTROL'},
        {'abbr': 'GW', 'name': 'GENERIC_WRITE', 'val': 0x40000000, 'desc': 'Generic right to write, mapped to WRITE_PROP | DS_SELF | READ_CONTROL'},
        {'abbr': 'GX', 'name': 'GENERIC_EXECUTE', 'val': 0x20000000, 'desc': 'Generic right to execute, mapped to ACTRL_DS_LIST | READ_CONTROL'},
        {'abbr': 'GA', 'name': 'GENERIC_ALL', 'val': 0x10000000, 'desc': 'Generic right mapped to every other existing right'},
        {'abbr': 'CC', 'name': 'ADS_RIGHT_DS_CREATE_CHILD', 'val': 0x1, 'desc': 'Create child objects'},
        {'abbr': 'DC', 'name': 'ADS_RIGHT_DS_DELETE_CHILD', 'val': 0x2, 'desc': 'Delete child objects'},
        {'abbr': 'LC', 'name': 'ADS_RIGHT_ACTRL_DS_LIST', 'val': 0x4, 'desc': 'List child objects'},
        {'abbr': 'SW', 'name': 'ADS_RIGHT_DS_SELF', 'val': 0x8, 'desc': 'Perform a validated write'},
        {'abbr': 'RP', 'name': 'ADS_RIGHT_DS_READ_PROP', 'val': 0x10, 'desc': 'Read properties'},
        {'abbr': 'WP', 'name': 'ADS_RIGHT_DS_WRITE_PROP', 'val': 0x20, 'desc': 'Write properties'},
        {'abbr': 'DT', 'name': 'ADS_RIGHT_DS_DELETE_TREE', 'val': 0x40, 'desc': 'Delete all child objects, no matter their DACL'},
        {'abbr': 'LO', 'name': 'ADS_RIGHT_DS_LIST_OBJECT', 'val': 0x80, 'desc': 'See this object, required if DS_LIST not held on the parent and 3rd character of dSHeuristics is 1'},
        {'abbr': 'CR', 'name': 'ADS_RIGHT_DS_CONTROL_ACCESS', 'val': 0x100, 'desc': 'Perform a controlled operation'},
    ]


AccessMask.TYPES['ad'] = ActiveDirectoryAccessMask

if __name__ == '__main__':
    main(ActiveDirectoryAccessMask)
