#!/usr/bin/env python3

from accessmask import AccessMask, main


class FileMappingAccessMask(AccessMask):

    VALID_RIGHTS = 0x1F001F

    RIGHTS = [
        {'abbr': None, 'name': 'SYNCHRONIZE', 'val': 0x100000, 'desc': '/!\\ Not supported by this object type'},
        {'abbr': 'GR', 'name': 'GENERIC_READ', 'val': 0x80000000, 'desc': 'Generic right to read, mapped to '},
        {'abbr': 'GW', 'name': 'GENERIC_WRITE', 'val': 0x40000000, 'desc': 'Generic right to write, mapped to '},
        {'abbr': 'GX', 'name': 'GENERIC_EXECUTE', 'val': 0x20000000, 'desc': 'Generic right to execute, mapped to '},
        {'abbr': 'GA', 'name': 'GENERIC_ALL', 'val': 0x10000000, 'desc': 'Generic right mapped to every other existing right'},
        {'abbr': None, 'name': 'FILE_MAP_ALL_ACCESS', 'val': 0xF001F, 'desc': 'All file mapping rights that existed when the requestor was compiled'},
        {'abbr': 'CC', 'name': '', 'val': 0x1, 'desc': 'Enumerate existing desktops in this station'},
        {'abbr': 'DC', 'name': 'FILE_MAP_WRITE', 'val': 0x2, 'desc': 'Create read-only, read-write, and copy-on-write views of this file mapping'},
        {'abbr': 'LC', 'name': 'FILE_MAP_READ', 'val': 0x4, 'desc': 'Create read-only and copy-on-write views of this file mapping'},
        {'abbr': 'SW', 'name': '', 'val': 0x8, 'desc': ''},
        {'abbr': 'RP', 'name': '', 'val': 0x10, 'desc': ''},
        {'abbr': 'WP', 'name': 'FILE_MAP_EXECUTE', 'val': 0x20, 'desc': 'Create executable views of this file mapping'},
        {'abbr': 'DT', 'name': '', 'val': 0x40, 'desc': ''},
        {'abbr': 'LO', 'name': '', 'val': 0x100, 'desc': ''},
        {'abbr': 'CR', 'name': '', 'val': 0x200, 'desc': ''},
    ]


AccessMask.TYPES['filemapping'] = FileMappingAccessMask

if __name__ == '__main__':
    main(FileMappingAccessMask)
