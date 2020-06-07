#!/usr/bin/env python3

from accessmask import AccessMask, main


class FileDirectoryAccessMask(AccessMask):

    VALID_RIGHTS = 0x001F01FF

    RIGHTS = [
        {'abbr': 'GR', 'name': 'FILE_GENERIC_READ', 'val': 0x80000000, 'desc': 'Generic right to read, mapped to FILE_READ_ATTRIBUTES | FILE_READ_DATA | FILE_READ_EA | SYNCHRONIZE | READ_CONTROL'},
        {'abbr': 'GR', 'name': 'GENERIC_READ', 'val': 0x80000000, 'desc': 'Generic right to read, mapped to FILE_READ_ATTRIBUTES | FILE_READ_DATA | FILE_READ_EA | SYNCHRONIZE | READ_CONTROL'},
        {'abbr': 'GW', 'name': 'FILE_GENERIC_WRITE', 'val': 0x40000000, 'desc': 'Generic right to write, mapped to FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_DATA | FILE_WRITE_EA | SYNCHRONIZE | READ_CONTROL'},
        {'abbr': 'GW', 'name': 'GENERIC_WRITE', 'val': 0x40000000, 'desc': 'Generic right to write, mapped to FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_DATA | FILE_WRITE_EA | SYNCHRONIZE | READ_CONTROL'},
        {'abbr': 'GX', 'name': 'FILE_GENERIC_EXECUTE', 'val': 0x20000000, 'desc': 'Generic right to execute, mapped to FILE_EXECUTE | FILE_READ_ATTRIBUTES | SYNCHRONIZE | READ_CONTROL'},
        {'abbr': 'GX', 'name': 'GENERIC_EXECUTE', 'val': 0x20000000, 'desc': 'Generic right to execute, mapped to FILE_EXECUTE | FILE_READ_ATTRIBUTES | SYNCHRONIZE | READ_CONTROL'},
        {'abbr': 'GA', 'name': 'GENERIC_ALL', 'val': 0x10000000, 'desc': 'Generic right mapped to every other existing right'},
        {'abbr': None, 'name': 'FILE_ALL_ACCESS', 'val': 0x1F01FF, 'desc': 'Every file right that existed when the requestor was compiled'},
        {'abbr': 'CC', 'name': 'FILE_LIST_DIRECTORY', 'val': 0x1, 'desc': 'List children of the directory'},
        {'abbr': 'DC', 'name': 'FILE_ADD_FILE', 'val': 0x2, 'desc': 'Add a child file to the directory'},
        {'abbr': 'LC', 'name': 'FILE_ADD_SUBDIRECTORY', 'val': 0x4, 'desc': 'Add a child directory to the directory'},
        {'abbr': 'SW', 'name': 'FILE_READ_EA', 'val': 0x8, 'desc': 'Read the directory\'s extended attributes, if any'},
        {'abbr': 'RP', 'name': 'FILE_WRITE_EA', 'val': 0x10, 'desc': 'Write the directory\'s extended attributes, if any'},
        {'abbr': 'WP', 'name': 'FILE_TRAVERSE', 'val': 0x20, 'desc': 'Access the directory\'s children, not required if SeChangeNotifyPrivilege is held'},
        {'abbr': 'DT', 'name': 'FILE_DELETE_CHILD', 'val': 0x40, 'desc': 'Delete any child of the directory'},
        {'abbr': 'LO', 'name': 'FILE_READ_EA', 'val': 0x80, 'desc': 'Read the directory\'s attributes'},
        {'abbr': 'CR', 'name': 'FILE_WRITE_EA', 'val': 0x100, 'desc': 'Write the directory\'s attributes'},
    ]


AccessMask.TYPES['filedir'] = FileDirectoryAccessMask
AccessMask.TYPES['directory'] = FileDirectoryAccessMask

if __name__ == '__main__':
    main(FileDirectoryAccessMask)
