#!/usr/bin/env python3

from accessmask import AccessMask, main


class FileAccessMask(AccessMask):

    VALID_RIGHTS = 0x001F01FF

    RIGHTS = [
        {'abbr': 'FR', 'name': 'FILE_GENERIC_READ', 'val': 0x80000000, 'desc': 'Generic right to read (mapped to FILE_READ_ATTRIBUTES | FILE_READ_DATA | FILE_READ_EA | SYNCHRONIZE | READ_CONTROL)'},
        {'abbr': 'GR', 'name': 'GENERIC_READ', 'val': 0x80000000, 'desc': 'Generic right to read (mapped to FILE_READ_ATTRIBUTES | FILE_READ_DATA | FILE_READ_EA | SYNCHRONIZE | READ_CONTROL)'},
        {'abbr': 'FW', 'name': 'FILE_GENERIC_WRITE', 'val': 0x40000000, 'desc': 'Generic right to write (mapped to FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_DATA | FILE_WRITE_EA | SYNCHRONIZE | READ_CONTROL)'},
        {'abbr': 'GW', 'name': 'GENERIC_WRITE', 'val': 0x40000000, 'desc': 'Generic right to write (mapped to FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_DATA | FILE_WRITE_EA | SYNCHRONIZE | READ_CONTROL)'},
        {'abbr': 'FX', 'name': 'FILE_GENERIC_EXECUTE', 'val': 0x20000000, 'desc': 'Generic right to execute (mapped to FILE_EXECUTE | FILE_READ_ATTRIBUTES | SYNCHRONIZE | READ_CONTROL)'},
        {'abbr': 'GX', 'name': 'GENERIC_EXECUTE', 'val': 0x20000000, 'desc': 'Generic right to execute (mapped to FILE_EXECUTE | FILE_READ_ATTRIBUTES | SYNCHRONIZE | READ_CONTROL)'},
        {'abbr': 'GA', 'name': 'GENERIC_ALL', 'val': 0x10000000, 'desc': 'Generic right mapped to every other existing right'},
        {'abbr': 'FA', 'name': 'FILE_ALL_ACCESS', 'val': 0x1F01FF, 'desc': 'Every file right that existed when the requestor was compiled'},
        {'abbr': 'CC', 'name': 'FILE_READ_DATA', 'val': 0x1, 'desc': 'Read contents of the file'},
        {'abbr': 'DC', 'name': 'FILE_WRITE_DATA', 'val': 0x2, 'desc': 'Append or replace contents of the file'},
        {'abbr': 'LC', 'name': 'FILE_APPEND_DATA', 'val': 0x4, 'desc': 'Append contents to the end of the file'},
        {'abbr': 'SW', 'name': 'FILE_READ_EA', 'val': 0x8, 'desc': 'Read the file\'s extended attributes, if any'},
        {'abbr': 'RP', 'name': 'FILE_WRITE_EA', 'val': 0x10, 'desc': 'Write the file\'s extended attributes, if any'},
        {'abbr': 'WP', 'name': 'FILE_EXECUTE', 'val': 0x20, 'desc': 'Execute the file'},
        {'abbr': 'LO', 'name': 'FILE_READ_ATTRIBUTES', 'val': 0x80, 'desc': 'Read the file\'s attributes'},
        {'abbr': 'CR', 'name': 'FILE_WRITE_ATTRIBUTES', 'val': 0x100, 'desc': 'Write the file\'s attributes'},
    ]


AccessMask.TYPES['file'] = FileAccessMask

if __name__ == '__main__':
    main(FileAccessMask)
