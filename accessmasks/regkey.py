#!/usr/bin/env python3

from accessmask import AccessMask, main


class RegKeyAccessMask(AccessMask):

    VALID_RIGHTS = 0x1F003F

    RIGHTS = [
        {'abbr': 'GR', 'name': 'GENERIC_READ', 'val': 0x80000000, 'desc': 'Generic right to read, mapped to KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY | READ_CONTROL'},
        {'abbr': 'GW', 'name': 'GENERIC_WRITE', 'val': 0x40000000, 'desc': 'Generic right to write, mapped to KEY_CREATE_SUB_KEY | KEY_SET_VALUE | READ_CONTROL'},
        {'abbr': 'GX', 'name': 'GENERIC_EXECUTE', 'val': 0x20000000, 'desc': 'Generic right to execute, mapped to KEY_CREATE_LINK | KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY | READ_CONTROL'},
        {'abbr': 'GA', 'name': 'GENERIC_ALL', 'val': 0x10000000, 'desc': 'Generic right mapped to every other existing right'},
        {'abbr': 'KA', 'name': 'KEY_ALL_ACCESS', 'val': 0xF003F, 'desc': 'All rights that existed when the requestor was compiled'},
        {'abbr': 'CC', 'name': 'KEY_QUERY_VALUE', 'val': 0x1, 'desc': 'Query value names and data in the registry key'},
        {'abbr': 'DC', 'name': 'KEY_SET_VALUE', 'val': 0x2, 'desc': 'Create, delete, and replace values in the registry key'},
        {'abbr': 'LC', 'name': 'KEY_CREATE_SUB_KEY', 'val': 0x4, 'desc': 'Create a registry key inside this key'},
        {'abbr': 'SW', 'name': 'KEY_ENUMERATE_SUB_KEYS', 'val': 0x8, 'desc': 'Get a list of all registry keys within this key'},
        {'abbr': 'RP', 'name': 'KEY_NOTIFY', 'val': 0x10, 'desc': 'Subscribe to changes in this key and its subkeys'},
        {'abbr': 'WP', 'name': 'KEY_CREATE_LINK', 'val': 0x20, 'desc': 'Create a symbolic link key within this key'},
        {'abbr': 'CR', 'name': 'KEY_WOW64_64KEY', 'val': 0x100, 'desc': 'Access 64-bit keys on a 64-bit Windows, since Windows 2000'},
        {'abbr': None, 'name': 'KEY_WOW64_32KEY', 'val': 0x200, 'desc': 'Access 32-bit keys on a 64-bit Windows, since Windows 2000'},
        {'abbr': 'KR', 'name': 'KEY_READ', 'val': 0x20019, 'desc': 'Alias for KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY | READ_CONTROL'},
        {'abbr': 'KX', 'name': 'KEY_EXECUTE', 'val': 0x20019, 'desc': 'Alias for KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY | READ_CONTROL'},
        {'abbr': 'KW', 'name': 'KEY_WRITE', 'val': 0x20006, 'desc': 'Equivalent to KEY_SET_VALUE | KEY_CREATE_SUB_KEY | READ_CONTROL'},
    ]


AccessMask.TYPES['regkey'] = RegKeyAccessMask

if __name__ == '__main__':
    main(RegKeyAccessMask)
