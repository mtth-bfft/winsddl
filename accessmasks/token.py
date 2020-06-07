#!/usr/bin/env python3

from accessmask import AccessMask, main


class TokenAccessMask(AccessMask):

    VALID_RIGHTS = 0x1F01FF

    RIGHTS = [
        {'abbr': 'GR', 'name': 'GENERIC_READ', 'val': 0x80000000, 'desc': 'Generic right to read, mapped to TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE | READ_CONTROL'},
        {'abbr': 'GW', 'name': 'GENERIC_WRITE', 'val': 0x40000000, 'desc': 'Generic right to write, mapped to TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_SESSIONID | READ_CONTROL'},
        {'abbr': 'GX', 'name': 'GENERIC_EXECUTE', 'val': 0x20000000, 'desc': 'Generic right to execute, mapped to TOKEN_IMPERSONATE | TOKEN_ASSIGN_PRIMARY | READ_CONTROL'},
        {'abbr': 'GA', 'name': 'GENERIC_ALL', 'val': 0x10000000, 'desc': 'Generic right mapped to every other existing right'},
        {'abbr': None, 'name': 'TOKEN_ALL_ACCESS', 'val': 0xF01FF, 'desc': 'Every thread right that existed when the requestor was compiled (was 0xF00FF before Windows 2000)'},
        {'abbr': 'CC', 'name': 'TOKEN_ASSIGN_PRIMARY', 'val': 0x1, 'desc': 'Create a process with that primary token (also requires TOKEN_DUPLICATE, TOKEN_QUERY, and holding the SeAssignPrimaryTokenPrivilege if the token is not a restricted version of the caller\'s token)'},
        {'abbr': 'DC', 'name': 'TOKEN_DUPLICATE', 'val': 0x2, 'desc': 'Add a child file to the directory'},
        {'abbr': 'LC', 'name': 'TOKEN_IMPERSONATE', 'val': 0x4, 'desc': 'Add a child directory to the directory'},
        {'abbr': 'SW', 'name': 'TOKEN_QUERY', 'val': 0x8, 'desc': 'Read properties from the token'},
        {'abbr': 'RP', 'name': 'TOKEN_QUERY_SOURCE', 'val': 0x10, 'desc': 'Query which component created the token (Lan Manager, RPC Server, Session Manager, etc.)'},
        {'abbr': 'WP', 'name': 'TOKEN_ADJUST_PRIVILEGES', 'val': 0x20, 'desc': 'Enable, disable, and remove existing privileges in the token'},
        {'abbr': 'DT', 'name': 'TOKEN_ADJUST_GROUPS', 'val': 0x40, 'desc': 'Enable and disable existing group SIDs in the token'},
        {'abbr': 'LO', 'name': 'TOKEN_ADJUST_DEFAULT', 'val': 0x80, 'desc': 'Replace the token\'s default Owner, default primary group, and default DACL'},
        {'abbr': 'CR', 'name': 'TOKEN_ADJUST_SESSIONID', 'val': 0x100, 'desc': 'Replace the token\'s session ID'},
    ]


AccessMask.TYPES['token'] = TokenAccessMask

if __name__ == '__main__':
    main(TokenAccessMask)
