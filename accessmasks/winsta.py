#!/usr/bin/env python3

from accessmask import AccessMask, main


class WindowStationAccessMask(AccessMask):

    VALID_RIGHTS = 0xF037F

    RIGHTS = [
        {'abbr': 'GR', 'name': 'GENERIC_READ', 'val': 0x80000000, 'desc': 'Generic right to read, mapped to WINSTA_READATTRIBUTES | WINSTA_ENUMDESKTOPS | WINSTA_ENUMERATE | READ_CONTROL, and WINSTA_READSCREEN if interactive'},
        {'abbr': 'GW', 'name': 'GENERIC_WRITE', 'val': 0x40000000, 'desc': 'Generic right to write, mapped to WINSTA_ACCESSCLIPBOARD | WINSTA_CREATEDESKTOP | READ_CONTROL, and WINSTA_WRITEATTRIBUTES if interactive'},
        {'abbr': 'GX', 'name': 'GENERIC_EXECUTE', 'val': 0x20000000, 'desc': 'Generic right to execute, mapped to WINSTA_ACCESSGLOBALATOMS | WINSTA_EXITWINDOWS | READ_CONTROL'},
        {'abbr': 'GA', 'name': 'GENERIC_ALL', 'val': 0x10000000, 'desc': 'Generic right mapped to every other existing right'},
        {'abbr': None, 'name': 'WINSTA_ALL_ACCESS', 'val': 0x37F, 'desc': 'All window station rights that existed when the requestor was compiled'},
        {'abbr': 'CC', 'name': 'WINSTA_ENUMDESKTOPS', 'val': 0x1, 'desc': 'Enumerate existing desktops in this station'},
        {'abbr': 'DC', 'name': 'WINSTA_READATTRIBUTES', 'val': 0x2, 'desc': 'Read global properties'},
        {'abbr': 'LC', 'name': 'WINSTA_ACCESSCLIPBOARD', 'val': 0x4, 'desc': 'Read and write from the clipboard'},
        {'abbr': 'SW', 'name': 'WINSTA_CREATEDESKTOP', 'val': 0x8, 'desc': 'Create new desktop objects within the window station'},
        {'abbr': 'RP', 'name': 'WINSTA_WRITEATTRIBUTES', 'val': 0x10, 'desc': 'Modify settings global to the window station'},
        {'abbr': 'WP', 'name': 'WINSTA_ACCESSGLOBALATOMS', 'val': 0x20, 'desc': 'Read and write the global atom table'},
        {'abbr': 'DT', 'name': 'WINSTA_EXITWINDOWS', 'val': 0x40, 'desc': 'Log off the interactive user'},
        {'abbr': 'LO', 'name': 'WINSTA_ENUMERATE', 'val': 0x100, 'desc': 'See this object when enumerating window stations'},
        {'abbr': 'CR', 'name': 'WINSTA_READSCREEN', 'val': 0x200, 'desc': 'Access screen contents'},
    ]


AccessMask.TYPES['winsta'] = WindowStationAccessMask

if __name__ == '__main__':
    main(WindowStationAccessMask)
