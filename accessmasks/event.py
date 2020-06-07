#!/usr/bin/env python3

from accessmask import AccessMask, main


class EventAccessMask(AccessMask):

    VALID_RIGHTS = 0x1F0003

    RIGHTS = [
        {'abbr': 'GR', 'name': 'GENERIC_READ', 'val': 0x80000000, 'desc': 'Generic right to read, mapped to <unknown bit 1> | READ_CONTROL' },
        {'abbr': 'GW', 'name': 'GENERIC_WRITE', 'val': 0x40000000, 'desc': 'Generic right to write, mapped to EVENT_MODIFY_STATE | READ_CONTROL' },
        {'abbr': 'GX', 'name': 'GENERIC_EXECUTE', 'val': 0x20000000, 'desc': 'Generic right to execute, mapped to SYNCHRONIZE | READ_CONTROL' },
        {'abbr': 'GA', 'name': 'GENERIC_ALL', 'val': 0x10000000, 'desc': 'Generic right mapped to every other existing right' },
        {'abbr': None, 'name': 'EVENT_ALL_ACCESS', 'val': 0x1F0003, 'desc': 'All event rights that existed when the requestor was compiled' },
        {'abbr': 'DC', 'name': 'EVENT_MODIFY_STATE', 'val': 0x2, 'desc': 'Signal the event and acknowledge signals' },
    ]


AccessMask.TYPES['event'] = EventAccessMask

if __name__ == '__main__':
    main(EventAccessMask)
