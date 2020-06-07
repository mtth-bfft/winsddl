#!/usr/bin/env python3

from accessmask import AccessMask, main


class MandatoryLabelPolicy(AccessMask):

    VALID_RIGHTS = 0x7

    RIGHTS = [
        {'abbr': 'NW', 'name': 'SYSTEM_MANDATORY_LABEL_NO_WRITE_UP', 'val': 0x1, 'desc': 'Lower integrity levels cannot write to the object'},
        {'abbr': 'NR', 'name': 'SYSTEM_MANDATORY_LABEL_NO_READ_UP', 'val': 0x2, 'desc': 'Lower integrity levels cannot read the object'},
        {'abbr': 'NX', 'name': 'SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP', 'val': 0x4, 'desc': 'Lower integrity levels cannot execute the object'},
    ]


if __name__ == '__main__':
    main(MandatoryLabelPolicy)
