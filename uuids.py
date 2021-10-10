uuids = """c2cd31ed27134010a0dedfc817a341b7
1b2522dbd2c942dc8830e53dc7e9b7f8
08d8cf0b62364dd18f81bc08ca5c8c4d"""

import uuid

for i in uuids.splitlines(keepends=False):
    print(uuid.UUID(hex=i))