uuids = """2d8ef48c17c44a79842eb8fc25242763
c090561a74b64837bb6fdda73d84d698
08d8cf0b62364dd18f81bc08ca5c8c4d"""

import uuid

for i in uuids.splitlines(keepends=False):
    print(uuid.UUID(hex=i))