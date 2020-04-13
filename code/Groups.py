import json
import sys

class Groups(object):
    """Persistently stores groups as JSON files"""
    def __init__(self, fp):
        self.fp = fp
        self.groups = dict();
        fp.seek(0)
        js = fp.read()
        if js is not '':
            self.groups = json.loads(js)
        else:
            self.groups = {}

    def flush(self):
        self.fp.seek(0)
        self.fp.truncate()
        json.dump(self.groups, self.fp)
        print("flushing")
        json.dump(self.groups, sys.stdout)
        self.fp.flush()

    def add_group(self, gname):
        if gname not in self.groups:
            self.groups[gname] = []

    def add_user(self, uname, gname):
        self.add_group(gname)
        group = self.groups[gname]
        if uname not in group:
            group.append(uname)

    def remove_user(self, uname, gname):
        if gname in self.groups:
            group = self.groups[gname]
            if uname in group:
                group.remove(uname)
            if len(group) == 0:
                del self.groups[gname]

    def get_users(self, gname):
        return self.groups.get(gname,[])