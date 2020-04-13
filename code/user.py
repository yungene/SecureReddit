import parsing
import secure_reddit
try:
    import Groups as g
except:
    import groups as g

class User(object):
    def __init__(self, username):
        self.username = username;
        self.reddit = None;
        self.key = None;
        try:
            self.fp = open('groups_' + self.username + '.json', 'a+')
            self.groups = g.Groups(self.fp);
        except IOError:
            print("Fatal error opening the groups file")
            raise IOError

    def __del__(self):
        self.fp.close()
