class ExplorationProcess(object):
    def __init__(self):
        self._is_explored = dict()
        self._to_explore  = dict()

    def add_to_explore(self,(jccs,inp)):
        x = hash(tuple(jccs))
        self._to_explore[x] = inp

    def add_to_explored(self,jccs):
        x = hash(tuple(jccs))
        #assert(x not in self._to_explore)

        if x in self._to_explore:
          del self._to_explore[x]

        self._is_explored[x] = None

    def was_explored(self,jccs):
        x = hash(tuple(jccs))
        r = (x in self._is_explored)

        return r

    def will_be_explored(self,jccs):
        x = hash(tuple(jccs))
        r = (x in self._to_explore)

        return r

    def new_to_explore(self):
        return len(self._to_explore) > 0

    def next_to_explore(self):
        (x,i) = self._to_explore.popitem()
        assert(x not in self._is_explored)
        self._is_explored[x] = i
        return x,i



"""
_is_explored = dict()
_to_explore  = dict()

def add_to_explore((b,i)):
  x = hash(tuple(b['tainted_instructions']))
  _to_explore[x] = i

def was_explored(b):
  x = hash(tuple(b['tainted_instructions']))
  r = (x in _is_explored)

  return r

def new_to_explore():
  return len(_to_explore) > 0

def next_to_explore():
  (x,i) = _to_explore.popitem()
  _is_explored[x] = i
  return x,i

def restart_exploration():
  _is_explored = dict()
  _to_explore  = dict()
"""
