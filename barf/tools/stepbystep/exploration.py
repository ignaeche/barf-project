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
