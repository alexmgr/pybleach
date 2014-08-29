class Oracle(object):

  def __init__(self, *args, **kwargs):
    self.args = args
    self.kwargs = kwargs
  
  def query(self, *args, **kwargs):
    raise NotImplementedError("Override this method to query the padding oracle")

