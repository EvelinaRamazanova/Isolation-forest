class Tree:
    def __init__(self, attr, split):
        self._attr = attr
        self._split = split

    def get_left(self):
        return self._left

    def get_right(self):
        return self._right

    def get_attr(self):
        return self._attr

    def get_split(self):
        return self._split

    def get_count(self):
        return self._count

    def set_left(self, left):
        self._left = left

    def set_right(self, right):
        self._right = right

    def set_attr(self, attr):
        self._attr = attr;

    def set_split(self, split):
        self._split = split;

    def set_count(self, count):
        self._count = count

    left = property(get_left, set_left)
    right = property(get_right, set_right)
    attr = property(get_attr, set_attr)
    split = property(get_split, set_split)
    count = property(get_count, set_count)

    
        
