from tree import *
import math
import random

def itree(data, height, limit):
    if (height >= limit) or (len(data) < 2):
        node = Tree(0, 0)
        node.left = None
        node.right = None
        node.count = len(data)
        return node
    else:
        q = random.randint(0, len(data[0]) - 1)
        column = []
        for row in data:
            column.append(row[q])
        minValue = min(column)
        maxValue = max(column)
        p = (random.random() * (maxValue - minValue + 1)) + minValue
        left = []
        right = []
        for row in data:
            if row[q] < p:
                left.append(row)
            else:
                right.append(row)
        nodeIn = Tree(q, p)
        nodeIn.left = itree(left, height + 1, limit)
        nodeIn.right = itree(right, height + 1, limit)
        return nodeIn

def iforest(data, treesCount, size):
    forest = []
    limit = math.ceil(math.log(size) / math.log(2))

    sub = []
    for i in range(0, treesCount):
        for j in range(0, size):
            randValue = random.randint(0, len(data) - 1)
            sub.append(data[randValue])
        forest.append(itree(sub, 0, limit))
        
    return forest

def path(data, tree, height):
    if (tree.left == None) and (tree.right == None):
        if tree.count > 1:
            return height + 2 * (math.log(tree.count - 1) + 0.5772156649) - (2 * (tree.count - 1) / tree.count)
        else:
            return height
    if data[tree.attr] < tree.split:
        return path(data, tree.left, height + 1)
    else:
        return path(data, tree.right, height + 1)
        
