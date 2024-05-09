#!/usr/bin/python
from __future__ import print_function
import numpy as np
import sys


def print_stats(arr, category=None):
  if not arr:
    return
  if category is not None:
    print("\tCategory " + category+":")
  else:
    print("\tUncategorized:") 
  #Set size
  print("\t\tSize: " + str(len(arr)))
  #Set avg
  print("\t\tAvg: " + str(np.average(arr)))
  #Set stddev
  print("\t\tStdev: " + str(np.std(arr)))
  #Set sum
  print("\t\tSum: " + str(np.sum(arr)))
  #Set median
  print("\t\tMedian: " + str(np.median(arr)))
  #Print empty line
  print("\n")  
     
def main():
  for infile in sys.argv[1:]:
    lines = []
    with open(infile) as f:
      lines = f.readlines()
    #lines = [i for i in open(infile, 'r').read()]
    categories = dict()
    nocat = []
    for idx, line in enumerate(lines):
      if line[0] == '#':
        continue
      try:
        nocat.append(float(line))
      except ValueError as err:
        split_line = line.split(' ')
        try:
          fval = float(split_line[1])
          if split_line[0] in categories:
            categories[split_line[0]].append(fval)
          else:
            categories[split_line[0]] = [fval]
        except IndexError as e:
          if split_line[0] == '\n':
            continue
          print("Line " + str(idx))
          print(split_line)
          raise e    
      
    #Print filename
    print("Stats for " + infile + ":")  
    print_stats(nocat)
    for cat in categories:
      print_stats(categories[cat], cat)

if __name__ == '__main__':
  main()
