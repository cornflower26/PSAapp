#!/usr/bin/bash

set -e

#Parameters
EXECUTABLE=ppsa
PLAIN_BITS=16
ITERATIONS=32
PACKING_SIZE=1 #Not sure what this is supposed to be
TMPFILE=./.temp
STATS_PROGRAM=stats.py

#Make sure the necessary files exist
file $EXECUTABLE
file $STATS_PROGRAM

LOW=1000
HIGH=1000000
DELTA=10

for ((i = $LOW ; i <= $HIGH ; i*=$DELTA)); do
  $EXECUTABLE -i $ITERATIONS -n $i -t $PLAIN_BITS -p $PACKING_SIZE | python $STATS_PROGRAM > $TMPFILE
  echo "Results for $i users:"
  cat $TMPFILE
  rm $TMPFILE
  echo -e "\n"
done
