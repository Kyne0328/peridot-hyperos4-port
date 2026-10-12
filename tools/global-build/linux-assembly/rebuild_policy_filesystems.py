#!/usr/bin/env python3
"""Explicit source-pinned selection of the two policy-bearing filesystems."""
import argparse
import rebuild_vendor_dev2 as V
PINS={'vendor':('c8bf2bf866e08644dd113adf55804bd867a00282346d7d5542ea3206e7eb771b',430030848),'system':('88142dce1788b9e105ebbc97b1945c0071fb840f827545a57c213b2e6298c32d',751255552)}
def select(partition):
 if partition not in PINS:raise ValueError('unsupported policy partition')
 V.PARTITION=partition;V.SOURCE_SHA,V.SOURCE_SIZE=PINS[partition];V.WORK=V.ROOT/(partition+'-dev2');V.TREE=V.WORK/'tree'
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('partition',choices=PINS);p.add_argument('action',choices=['extract']);a=p.parse_args();select(a.partition);V.extract()
