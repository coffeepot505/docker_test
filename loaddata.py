#!/usr/bin/env python
import os
import sys
import time
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "nvdapi.settings")
import django
django.setup()
from xml_parser import *
from subprocess import call

range_from = 2002
range_to = 2016

for i in range(range_from, range_to+1):
	os.system("wget -O tmp/aux.zip https://static.nvd.nist.gov/feeds/xml/cve/2.0/nvdcve-2.0-%i.xml.zip" % i)
	os.system("unzip -o tmp/aux.zip -d tmp/")
	e = xml.etree.ElementTree.parse('tmp/nvdcve-2.0-%i.xml' % i).getroot()
	for entry in e:
		process_entry(entry)
