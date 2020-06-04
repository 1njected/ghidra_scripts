#!/usr/bin/env python
# dangerous_functions.py for Ghidra. 
# Converted from old IDA script found somewhere on the interwebz.

import os, sys, re
from xml.dom import minidom

dangerous_functions_file = os.path.dirname(str(getSourceFile())) + os.sep +  'dangerous_functions.xml'

print "Using: " + dangerous_functions_file

VERSION = 0.03
dangerous_functions = []


def parse_dangerous_functions_file(functions, filename):
	doc = minidom.parse(filename)
	parent = doc.documentElement
	
	children = [child for child in parent.childNodes if child.nodeType == 1]
	
	for child in children:
		if not child.hasAttribute("name"):
			print "Malformed XML element: no 'name' attribute."
			return False
		function_name = child.getAttribute("name")
		
		if not child.hasAttribute("warning"):
			print "Malformed XML element: no 'warning' attribute."
			return False
		warning = child.getAttribute("warning")
		
		if not child.hasAttribute("suggestion"):
			print "Malformed XML element: no 'suggestion' attribute"
			return False
		suggestion = child.getAttribute("suggestion")
		
		if not child.hasAttribute("type"):
			print "Malformed XML element: no 'type' attribute."
			return False
		childtype = child.getAttribute("type")
		
		if not child.hasAttribute("warning_level"):
			print "Malformed XML element: no 'warning_level' attribute."
			return False
		warning_level = child.getAttribute("warning_level")
		
		functions.append({ 'name' : function_name,
							'warning' : warning,
							'suggestion' : suggestion,
							'type' : childtype,
							'warning_level' : warning_level
						})
	return True

def is_dangerous_function(function_name):
	for dangerous_function in dangerous_functions:
		if dangerous_function["regex"].search(function_name):
			return True
	return False

def get_dangerous_function(function_name):
	for dangerous_function in dangerous_functions:
		if dangerous_function["regex"].search(function_name):
			return dangerous_function
	return False

def compile_dangerous_function_regexes():
	for dangerous_function in dangerous_functions:
		dangerous_function["regex"] = re.compile("^_*%s$" % dangerous_function["name"])

def find_dangerous_functions():
	if not parse_dangerous_functions_file(dangerous_functions, dangerous_functions_file):
		print "Error finding dangerous functions."
		return False
	
	compile_dangerous_function_regexes()
	
	cur_function = getFirstFunction() # Get first function from Ghidra
	while cur_function:
		if is_dangerous_function(cur_function.getName()):
				print "Found dangerous function %s found at %s" % (cur_function.getName(), cur_function.getEntryPoint())
				issue = get_dangerous_function(cur_function.getName())
				print "Warning: %s" % issue["warning"]
				print "Suggestion: %s" % issue["suggestion"]
				print "Vuln type: %s" % issue["type"]
		
		cur_function = getFunctionAfter(cur_function) # Get next function

find_dangerous_functions()