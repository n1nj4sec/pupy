#!/usr/bin/env python
# -*- coding: UTF8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

from . import conf
import logging

class PupyCategories(object):
	def __init__(self, pupsrv):
		self.pupsrv=pupsrv
		self.categories={} #sorted by category
		for c in conf.categories:
			self.categories[c]=[]
		self.shell_list=[]
		self.parse_categories()

	def parse_categories(self):
		#init categories dic
		for mod in self.pupsrv.iter_modules():
			if mod.category:
				cat=mod.category
			else:
				cat="general"
			if not cat in self.get_categories():
				logging.warning("Undefined category \"%s\" for module %s"%(mod.category, mod.get_name()))
				self.categories["general"].append(mod)
			else:
				self.categories[cat].append(mod)
			#fill shell_list for fast auto-completion:
			self.shell_list.append("%s/%s"%(cat,mod.get_name()))

	def get_module_from_path(self, shell_path):
		""" take a auto-completed path and return the corresponding module """
		tab=shell_path.strip('/').split('/')
		if len(tab)==2:
			for mod in self.categories[tab[0]]:
				if mod.get_name()==tab[1]:
					return mod

	def get_categories(self):
		return conf.categories

	def get_modules_by_category(self, category, system=None):
		""" return all modules in a category. Also filter by os if system is not None """
		if system is None:
			return self.categories[category]
		else:
			l=[]
			for mod in self.categories[category]:
				if system in mod.compatible_systems:
					l.append(mod)
			return l

	def get_shell_list(self, start_text):
		""" return a list of modules sorted for shell auto completion """
		return [x for x in self.shell_list if x.startswith(start_text)]



