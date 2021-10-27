# -*- coding: utf-8 -*-
#
# system-config documentation build configuration file
import datetime
import os
import sys
# -- General configuration ------------------------------------------------
# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
sys.path.insert(0, os.path.abspath('.'))
# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = ['zuul_sphinx']
# We have roles split between zuul-suitable roles at top level roles/*
# (automatically detected by zuul-sphinx) and playbook-specific roles
# (might have plugins, etc that make them unsuitable as potential zuul
# roles).  Document both.
zuul_role_paths = ['playbooks/roles']
# The suffix of source filenames.
source_suffix = '.rst'
# The master toctree document.
master_doc = 'index'
# General information about the project.
project = u'Openstack System Documentation'
copyright = ('%d, Openstack Contributors.' % datetime.date.today().year)
# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
exclude_patterns = ['_build']
# The name of the Pygments (syntax highlighting) style to use.
pygments_style = 'sphinx'
# -- Options for HTML output ----------------------------------------------
# This static content is used by the logo below
html_static_path = [
        '_static/',
    ]
# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
html_theme = 'alabaster'
html_theme_options = {
        'logo': 'openstack.png'
    }
# -- Options for LaTeX output ---------------------------------------------
# Grouping the document tree into LaTeX files. List of tuples
# (source start file, target name, title,
#  author, documentclass [howto, manual, or own class]).
latex_documents = [
  ('index', 'system-config.tex', u'system-config Documentation',
   u'OpenStack CI Log Processing team', 'manual'),
]
