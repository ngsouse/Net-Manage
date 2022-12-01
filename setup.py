#!/usr/bin/env python3

# flake8: noqa

import ansible_runner
import collectors as cl
import datetime as dt
# import dtale
import helpers as hp
import importlib
import ipywidgets as widgets
import jupyterlab_widgets
import os
import pandas as pd
import readline
import run_collectors as rc
import validators as vl

from IPython.display import clear_output
from IPython.display import display

# Reload helper modules after changes. Mostly used for development.
importlib.reload(cl)
importlib.reload(hp)
importlib.reload(rc)
importlib.reload(vl)

# Do not write history to .python_history to protect credentials
readline.write_history_file = lambda *args: None

# Defining these variables now allows the user to update selections later
collector_select = dict()
hostgroup_select = dict()

# Set Pandas display settings
pd.set_option('display.max_rows', 50)
pd.set_option('display.max_columns', None)
pd.set_option('display.width', 1000)
pd.set_option('display.colheader_justify', 'center')
pd.set_option('display.precision', 3)

# Define several functions that need to be run within Jupyter
def create_collectors_df(collector_select, hostgroup_select):
    '''
    Creates a dataframe of collectors to execute. Each row contains the
    ansible_os, hostgroup, and collector.

    Args:
        collector_select(dict):    A dictionary of selected collectors
        hostgroup_select (dict):   A dictionary of selected hostgroups

    Returns:
        df_collectors (DataFrame): A dataframe of collectors to run
    '''
    
    df_data = dict()
    df_data['ansible_os'] = list()
    df_data['hostgroup'] = list()
    df_data['collector'] = list()

    for key, value in hostgroup_select.items():
        for item in value:
            if item.value == True:
                collectors = [c.description for c in collector_select.get(key) if \
                              c.value == True]
                for c in collectors:
                    df_data['ansible_os'].append(key)
                    df_data['hostgroup'].append(item.description)
                    df_data['collector'].append(c)
    df_collectors = pd.DataFrame.from_dict(df_data)
    return df_collectors

def select_collectors(collector_select, hostgroup_select):
    '''
    Selects the collectors for the selected hostgroups.

    Args:
        collector_select (dict): The collectors the user selected. The first
                                 time this is run, it will be an empty
                                 dictionary. Passing it to the function
                                 allows the user to select additional
                                 hostgroups later without losing their
                                 selected collectors.
        hostgroup_select (dict): The hostgroups the user selected

    Returns:
        collector_select (dict): A dictionary of collectors to select
    '''
    for key, value in hostgroup_select.items():
        for item in value:
            if item.value == True:
                if not collector_select.get(key):
                    available = hp.define_collectors(key)
                    collector_select[key] = [widgets.Checkbox(value=False,
                                                              description=c,
                                                              disabled=False,
                                                              indent=False) for c in available]
    # Delete any hostgroups that do not have available selectors
    to_delete = list()
    for key, value in collector_select.items():
        if not value:
            to_delete.append(key)
    for item in to_delete:
        del collector_select[item]
                    
    # Delete any hostgroups that the user has de-selected
    for key, value in hostgroup_select.items():
        if collector_select.get(key):
            to_delete = True
            for item in hostgroup_select[key]:
                if item.value == True:
                    to_delete = False
            if to_delete:
                del collector_select[key]
    return collector_select

def select_hostgroups(private_data_dir):
    '''
    Selects the collectors for the selected hostgroups.

    Args:
        collector_select (dict): The collectors the user selected. The first
                                 time this is run, it will be an empty
                                 dictionary. Passing it to the function
                                 allows the user to select additional
                                 hostgroups later without losing their
                                 selected collectors.
        hostgroup_select (dict): The hostgroups the user selected
        private_data_dir (str):  The path to the Ansible private data directory

    Returns:
        collector_select (dict): A dictionary of collectors to select
    '''
    # Define and select hostgroups
    groups = hp.ansible_group_hostgroups_by_os(private_data_dir)    
    for key, value in groups.items():
        if not hostgroup_select.get(key):
            hostgroup_select[key] = [widgets.Checkbox(value=False,
                                                      description=h,
                                                      disabled=False,
                                                      indent=False) for h in value]
    return hostgroup_select