"""Implement a default to plugin. Using Plugin inherited functions"""
from pollenisator.plugins.plugin import Plugin
from pollenisator.plugins.plugin_result import PluginResult


class Default(Plugin):
    """Attributes:
        autoDefect: a boolean indication that this plugin should be used to autodetect file.
    """
    autoDetect = False  # Override default True value
