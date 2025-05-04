"""
Advanced Plugin Manager for CyberWolfScanner
Manages the lifecycle of advanced plugins, handles dependencies,
and provides plugin discovery and event propagation.
"""

import os
import sys
import json
import logging
import importlib
import pkgutil
import inspect
from typing import Dict, List, Any, Optional, Set, Tuple, Type
import threading
from datetime import datetime
import time
import traceback

from core.advanced_plugin import AdvancedPlugin, PluginState, PluginEvent, PluginCategory, PluginMetadata

class AdvancedPluginManager:
    """Manager for advanced plugins with dependency resolution and event handling"""
    
    def __init__(self, plugins_dir: str = "plugins", config_dir: str = "config"):
        self.plugins_dir = plugins_dir
        self.config_dir = config_dir
        self.plugins: Dict[str, AdvancedPlugin] = {}
        self.plugin_classes: Dict[str, Type[AdvancedPlugin]] = {}
        self.plugin_modules: Dict[str, Any] = {}
        self.event_subscribers: Dict[str, List[AdvancedPlugin]] = {}
        self.logger = logging.getLogger("plugin_manager")
        
        # Create config directory if it doesn't exist
        os.makedirs(os.path.join(self.config_dir, "plugins"), exist_ok=True)
        
        # Initialize plugin discovery
        self._discover_plugins()
    
    def _discover_plugins(self) -> None:
        """Discover available plugins"""
        self.logger.info("Discovering plugins...")
        
        # Import the plugins package
        try:
            plugins_package = importlib.import_module(self.plugins_dir)
        except ImportError:
            self.logger.error(f"Could not import plugins package: {self.plugins_dir}")
            return
        
        # Iterate through all modules in the plugins package
        for _, name, is_pkg in pkgutil.iter_modules(plugins_package.__path__, f"{self.plugins_dir}."):
            if is_pkg:
                # Skip packages, we're looking for modules
                continue
                
            try:
                # Import the module
                module = importlib.import_module(name)
                self.plugin_modules[name] = module
                
                # Find all AdvancedPlugin subclasses in the module
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    
                    # Check if it's a class and a subclass of AdvancedPlugin
                    if (inspect.isclass(attr) and 
                        issubclass(attr, AdvancedPlugin) and 
                        attr is not AdvancedPlugin):
                        
                        # Create an instance of the plugin class
                        plugin_class = attr
                        self.plugin_classes[plugin_class.__name__] = plugin_class
                        self.logger.info(f"Discovered plugin class: {plugin_class.__name__}")
            
            except Exception as e:
                self.logger.error(f"Error loading plugin module {name}: {str(e)}")
                traceback.print_exc()
    
    def load_plugin(self, plugin_class_name: str) -> Optional[AdvancedPlugin]:
        """Load a plugin by class name"""
        if plugin_class_name in self.plugins:
            self.logger.warning(f"Plugin {plugin_class_name} is already loaded")
            return self.plugins[plugin_class_name]
        
        if plugin_class_name not in self.plugin_classes:
            self.logger.error(f"Plugin class {plugin_class_name} not found")
            return None
        
        try:
            # Create an instance of the plugin
            plugin_class = self.plugin_classes[plugin_class_name]
            plugin = plugin_class()
            
            # Load configuration if available
            self._load_plugin_config(plugin)
            
            # Initialize the plugin
            if not plugin.initialize():
                self.logger.error(f"Failed to initialize plugin {plugin.name}")
                return None
            
            # Register the plugin
            self.plugins[plugin.name] = plugin
            
            # Set up event handling
            self._setup_event_handling(plugin)
            
            self.logger.info(f"Loaded plugin: {plugin.name} v{plugin.metadata.version}")
            return plugin
            
        except Exception as e:
            self.logger.error(f"Error loading plugin {plugin_class_name}: {str(e)}")
            traceback.print_exc()
            return None
    
    def load_all_plugins(self) -> Dict[str, AdvancedPlugin]:
        """Load all discovered plugins with dependency resolution"""
        self.logger.info("Loading all plugins...")
        
        # Track loaded plugins and their dependencies
        loaded_plugins = {}
        dependency_graph = {}
        
        # Build dependency graph
        for plugin_class_name, plugin_class in self.plugin_classes.items():
            try:
                # Create temporary instance to get metadata
                temp_plugin = plugin_class()
                plugin_name = temp_plugin.name
                dependencies = temp_plugin.metadata.dependencies
                
                dependency_graph[plugin_name] = dependencies
            except Exception as e:
                self.logger.error(f"Error analyzing dependencies for {plugin_class_name}: {str(e)}")
        
        # Helper function for topological sort
        def load_with_dependencies(plugin_name):
            if plugin_name in loaded_plugins:
                return
            
            # Load dependencies first
            for dep in dependency_graph.get(plugin_name, []):
                if dep not in loaded_plugins:
                    load_with_dependencies(dep)
            
            # Find the class name for this plugin
            class_name = None
            for name, plugin_class in self.plugin_classes.items():
                try:
                    if plugin_class().name == plugin_name:
                        class_name = name
                        break
                except:
                    pass
            
            if class_name:
                plugin = self.load_plugin(class_name)
                if plugin:
                    loaded_plugins[plugin_name] = plugin
        
        # Load all plugins with dependencies
        for plugin_name in dependency_graph.keys():
            load_with_dependencies(plugin_name)
        
        return loaded_plugins
    
    def _load_plugin_config(self, plugin: AdvancedPlugin) -> None:
        """Load configuration for a plugin"""
        config_path = os.path.join(self.config_dir, "plugins", f"{plugin.name}.json")
        
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    config = json.load(f)
                plugin.configure(config)
                self.logger.debug(f"Loaded configuration for plugin {plugin.name}")
            except Exception as e:
                self.logger.error(f"Error loading configuration for plugin {plugin.name}: {str(e)}")
    
    def save_plugin_config(self, plugin_name: str, config: Dict[str, Any]) -> bool:
        """Save configuration for a plugin"""
        if plugin_name not in self.plugins:
            self.logger.error(f"Cannot save config for unknown plugin: {plugin_name}")
            return False
        
        plugin = self.plugins[plugin_name]
        
        try:
            # Validate configuration
            plugin._validate_config(config)
            
            # Save to file
            config_path = os.path.join(self.config_dir, "plugins", f"{plugin_name}.json")
            with open(config_path, 'w') as f:
                json.dump(config, f, indent=2)
            
            # Update plugin configuration
            plugin.configure(config)
            
            self.logger.info(f"Saved configuration for plugin {plugin_name}")
            return True
        except Exception as e:
            self.logger.error(f"Error saving configuration for plugin {plugin_name}: {str(e)}")
            return False
    
    def _setup_event_handling(self, plugin: AdvancedPlugin) -> None:
        """Set up event handling for a plugin"""
        # Register a wildcard handler to propagate events to the manager
        plugin.register_event_handler("*", self._handle_plugin_event)
    
    def _handle_plugin_event(self, event: PluginEvent) -> None:
        """Handle events emitted by plugins"""
        self.logger.debug(f"Received event: {event}")
        
        # Propagate event to subscribers
        subscribers = self.event_subscribers.get(event.event_type, [])
        subscribers.extend(self.event_subscribers.get("*", []))
        
        for subscriber in subscribers:
            if subscriber.name != event.source:  # Don't send back to source
                try:
                    # Call the plugin's event handlers directly
                    for handler in subscriber._event_handlers.get(event.event_type, []):
                        handler(event)
                    for handler in subscriber._event_handlers.get("*", []):
                        handler(event)
                except Exception as e:
                    self.logger.error(f"Error propagating event to {subscriber.name}: {str(e)}")
    
    def subscribe_to_event(self, plugin_name: str, event_type: str) -> bool:
        """Subscribe a plugin to an event type"""
        if plugin_name not in self.plugins:
            self.logger.error(f"Unknown plugin: {plugin_name}")
            return False
        
        if event_type not in self.event_subscribers:
            self.event_subscribers[event_type] = []
        
        plugin = self.plugins[plugin_name]
        if plugin not in self.event_subscribers[event_type]:
            self.event_subscribers[event_type].append(plugin)
            self.logger.debug(f"Plugin {plugin_name} subscribed to event: {event_type}")
        
        return True
    
    def execute_plugin(self, plugin_name: str, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """Execute a plugin with the given target and options"""
        if plugin_name not in self.plugins:
            self.logger.error(f"Unknown plugin: {plugin_name}")
            return {"error": f"Unknown plugin: {plugin_name}"}
        
        plugin = self.plugins[plugin_name]
        return plugin.execute(target, options)
    
    def get_plugin_info(self, plugin_name: str) -> Dict[str, Any]:
        """Get information about a plugin"""
        if plugin_name not in self.plugins:
            self.logger.error(f"Unknown plugin: {plugin_name}")
            return {"error": f"Unknown plugin: {plugin_name}"}
        
        plugin = self.plugins[plugin_name]
        
        return {
            "name": plugin.name,
            "metadata": plugin.metadata.to_dict(),
            "state": plugin.state.value,
            "last_run_time": plugin._last_run_time,
            "last_run_duration": plugin._last_run_duration,
            "error": plugin._error,
            "config": plugin.config
        }
    
    def get_all_plugins_info(self) -> List[Dict[str, Any]]:
        """Get information about all loaded plugins"""
        return [self.get_plugin_info(name) for name in self.plugins]
    
    def unload_plugin(self, plugin_name: str) -> bool:
        """Unload a plugin"""
        if plugin_name not in self.plugins:
            self.logger.error(f"Unknown plugin: {plugin_name}")
            return False
        
        plugin = self.plugins[plugin_name]
        
        try:
            # Clean up plugin resources
            plugin.cleanup()
            
            # Remove from event subscribers
            for event_type, subscribers in self.event_subscribers.items():
                if plugin in subscribers:
                    subscribers.remove(plugin)
            
            # Remove from plugins dict
            del self.plugins[plugin_name]
            
            self.logger.info(f"Unloaded plugin: {plugin_name}")
            return True
        except Exception as e:
            self.logger.error(f"Error unloading plugin {plugin_name}: {str(e)}")
            return False
    
    def unload_all_plugins(self) -> None:
        """Unload all plugins"""
        plugin_names = list(self.plugins.keys())
        for name in plugin_names:
            self.unload_plugin(name)
    
    def reload_plugin(self, plugin_name: str) -> bool:
        """Reload a plugin"""
        if plugin_name not in self.plugins:
            self.logger.error(f"Unknown plugin: {plugin_name}")
            return False
        
        # Get the class name
        plugin = self.plugins[plugin_name]
        class_name = plugin.__class__.__name__
        
        # Unload the plugin
        if not self.unload_plugin(plugin_name):
            return False
        
        # Reload the module
        module_name = self.plugin_modules.keys()[list(self.plugin_classes.values()).index(plugin.__class__)]
        try:
            module = importlib.reload(self.plugin_modules[module_name])
            self.plugin_modules[module_name] = module
            
            # Update the class reference
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if (inspect.isclass(attr) and 
                    issubclass(attr, AdvancedPlugin) and 
                    attr.__name__ == class_name):
                    self.plugin_classes[class_name] = attr
        except Exception as e:
            self.logger.error(f"Error reloading module for plugin {plugin_name}: {str(e)}")
            return False
        
        # Load the plugin again
        if self.load_plugin(class_name):
            self.logger.info(f"Reloaded plugin: {plugin_name}")
            return True
        else:
            return False
