"""
Advanced Plugin System for CyberWolfScanner
Provides enhanced plugin capabilities with configuration, dependencies, versioning,
lifecycle hooks, and event system.
"""

from abc import ABC, abstractmethod
import logging
import json
import os
import importlib
import pkgutil
import inspect
from typing import Dict, List, Any, Optional, Callable, Set, Tuple
from enum import Enum
import threading
import time
from datetime import datetime

# Define plugin lifecycle states
class PluginState(Enum):
    UNLOADED = "unloaded"
    LOADED = "loaded"
    INITIALIZED = "initialized"
    RUNNING = "running"
    PAUSED = "paused"
    STOPPED = "stopped"
    ERROR = "error"

# Define plugin categories
class PluginCategory(Enum):
    SCANNER = "scanner"
    ANALYZER = "analyzer"
    REPORTER = "reporter"
    UTILITY = "utility"
    INTEGRATION = "integration"
    CUSTOM = "custom"

class PluginMetadata:
    """Metadata for plugin description and management"""
    
    def __init__(self, 
                 name: str,
                 version: str = "1.0.0",
                 description: str = "",
                 author: str = "",
                 website: str = "",
                 category: PluginCategory = PluginCategory.CUSTOM,
                 tags: List[str] = None,
                 dependencies: List[str] = None,
                 config_schema: Dict[str, Any] = None):
        self.name = name
        self.version = version
        self.description = description
        self.author = author
        self.website = website
        self.category = category
        self.tags = tags or []
        self.dependencies = dependencies or []
        self.config_schema = config_schema or {}
        self.created_at = datetime.now().isoformat()
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert metadata to dictionary"""
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "author": self.author,
            "website": self.website,
            "category": self.category.value,
            "tags": self.tags,
            "dependencies": self.dependencies,
            "config_schema": self.config_schema,
            "created_at": self.created_at
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PluginMetadata':
        """Create metadata from dictionary"""
        category = PluginCategory(data.get("category", "custom"))
        return cls(
            name=data.get("name", "Unknown"),
            version=data.get("version", "1.0.0"),
            description=data.get("description", ""),
            author=data.get("author", ""),
            website=data.get("website", ""),
            category=category,
            tags=data.get("tags", []),
            dependencies=data.get("dependencies", []),
            config_schema=data.get("config_schema", {})
        )

class PluginEvent:
    """Event class for plugin communication"""
    
    def __init__(self, event_type: str, source: str, data: Any = None):
        self.event_type = event_type
        self.source = source
        self.data = data
        self.timestamp = datetime.now().isoformat()
        
    def __str__(self) -> str:
        return f"PluginEvent({self.event_type}, from={self.source}, time={self.timestamp})"

class AdvancedPlugin(ABC):
    """Enhanced base plugin class with advanced features"""
    
    def __init__(self):
        # Initialize basic properties
        self._state = PluginState.UNLOADED
        self._config = {}
        self._event_handlers = {}
        self._last_run_time = None
        self._last_run_duration = None
        self._error = None
        
        # Set up metadata
        self._metadata = self._get_metadata()
        
        # Initialize logging
        self._logger = logging.getLogger(f"plugin.{self._metadata.name}")
        
        # Change state to loaded
        self._state = PluginState.LOADED
        
    @abstractmethod
    def _get_metadata(self) -> PluginMetadata:
        """Return plugin metadata"""
        pass
    
    @property
    def name(self) -> str:
        """Get plugin name"""
        return self._metadata.name
    
    @property
    def metadata(self) -> PluginMetadata:
        """Get plugin metadata"""
        return self._metadata
    
    @property
    def state(self) -> PluginState:
        """Get current plugin state"""
        return self._state
    
    @property
    def config(self) -> Dict[str, Any]:
        """Get plugin configuration"""
        return self._config
    
    def configure(self, config: Dict[str, Any]) -> None:
        """Configure the plugin with provided settings"""
        # Validate configuration against schema
        self._validate_config(config)
        # Update configuration
        self._config.update(config)
        self._logger.debug(f"Plugin {self.name} configured with: {config}")
        
    def _validate_config(self, config: Dict[str, Any]) -> bool:
        """Validate configuration against schema"""
        # Basic validation - can be enhanced with JSON Schema validation
        schema = self._metadata.config_schema
        for key, spec in schema.items():
            if key in config:
                # Check type if specified
                if 'type' in spec:
                    expected_type = spec['type']
                    if expected_type == 'string' and not isinstance(config[key], str):
                        raise ValueError(f"Config '{key}' must be a string")
                    elif expected_type == 'number' and not isinstance(config[key], (int, float)):
                        raise ValueError(f"Config '{key}' must be a number")
                    elif expected_type == 'boolean' and not isinstance(config[key], bool):
                        raise ValueError(f"Config '{key}' must be a boolean")
                    elif expected_type == 'array' and not isinstance(config[key], list):
                        raise ValueError(f"Config '{key}' must be an array")
                    elif expected_type == 'object' and not isinstance(config[key], dict):
                        raise ValueError(f"Config '{key}' must be an object")
                
                # Check required
                if spec.get('required', False) and (config[key] is None or config[key] == ''):
                    raise ValueError(f"Config '{key}' is required and cannot be empty")
                
                # Check enum values
                if 'enum' in spec and config[key] not in spec['enum']:
                    raise ValueError(f"Config '{key}' must be one of: {spec['enum']}")
        
        return True
    
    def initialize(self) -> bool:
        """Initialize the plugin"""
        try:
            self._state = PluginState.INITIALIZED
            self._logger.info(f"Plugin {self.name} initialized")
            return True
        except Exception as e:
            self._state = PluginState.ERROR
            self._error = str(e)
            self._logger.error(f"Failed to initialize plugin {self.name}: {str(e)}")
            return False
    
    @abstractmethod
    def run(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """Run the plugin with the given target and options"""
        pass
    
    def execute(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """Execute the plugin with timing and state management"""
        if self._state not in [PluginState.INITIALIZED, PluginState.STOPPED]:
            raise RuntimeError(f"Plugin {self.name} is not in a runnable state: {self._state}")
        
        options = options or {}
        self._state = PluginState.RUNNING
        start_time = time.time()
        
        try:
            # Emit starting event
            self._emit_event("plugin.starting", {"target": target, "options": options})
            
            # Run the plugin
            result = self.run(target, options)
            
            # Update timing information
            end_time = time.time()
            self._last_run_time = datetime.now().isoformat()
            self._last_run_duration = end_time - start_time
            
            # Update state
            self._state = PluginState.STOPPED
            
            # Emit completed event
            self._emit_event("plugin.completed", {"result": result})
            
            return result
        except Exception as e:
            # Handle errors
            end_time = time.time()
            self._last_run_time = datetime.now().isoformat()
            self._last_run_duration = end_time - start_time
            self._state = PluginState.ERROR
            self._error = str(e)
            
            # Emit error event
            self._emit_event("plugin.error", {"error": str(e)})
            
            self._logger.error(f"Error executing plugin {self.name}: {str(e)}", exc_info=True)
            return {"error": str(e)}
    
    def register_event_handler(self, event_type: str, handler: Callable[[PluginEvent], None]) -> None:
        """Register an event handler"""
        if event_type not in self._event_handlers:
            self._event_handlers[event_type] = []
        self._event_handlers[event_type].append(handler)
    
    def _emit_event(self, event_type: str, data: Any = None) -> None:
        """Emit an event to registered handlers"""
        event = PluginEvent(event_type, self.name, data)
        
        # Call handlers for this event type
        handlers = self._event_handlers.get(event_type, [])
        for handler in handlers:
            try:
                handler(event)
            except Exception as e:
                self._logger.error(f"Error in event handler for {event_type}: {str(e)}")
        
        # Call handlers for wildcard events
        wildcard_handlers = self._event_handlers.get("*", [])
        for handler in wildcard_handlers:
            try:
                handler(event)
            except Exception as e:
                self._logger.error(f"Error in wildcard event handler for {event_type}: {str(e)}")
    
    def get_ui_components(self) -> Dict[str, Any]:
        """Get UI components for plugin configuration"""
        # Default implementation returns config schema
        return {
            "config_schema": self._metadata.config_schema,
            "name": self.name,
            "description": self._metadata.description
        }
    
    def cleanup(self) -> None:
        """Clean up resources used by the plugin"""
        self._state = PluginState.UNLOADED
        self._logger.info(f"Plugin {self.name} cleaned up")
