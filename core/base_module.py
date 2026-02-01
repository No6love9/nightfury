import abc

class BaseModule(metaclass=abc.ABCMeta):
    """Base class for all Nightfury modules."""
    
    def __init__(self, framework):
        self.framework = framework
        self.name = self.__class__.__name__
        self.description = "No description provided."
        self.options = {}

    @abc.abstractmethod
    def run(self, args):
        """Execute the module logic."""
        pass

    def set_option(self, name, value):
        """Set a module option."""
        self.options[name] = value

    def log(self, message, level="info"):
        """Log a message through the framework."""
        self.framework.log(f"[{self.name}] {message}", level)
