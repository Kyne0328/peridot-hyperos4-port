class BuilderError(RuntimeError):
    """Base exception for controlled builder failures."""


class RomValidationError(BuilderError):
    """The supplied ROM does not meet the expected input contract."""


class ToolUnavailableError(BuilderError):
    """A required external tool is not installed or discoverable."""


class ToolExecutionError(BuilderError):
    """An external tool returned a non-zero exit code."""
