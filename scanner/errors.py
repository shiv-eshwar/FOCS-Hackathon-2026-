"""Custom exception types for scanner."""


class ScannerError(RuntimeError):
    """Base scanner error."""


class ToolNotInstalledError(ScannerError):
    """Raised when syft/grype is unavailable."""


class ToolExecutionError(ScannerError):
    """Raised when external tool execution fails."""
