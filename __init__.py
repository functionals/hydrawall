from __future__ import annotations

import logging
from ._builder import ProjectBuilder
from ._exceptions import (
    BuildBackendException,
    BuildException,
    BuildSystemTableValidationError,
    FailedProcessError,
    TypoWarning,
)
from ._types import ConfigSettings as ConfigSettingsType
from ._types import Distribution as DistributionType
from ._types import SubprocessRunner as RunnerType
from ._util import check_dependency

__version__ = '1.2.1'

__all__ = [
    '__version__',
    'BuildBackendException',
    'BuildException',
    'BuildSystemTableValidationError',
    'check_dependency',
    'ConfigSettingsType',
    'DistributionType',
    'FailedProcessError',
    'ProjectBuilder',
    'RunnerType',
    'TypoWarning',
]

def __dir__() -> list[str]:
    return __all__

# Logging configuration
logger = logging.getLogger("pypacker")
logger.setLevel(logging.WARNING)

class NiceFormatter(logging.Formatter):
    FORMATS = {
        logging.DEBUG: "%(module)s -> %(funcName)s -> %(lineno)d: %(message)s",
        logging.INFO: "%(message)s",
        logging.WARNING: "WARNING: %(module)s: %(lineno)d: %(message)s",
        logging.ERROR: "ERROR: %(module)s: %(lineno)d: %(message)s",
        "DEFAULT": "%(message)s",
    }

    def __init__(self):
        super().__init__(fmt="%(levelno)d: %(msg)s", datefmt=None, style="%")

    def format(self, record):
        format_orig = self._style._fmt
        self._style._fmt = self.FORMATS.get(record.levelno, self.FORMATS["DEFAULT"])
        result = super().format(record)
        self._style._fmt = format_orig
        return result

logger_streamhandler = logging.StreamHandler()
logger_formatter = NiceFormatter()
logger_streamhandler.setFormatter(logger_formatter)
logger.addHandler(logger_streamhandler)
