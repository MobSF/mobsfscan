# -*- coding: utf_8 -*-
"""Logger Config."""
import sys
import logging

from colorama import Back, Fore, Style


class ColorLogsWrapper(object):
    COLOR_MAP = {
        'debug': Fore.BLUE,
        'info': Fore.CYAN,
        'warning': Fore.YELLOW,
        'error': Fore.RED,
        'critical': Back.RED,
    }

    def __init__(self, logger):
        self.logger = logger

    def __getattr__(self, attr_name):
        """Getattr."""
        if attr_name == 'info':
            attr_name = 'info'
        if attr_name not in 'debug info warning error critical':
            return getattr(self.logger, attr_name)
        log_level = getattr(logging, attr_name.upper())
        # mimicking logging/__init__.py behaviour
        if not self.logger.isEnabledFor(log_level):
            return

        def wrapped_attr(msg, *args, **kwargs):
            style_prefix = self.COLOR_MAP[attr_name]
            msg = style_prefix + str(msg) + Style.RESET_ALL
            # We call _.log directly to not increase the callstack
            # so that Logger.findCaller extract the corrects filename/lineno
            return self.logger._log(log_level, msg, args, **kwargs)
        return wrapped_attr


def init_logger(module_name) -> logging.Logger:
    """Setup logger."""
    log_format = '%(message)s'
    logging.basicConfig(stream=sys.stderr,
                        format=log_format,
                        level=logging.INFO)
    logger_obj = logging.getLogger(module_name)
    logger = ColorLogsWrapper(logger_obj)
    return logger
