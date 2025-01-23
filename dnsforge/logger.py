#############################################################################
#   Copyright 2024 Aon plc
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#############################################################################

import logging as log

from termcolor import colored


def setup_logging(verbose):
    if verbose:
        log.basicConfig(format="%(message)s", level=log.DEBUG)
    else:
        log.basicConfig(format="%(message)s", level=log.INFO)


def log_info(message, color="green"):
    log.info(colored(message, color))


def log_debug(message, color="yellow"):
    log.debug(colored(message, color))


def log_error(message, color="red"):
    log.error(colored(message, color))
