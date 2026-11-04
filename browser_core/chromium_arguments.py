"""Classify already-tokenized Chromium arguments, without rewriting user values.

Matches pinned base/command_line.cc (AppendSwitchesAndArguments, IsSwitch,
AppendSwitchNative) and base/strings/whitespace_constants.h. This is not a shell
parser: Popen receives an argv list. Keep duplicates so every supplied override
is checked, regardless of which later value Chromium would retain.
"""
from __future__ import annotations

from dataclasses import dataclass
import sys

_WINDOWS = sys.platform == 'win32'
_ASCII_WHITESPACE = '\t\v\f \n\r'
_WINDOWS_WHITESPACE = (_ASCII_WHITESPACE + '\u0085\u00a0\u1680'
                       + ''.join(chr(code) for code in range(0x2000, 0x200b))
                       + '\u2028\u2029\u202f\u205f\u3000')
_LOWER_ASCII = str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')


@dataclass(frozen=True)
class ChromiumArguments:
    switches: tuple[str, ...]
    positional: tuple[str, ...]


def classify_arguments(arguments: tuple[str, ...], *, windows: bool | None = None) -> ChromiumArguments:
    """Return canonical switch keys and Chromium-trimmed positional arguments.

    Only an exact trimmed ``--`` ends switch parsing. An ordinary positional
    argument does not end it. The first terminator is not a startup target;
    later terminators are positional. Windows folds ASCII names, not values.
    ``single-argument`` is identified here and refused by the managed launcher,
    since its raw-command-line mode cannot preserve exact argv target ownership.
    """
    windows = _WINDOWS if windows is None else windows
    whitespace = _WINDOWS_WHITESPACE if windows else _ASCII_WHITESPACE
    prefixes = ('--', '-', '/') if windows else ('--', '-')
    switches, positional = [], []
    parse_switches = True
    for value in arguments:
        argument = value.strip(whitespace)
        if parse_switches and argument == '--':
            parse_switches = False
            continue
        prefix = next((prefix for prefix in prefixes if argument.startswith(prefix)), '')
        if parse_switches and prefix and len(argument) > len(prefix):
            name = argument[len(prefix):].split('=', 1)[0]
            switches.append(name.translate(_LOWER_ASCII) if windows else name)
        else:
            positional.append(argument)
    return ChromiumArguments(tuple(switches), tuple(positional))
