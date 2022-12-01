#
# Description:  Binary Ninja plugin to decompile all the codebase in Pseudo C
# and dump it into a folder, though File / Export will also work for some
# cases instead of using this plugin, depending on what you are trying to achieve.
#
# Author: Asher Davila (@asher_davila)
# https://github.com/AsherDLL/PCDump-bn
#

import os
import platform
import re

from binaryninja.binaryview import BinaryView
from binaryninja.enums import DisassemblyOption, FunctionAnalysisSkipOverride
from binaryninja.function import DisassemblySettings, Function
from binaryninja.interaction import get_directory_name_input
from binaryninja.lineardisassembly import LinearViewCursor, LinearViewObject
from binaryninja.log import log_alert, log_error, log_info, log_warn
from binaryninja.plugin import BackgroundTaskThread, PluginCommand


class PseudoCDump(BackgroundTaskThread):
    MAX_PATH = 255
    FILE_SUFFIX = 'c'

    def __init__(self, bv: BinaryView, msg: str, destination_path: str):
        BackgroundTaskThread.__init__(self, msg, can_cancel=True)
        self.bv = bv
        self.destination_path = destination_path

    def _get_function_name(self, function: Function) -> str:
        function_symbol = self.bv.get_symbol_at(function.start)

        if hasattr(function_symbol,
                   'short_name') and (len(self.destination_path) + len(
                       function_symbol.short_name)) <= self.MAX_PATH:
            return function_symbol.short_name
        elif len(self.destination_path) + len(
                'sub_%x' % (function.start)) <= self.MAX_PATH:
            return 'sub_%x' % (function.start)
        else:
            if hasattr(function_symbol, 'short_name'):
                raise ValueError(
                    'File name too long for function: '
                    f'{function_symbol.short_name!r}\n Try using a different path'
                )
            else:
                raise ValueError(
                    'File name too long for function: '
                    f'sub_{function.start:x}\n Try using a different path')

    def run(self) -> None:
        log_info(f'Number of functions to dump: {len(self.bv.functions)}')
        count = 1
        for function in self.bv.functions:
            function_name = self._get_function_name(function)
            log_info(f'Dumping function {function_name}')
            self.progress = "Dumping Pseudo C: %d/%d" % (
                count, len(self.bv.functions))
            force_analysis(self.bv, function)
            pcode = get_pseudo_c(self.bv, function)
            destination = os.path.join(
                self.destination_path,
                normalize_destination_file(function_name, self.FILE_SUFFIX))
            with open(destination, 'wb') as file:
                file.write(bytes(pcode, 'utf-8'))
            count += 1
        log_alert('Done')


def normalize_destination_file(destination_file: str,
                               filename_suffix: str) -> str:
    if 'Windows' in platform.system():
        normalized_destination_file = '.'.join(
            (re.sub(r'[><:"/\\|\?\*]', '_',
                    destination_file), filename_suffix))
        return normalized_destination_file
    else:
        normalized_destination_file = '.'.join(
            (re.sub(r'/', '_', destination_file), filename_suffix))
        return normalized_destination_file


def force_analysis(bv: BinaryView, function: Function):
    ''' Force analysis of the function if Binja skipped it'''
    if function is not None and function.analysis_skipped:
        log_warn(
            ''
            f'Analyzing skipped function {bv.get_symbol_at(function.start)}')
        function.analysis_skip_override = FunctionAnalysisSkipOverride.NeverSkipFunctionAnalysis
        bv.update_analysis_and_wait()


def get_pseudo_c(bv: BinaryView, function: Function) -> str:
    lines = []
    settings = DisassemblySettings()
    settings.set_option(DisassemblyOption.ShowAddress, False)
    settings.set_option(DisassemblyOption.WaitForIL, True)
    obj = LinearViewObject.language_representation(bv, settings)
    cursor_end = LinearViewCursor(obj)
    cursor_end.seek_to_address(function.highest_address)
    body = bv.get_next_linear_disassembly_lines(cursor_end)
    cursor_end.seek_to_address(function.highest_address)
    header = bv.get_previous_linear_disassembly_lines(cursor_end)

    for line in header:
        lines.append(f'{str(line)}\n')

    for line in body:
        lines.append(f'{str(line)}\n')

    lines_of_code = ''.join(lines)
    return (lines_of_code)


def dump_pseudo_c(bv: BinaryView, action: int) -> None:
    destination_path = get_directory_name_input('Destination')

    if destination_path == None:
        log_error(''
                  'No directory was provided to save the decompiled Pseudo C')
        return

    dump = PseudoCDump(bv, 'Starting the Pseudo C Dump..', destination_path)
    dump.start()


PluginCommand.register_for_address('Pseudo C Dump',
                                   'Dumps Pseudo C for the whole code base',
                                   dump_pseudo_c)
