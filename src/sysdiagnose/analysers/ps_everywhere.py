#! /usr/bin/env python3

from typing import Generator, Set, Optional
from sysdiagnose.utils.base import BaseAnalyserInterface, logger
from sysdiagnose.parsers.ps import PsParser
from sysdiagnose.parsers.psthread import PsThreadParser
from sysdiagnose.parsers.spindumpnosymbols import SpindumpNoSymbolsParser
from sysdiagnose.parsers.shutdownlogs import ShutdownLogsParser
from sysdiagnose.parsers.logarchive import LogarchiveParser
from sysdiagnose.parsers.logdata_statistics import LogDataStatisticsParser
from sysdiagnose.parsers.logdata_statistics_txt import LogDataStatisticsTxtParser
from sysdiagnose.parsers.uuid2path import UUID2PathParser
from sysdiagnose.parsers.taskinfo import TaskinfoParser
from sysdiagnose.parsers.remotectl_dumpstate import RemotectlDumpstateParser


class PsEverywhereAnalyser(BaseAnalyserInterface):
    """
    Analyser that gathers process information from multiple sources
    to build a comprehensive list of running processes across different system logs.
    """

    description = "List all processes we can find a bit everywhere."
    format = "jsonl"

    def __init__(self, config: dict, case_id: str):
        super().__init__(__file__, config, case_id)
        self.all_ps: Set[tuple] = set()  # Now stores tuples of (process, uid/euid)

    @staticmethod
    def _strip_flags(process: str) -> str:
        """
        Extracts the base command by removing everything after the first space.

        :param process: Full process command string.
        :return: Command string without flags.
        """
        process, *_ = process.partition(' ')
        return process

    @staticmethod
    def extract_euid_for_binary(message: str, binary_path: str) -> Optional[int]:
        """
        Extracts the euid for a specific binary_path from a message.
        Handles cases where multiple processes with different euids are mentioned.
        
        :param message: Log message containing process information with euid
        :param binary_path: The specific binary path to extract euid for
        :return: The euid as an integer, or None if not found
        """
        try:
            # Look for pattern: binary_path=/path/to/binary followed by euid=XXX
            # We need to find the specific binary_path and then its associated euid
            
            # Find all occurrences of the binary_path
            search_pattern = f'binary_path={binary_path}'
            start_pos = message.find(search_pattern)
            
            if start_pos == -1:
                return None
                
            # From this position, look backwards to find the associated euid
            # The euid appears before binary_path in the format: euid=XXX, binary_path=YYY
            
            # Get the substring before binary_path
            before_binary = message[:start_pos]
            
            # Find the last occurrence of euid= before this binary_path
            euid_pos = before_binary.rfind('euid=')
            if euid_pos == -1:
                return None
                
            # Extract the euid value
            euid_start = euid_pos + len('euid=')
            euid_end = message.find(',', euid_start)
            if euid_end == -1:
                euid_end = message.find(' ', euid_start)
            if euid_end == -1:
                euid_end = message.find('}', euid_start)
                
            if euid_end != -1:
                euid_str = message[euid_start:euid_end].strip()
            else:
                euid_str = message[euid_start:].strip()
                
            # Convert to integer
            return int(euid_str)
            
        except (ValueError, AttributeError) as e:
            logger.debug(f"Error extracting euid for binary {binary_path}: {e}")
            return None

    @staticmethod
    def message_extract_binary(process: str, message: str) -> Optional[list[dict]]:
        """
        Extracts process_name from special messages:
        1. backboardd Signpost messages with process_name
        2. tccd process messages with binary_path (now also returns euid)
        3. '/kernel' process messages with app name mapping format 'App Name -> /path/to/app'
        4. configd SCDynamicStore client sessions showing connected processes

        :param process: Process name.
        :param message: Log message potentially containing process information.
        :return: List of dicts with 'path' and optionally 'euid' keys, or None if not found
        """
        # Case 1: Backboardd Signpost messages
        if process == '/usr/libexec/backboardd' and 'Signpost' in message and 'process_name=' in message:
            try:
                # Find the process_name part in the message
                process_name_start = message.find('process_name=')
                if process_name_start != -1:
                    # Extract from after 'process_name=' to the next space or end of string
                    process_name_start += len('process_name=')
                    process_name_end = message.find(' ', process_name_start)

                    if process_name_end == -1:  # If no space after process_name
                        path = message[process_name_start:]
                    else:
                        path = message[process_name_start:process_name_end]
                    
                    return [{'path': path}]
            except Exception as e:
                logger.debug(f"Error extracting process_name from backboardd: {e}")

        # Case 2: TCCD process messages
        if process == '/System/Library/PrivateFrameworks/TCC.framework/Support/tccd' and 'binary_path=' in message:
            try:
                # Extract binary paths with their associated euids
                results = {}

                # Find all occurrences of binary_path= in the message
                start_pos = 0
                while True:
                    binary_path_start = message.find('binary_path=', start_pos)
                    if binary_path_start == -1:
                        break

                    binary_path_start += len('binary_path=')
                    # Find the end of the path (comma, closing bracket, or end of string)
                    binary_path_end = None
                    for delimiter in [',', '}', ' access to', ' is checking']:
                        delimiter_pos = message.find(delimiter, binary_path_start)
                        if delimiter_pos != -1 and (binary_path_end is None or delimiter_pos < binary_path_end):
                            binary_path_end = delimiter_pos

                    if binary_path_end is None:
                        path = message[binary_path_start:].strip()
                    else:
                        path = message[binary_path_start:binary_path_end].strip()

                    # Skip paths with excessive information
                    if len(path) > 0 and path.startswith('/') and ' ' not in path:
                        # Extract euid for this binary path
                        euid = PsEverywhereAnalyser.extract_euid_for_binary(message, path)
                        if euid is not None:
                            results[path] = {'euid': euid}
                        else:
                            results[path] = {}

                    # Move to position after the current binary_path
                    start_pos = binary_path_start + 1

                # Return results as list of dicts
                if results:
                    result_list = []
                    for path, info in results.items():
                        entry = {'path': path}
                        if 'euid' in info:
                            entry['euid'] = info['euid']
                        result_list.append(entry)
                    return result_list

            except Exception as e:
                logger.debug(f"Error extracting binary_path from tccd: {e}")

        # Case 3: /kernel process with App name mapping pattern "App Name -> /path/to/app"
        if process == '/kernel' and ' -> ' in message and 'App Store Fast Path' in message:
            try:
                # Find the arrow mapping pattern
                arrow_pos = message.find(' -> ')
                if arrow_pos != -1:
                    path_start = arrow_pos + len(' -> ')
                    # Look for common path patterns - more flexible for kernel messages
                    if message[path_start:].startswith('/'):
                        # Find the end of the path (space or end of string)
                        path_end = message.find(' ', path_start)
                        if path_end == -1:  # If no space after path
                            path = message[path_start:]
                        else:
                            path = message[path_start:path_end]
                        
                        return [{'path': path}]
            except Exception as e:
                logger.debug(f"Error extracting app path from kernel mapping: {e}")

        # Case 4: configd SCDynamicStore client sessions
        if process == '/usr/libexec/configd' and 'SCDynamicStore/client sessions' in message:
            try:
                # Process the list of connected clients from configd
                process_paths = []
                lines = message.split('\n')
                for line in lines:
                    line = line.strip()
                    if line.startswith('"') and '=' in line:
                        # Extract the client path from lines like ""/usr/sbin/mDNSResponder:null" = 1;"
                        client_path = line.split('"')[1]  # Get the part between the first pair of quotes
                        if ':' in client_path:
                            # Extract the actual process path part (before the colon)
                            process_path = client_path.split(':')[0]
                            if process_path.startswith('/') or process_path.startswith('com.apple.'):
                                process_paths.append(process_path)

                # Return the list of process paths if any were found
                if process_paths:
                    return [{'path': path} for path in process_paths]
            except Exception as e:
                logger.debug(f"Error extracting client paths from configd SCDynamicStore: {e}")

        return None

    def execute(self) -> Generator[dict, None, None]:
        """
        Executes all extraction methods dynamically, ensuring that each extracted process is unique.

        :yield: A dictionary containing process details from various sources.
        """
        for func in dir(self):
            if func.startswith(f"_{self.__class__.__name__}__extract_ps_"):
                yield from getattr(self, func)()  # Dynamically call extract methods

    def __extract_ps_base_file(self) -> Generator[dict, None, None]:
        """
        Extracts process data from ps.txt.

        :return: A generator yielding dictionaries containing process details from ps.txt.
        """
        entity_type = 'ps.txt'
        try:
            for p in PsParser(self.config, self.case_id).get_result():
                ps_event = {
                    'process': self._strip_flags(p['command']),
                    'timestamp': p['timestamp'],
                    'datetime': p['datetime'],
                    'source': entity_type
                }
                # Add uid if available
                if 'uid' in p:
                    ps_event['uid'] = p['uid']
                # Pass uid to uniqueness check
                uid_value = ps_event.get('uid')
                if self.add_if_full_command_is_not_in_set(ps_event['process'], uid_value):
                    yield ps_event
        except Exception as e:
            logger.exception(f"ERROR while extracting {entity_type} file. {e}")

    def __extract_ps_thread_file(self) -> Generator[dict, None, None]:
        """
        Extracts process data from psthread.txt.

        :return: A generator yielding dictionaries containing process details from psthread.txt.
        """
        entity_type = 'psthread.txt'
        try:
            for p in PsThreadParser(self.config, self.case_id).get_result():
                ps_event = {
                    'process': self._strip_flags(p['command']),
                    'timestamp': p['timestamp'],
                    'datetime': p['datetime'],
                    'source': entity_type
                }
                # Add uid if available
                if 'uid' in p:
                    ps_event['uid'] = p['uid']
                # Pass uid to uniqueness check
                uid_value = ps_event.get('uid')
                if self.add_if_full_command_is_not_in_set(ps_event['process'], uid_value):
                    yield ps_event
        except Exception as e:
            logger.exception(f"ERROR while extracting {entity_type} file. {e}")

    def __extract_ps_spindump_nosymbols_file(self) -> Generator[dict, None, None]:
        """
        Extracts process data from spindump-nosymbols.txt.

        :return: A generator yielding dictionaries containing process and thread details from spindump-nosymbols.txt.
        """
        entity_type = 'spindump-nosymbols.txt'
        try:
            for p in SpindumpNoSymbolsParser(self.config, self.case_id).get_result():
                if 'process' not in p:
                    continue
                process_name = p.get('path', '/kernel' if p['process'] == 'kernel_task [0]' else p['process'])

                # Get uid before the uniqueness check
                uid_value = p.get('uid') if 'uid' in p else None
                if self.add_if_full_command_is_not_in_set(self._strip_flags(process_name), uid_value):
                    ps_event = {
                        'process': self._strip_flags(process_name),
                        'timestamp': p['timestamp'],
                        'datetime': p['datetime'],
                        'source': entity_type
                    }
                    # Add uid if available (SpindumpNoSymbolsParser hardcodes uid to 501)
                    if 'uid' in p:
                        ps_event['uid'] = p['uid']
                    yield ps_event

                for t in p['threads']:
                    try:
                        thread_name = f"{self._strip_flags(process_name)}::{t['thread_name']}"
                        # Use the same uid from parent process for thread
                        if self.add_if_full_command_is_not_in_set(thread_name, uid_value):
                            ps_event = {
                                'process': thread_name,
                                'timestamp': p['timestamp'],
                                'datetime': p['datetime'],
                                'source': entity_type
                            }
                            # Add uid if available
                            if 'uid' in p:
                                ps_event['uid'] = p['uid']
                            yield ps_event
                    except KeyError:
                        pass
        except Exception as e:
            logger.exception(f"ERROR while extracting {entity_type} file. {e}")

    def __extract_ps_shutdownlogs(self) -> Generator[dict, None, None]:
        """
        Extracts process data from shutdown logs.

        :return: A generator yielding dictionaries containing process details from shutdown logs.
        """
        entity_type = 'shutdown.logs'
        try:
            for p in ShutdownLogsParser(self.config, self.case_id).get_result():
                # Use uid or auid for uniqueness check
                uid_value = p.get('uid') if 'uid' in p else p.get('auid')
                if self.add_if_full_command_is_not_in_set(self._strip_flags(p['command']), uid_value):
                    ps_event = {
                        'process': self._strip_flags(p['command']),
                        'timestamp': p['timestamp'],
                        'datetime': p['datetime'],
                        'source': entity_type
                    }
                    # Add uid/auid if available
                    if 'uid' in p:
                        ps_event['uid'] = p['uid']
                    if 'auid' in p:
                        ps_event['auid'] = p['auid']
                    yield ps_event
        except Exception as e:
            logger.exception(f"ERROR while extracting {entity_type}. {e}")

    def __extract_ps_logarchive(self) -> Generator[dict, None, None]:
        """
        Extracts process data from logarchive.

        :return: A generator yielding dictionaries containing process details from logarchive.
        """
        entity_type = 'log archive'
        try:
            for p in LogarchiveParser(self.config, self.case_id).get_result():
                # First check if we can extract a binary from the message
                if 'message' in p:
                    extracted_processes = self.message_extract_binary(p['process'], p['message'])
                    if extracted_processes:
                        # extracted_processes is now always a list of dicts
                        for proc_info in extracted_processes:
                            proc_path = proc_info.get('path')
                            # Get euid for uniqueness check
                            euid_value = proc_info.get('euid') if 'euid' in proc_info else p.get('euid')
                            if proc_path and self.add_if_full_command_is_not_in_set(self._strip_flags(proc_path), euid_value):
                                ps_event = {
                                    'process': self._strip_flags(proc_path),
                                    'timestamp': p['timestamp'],
                                    'datetime': p['datetime'],
                                    'source': entity_type + ' message'
                                }
                                # Add euid from extracted info if available
                                if 'euid' in proc_info:
                                    ps_event['uid'] = proc_info['euid']
                                # Also add euid from LogarchiveParser if available and not already set
                                elif 'euid' in p:
                                    ps_event['uid'] = p['euid']
                                yield ps_event

                # Process the original process name
                euid_value = p.get('euid') if 'euid' in p else None
                if self.add_if_full_command_is_not_in_set(self._strip_flags(p['process']), euid_value):
                    ps_event = {
                        'process': self._strip_flags(p['process']),
                        'timestamp': p['timestamp'],
                        'datetime': p['datetime'],
                        'source': entity_type
                    }
                    # Add euid if available
                    if 'euid' in p:
                        ps_event['uid'] = p['euid']
                    yield ps_event
        except Exception as e:
            logger.exception(f"ERROR while extracting {entity_type}. {e}")

    def __extract_ps_uuid2path(self) -> Generator[dict, None, None]:
        """
        Extracts process data from UUID2PathParser.

        :return: A generator yielding process data from uuid2path.
        """
        entity_type = 'uuid2path'
        try:
            for p in UUID2PathParser(self.config, self.case_id).get_result().values():
                # No uid available for uuid2path
                if self.add_if_full_command_is_not_in_set(self._strip_flags(p), None):
                    yield {
                        'process': self._strip_flags(p),
                        'timestamp': None,
                        'datetime': None,
                        'source': entity_type
                    }
        except Exception as e:
            logger.exception(f"ERROR while extracting {entity_type}. {e}")

    def __extract_ps_taskinfo(self) -> Generator[dict, None, None]:
        """
        Extracts process and thread information from TaskinfoParser.

        :return: A generator yielding process and thread information from taskinfo.
        """
        entity_type = 'taskinfo.txt'
        try:
            for p in TaskinfoParser(self.config, self.case_id).get_result():
                if 'name' not in p:
                    continue

                # Use uid or auid for uniqueness check
                uid_value = p.get('uid') if 'uid' in p else p.get('auid')
                if self.add_if_full_path_is_not_in_set(self._strip_flags(p['name']), uid_value):
                    ps_event = {
                        'process': self._strip_flags(p['name']),
                        'timestamp': p['timestamp'],
                        'datetime': p['datetime'],
                        'source': entity_type
                    }
                    # Add uid/auid if available
                    if 'uid' in p:
                        ps_event['uid'] = p['uid']
                    if 'auid' in p:
                        ps_event['auid'] = p['auid']
                    yield ps_event

                for t in p['threads']:
                    try:
                        thread_name = f"{self._strip_flags(p['name'])}::{t['thread name']}"
                        # Use the same uid from parent process for thread
                        if self.add_if_full_path_is_not_in_set(thread_name, uid_value):
                            ps_event = {
                                'process': thread_name,
                                'timestamp': p['timestamp'],
                                'datetime': p['datetime'],
                                'source': entity_type
                            }
                            # Add uid/auid if available
                            if 'uid' in p:
                                ps_event['uid'] = p['uid']
                            if 'auid' in p:
                                ps_event['auid'] = p['auid']
                            yield ps_event
                    except KeyError:
                        pass
        except Exception as e:
            logger.exception(f"ERROR while extracting {entity_type}. {e}")

    def __extract_ps_remotectl_dumpstate(self) -> Generator[dict, None, None]:
        """
        Extracts process data from RemotectlDumpstateParser.

        :return: A generator yielding process data from remotectl_dumpstate.txt.
        """
        entity_type = 'remotectl_dumpstate.txt'
        try:
            remotectl_dumpstate_json = RemotectlDumpstateParser(self.config, self.case_id).get_result()
            if remotectl_dumpstate_json:
                for p in remotectl_dumpstate_json['Local device']['Services']:
                    # No uid available for remotectl_dumpstate
                    if self.add_if_full_path_is_not_in_set(self._strip_flags(p), None):
                        yield {
                            'process': self._strip_flags(p),
                            'timestamp': None,
                            'datetime': None,
                            'source': entity_type
                        }
        except Exception as e:
            logger.exception(f"ERROR while extracting {entity_type}. {e}")

    def __extract_ps_logdata_statistics(self) -> Generator[dict, None, None]:
        """
        Extracts process data from logdata_statistics.jsonl.

        :return: A generator yielding process data from logdata_statistics.jsonl.
        """
        entity_type = 'logdata.statistics.jsonl'
        try:
            for p in LogDataStatisticsParser(self.config, self.case_id).get_result():
                # Use uid or euid for uniqueness check
                uid_value = p.get('uid') if 'uid' in p else p.get('euid')
                if self.add_if_full_command_is_not_in_set(self._strip_flags(p['process']), uid_value):
                    ps_event = {
                        'process': self._strip_flags(p['process']),
                        'timestamp': p['timestamp'],
                        'datetime': p['datetime'],
                        'source': entity_type
                    }
                    # Add uid/euid if available
                    if 'uid' in p:
                        ps_event['uid'] = p['uid']
                    if 'euid' in p:
                        ps_event['uid'] = p['euid']
                    yield ps_event
        except Exception as e:
            logger.exception(f"ERROR while extracting {entity_type}. {e}")

    def __extract_ps_logdata_statistics_txt(self) -> Generator[dict, None, None]:
        """
        Extracts process data from logdata.statistics.txt.

        :return: A generator yielding process data from logdata.statistics.txt.
        """
        entity_type = "logdata.statistics.txt"

        try:
            for p in LogDataStatisticsTxtParser(self.config, self.case_id).get_result():
                # Use uid or euid for uniqueness check
                uid_value = p.get('uid') if 'uid' in p else p.get('euid')
                if self.add_if_full_path_is_not_in_set(self._strip_flags(p['process']), uid_value):
                    ps_event = {
                        'process': self._strip_flags(p['process']),
                        'timestamp': p['timestamp'],
                        'datetime': p['datetime'],
                        'source': entity_type
                    }
                    # Add uid/euid if available
                    if 'uid' in p:
                        ps_event['uid'] = p['uid']
                    if 'euid' in p:
                        ps_event['uid'] = p['euid']
                    yield ps_event
        except Exception as e:
            logger.exception(f"ERROR while extracting {entity_type}. {e}")

    def add_if_full_path_is_not_in_set(self, name: str, uid: Optional[int] = None) -> bool:
        """
        Ensures that a process path with uid is unique before adding it to the shared set.

        :param name: Process path name
        :param uid: User ID (can be uid, euid, or auid)
        :return: True if the process was not in the set and was added, False otherwise.
        """
        # Create unique key with process and uid
        key = (name, uid)
        
        # Check if this exact combination already exists
        if key in self.all_ps:
            return False
            
        # For backward compatibility, also check if process exists without considering uid
        # This handles cases where uid might not be available
        for item_name, item_uid in self.all_ps:
            if item_name.endswith(name):
                if uid is None or item_uid is None:
                    return False
            if item_name.split('::')[0].endswith(name):
                if uid is None or item_uid is None:
                    return False
            if '::' not in item_name and item_name.split(' ')[0].endswith(name):
                if uid is None or item_uid is None:
                    return False
                    
        self.all_ps.add(key)
        return True

    def add_if_full_command_is_not_in_set(self, name: str, uid: Optional[int] = None) -> bool:
        """
        Ensures that a process command with uid is unique before adding it to the shared set.

        :param name: Process command name
        :param uid: User ID (can be uid, euid, or auid)
        :return: True if the process was not in the set and was added, False otherwise.
        """
        # Create unique key with process and uid
        key = (name, uid)
        
        # Check if this exact combination already exists
        if key in self.all_ps:
            return False
            
        # For backward compatibility, also check if process exists without considering uid
        # This handles cases where uid might not be available
        for item_name, item_uid in self.all_ps:
            if item_name.startswith(name):
                if uid is None or item_uid is None:
                    return False
                    
        self.all_ps.add(key)
        return True
