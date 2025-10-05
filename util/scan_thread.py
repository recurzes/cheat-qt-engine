import ctypes
import struct
import time
from ctypes import wintypes

from PyQt5.QtCore import QThread, pyqtSignal
from main import main_window_ref

from main import OpenProcess_Raw, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, SCANNER_CORE_DLL, CloseHandle_Raw, \
    VirtualQueryEx_Raw, ReadProcessMemory_Raw

MEM_COMMIT = 0x1000
PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READWRITE = 0x40
PAGE_READONLY = 0x02
PAGE_EXECUTE_READ = 0x20

SCAN_CHUNK_SIZE = 1024 * 1024 * 1


class CppScanComparisonType(ctypes.c_int):
    ExactValue = 0
    ValueBetween = 1
    BiggerThan = 2
    SmallerThan = 3
    StringContains = 4
    StringExact = 5
    AoBExact = 6


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ('BaseAddress', wintypes.LPVOID),
        ('AllocationBase', wintypes.LPVOID),
        ('AllocationProtect', wintypes.DWORD),
        ('RegionSize', ctypes.c_size_t),
        ('State', wintypes.DWORD),
        ('Protect', wintypes.DWORD),
        ('Type', wintypes.DWORD)
    ]


class ScanThread(QThread):
    results_ready = pyqtSignal(list)
    progress_update = pyqtSignal(int, int, int)
    scan_finished = pyqtSignal(int, bool)
    error_occurred = pyqtSignal(str)

    def __init__(self, target_pid, scan_params, timeout_seconds=15, previous_results=None):
        super().__init__()
        self.target_pid = target_pid
        self.scan_params = scan_params
        self.timeout_duration = timeout_seconds
        self.previous_results = previous_results
        self.is_cancelled = False
        self.timed_out = False
        self.MAX_RESULTS_TO_COLLECT = 1000

    def run(self):
        start_time = time.time()
        total_found_this_run = 0

        try:
            if self.previous_results is not None:
                total_found_this_run = self._perform_next_scan_logic(start_time)
            else:
                total_found_this_run = self._perform_first_scan_logic(start_time)

            if self.timed_out:
                self.scan_finished.emit(total_found_this_run, True)
            elif self.is_cancelled:
                self.scan_finished.emit(total_found_this_run, False)
            else:
                self.scan_finished.emit(total_found_this_run, False)
        except Exception as e:
            if not self.timed_out:
                self.error_occurred.emit(f"Critical scan erro: {str(e)}")
            self.scan_finished.emit(total_found_this_run, self.timed_out)

    def _perform_first_scan_logic(self, start_time):
        global main_window_ref

        # Extract scan parameters
        value_type_str = self.scan_params['value_type']
        scan_type_str_ui = self.scan_params['scan_type']
        parsed_val1 = self.scan_params['parsed_val1']
        parsed_val2 = self.scan_params['parsed_val2']
        case_sensitive = self.scan_params['case_sensitive']
        is_utf16 = self.scan_params['is_utf16']

        found_results_batch = []
        total_found_count = 0

        query_handle = OpenProcess_Raw(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, self.target_pid)
        if not query_handle:
            self.error_occurred.emit(
                f"ScanThread: Failed to open query handle for PID {self.target_pid}. Err: {ctypes.get_last_error()}")
            return 0

        dll_process_handle = SCANNER_CORE_DLL.OpenTargetProcess(self.target_pid) if SCANNER_CORE_DLL else None

        if SCANNER_CORE_DLL and not dll_process_handle:
            if SCANNER_CORE_DLL:
                self.error_occurred.emit(
                    f"ScanThread: DLL Failed to open target process PID {self.target_pid}. Err: {ctypes.get_last_error()}")
            CloseHandle_Raw(query_handle)

            python_fallback_read_handle = OpenProcess_Raw(PROCESS_VM_READ, False, self.target_pid)
            if not python_fallback_read_handle:
                self.error_occurred.emit(f"ScanThread: Python fallback also failed to open PID {self.target_pid}")
                return 0
            dll_process_handle = None
        elif not SCANNER_CORE_DLL:
            python_fallback_read_handle = OpenProcess_Raw(PROCESS_VM_READ, False, self.target_pid)
            if not python_fallback_read_handle:
                self.error_occurred.emit(
                    f"ScanThread: Python fallback failed to open target process PID {self.target_pid}. Err: {ctypes.get_last_error()}")
                CloseHandle_Raw(query_handle)
                return 0
        else:
            python_fallback_read_handle = None

        mem_info = MEMORY_BASIC_INFORMATION()
        current_address_iter = 0
        max_address_iter = 0x7FFFFFFFFFFF if ctypes.sizeof(ctypes.c_void_p) == 8 else 0x7FFFFFFF
        regions = []
        while current_address_iter < max_address_iter:
            if VirtualQueryEx_Raw(query_handle, ctypes.c_void_p(current_address_iter), ctypes.byref(mem_info),
                                  ctypes.sizeof(mem_info)) == 0:
                break
            is_readable = (mem_info.Protect & PAGE_READONLY) or (mem_info.Protect & PAGE_READWRITE) or (
                    mem_info.Protect & PAGE_EXECUTE_READ) or (mem_info.Protect & PAGE_EXECUTE_READWRITE)
            if mem_info.State == MEM_COMMIT and is_readable and not (mem_info.Protect & PAGE_NOACCESS) and not (
                    mem_info.Protect & PAGE_GUARD):
                regions.append((mem_info.BaseAddress, mem_info.RegionSize))
            if current_address_iter + mem_info.RegionSize <= current_address_iter:
                break
            current_address_iter += mem_info.RegionSize
        CloseHandle_Raw(query_handle)

        num_regions = len(regions)
        for i, (base_addr, region_size_val) in enumerate(regions):
            if self._check_timeout(start_time, "Region Scan") or self.is_cancelled:
                break
            self.progress_update.emit(i + 1, num_regions, total_found_count)
            current_chunk_addr = base_addr
            region_size_py = int(region_size_val) if isinstance(region_size_val, ctypes.c_size_t) else region_size_val
            region_end_addr = base_addr + region_size_py

            while current_chunk_addr < region_end_addr:
                if self._check_timeout(start_time, "Chunk Scan") or self.is_cancelled:
                    break
                chunk_to_scan_size = min(SCAN_CHUNK_SIZE, region_end_addr - current_chunk_addr)
                if chunk_to_scan_size <= 0:
                    print(
                        f"DEBUG: Skipping chunk at {hex(current_chunk_addr)} due to zero/neg size: {chunk_to_scan_size}")
                    break
                print(
                    f"DEBUG: DLL Call Prep: Addr={hex(current_chunk_addr)}, Size={chunk_to_scan_size}, Type={value_type_str}, V1='{parsed_val1}'")
                use_dll_for_this_type = SCANNER_CORE_DLL and dll_process_handle and value_type_str in ["Byte",
                                                                                                       "2 Bytes",
                                                                                                       "4 Bytes",
                                                                                                       "8 Bytes",
                                                                                                       "Float",
                                                                                                       "Double",
                                                                                                       "String",
                                                                                                       "Array Of Byte"]
                found_addr_ptr_ptr = ctypes.POINTER(ctypes.c_void_p)()
                FoundResultWithValueStruct = getattr(SCANNER_CORE_DLL, 'FoundResultWithValue',
                                                     ctypes.c_void_p) if SCANNER_CORE_DLL else ctypes.c_void_p
                found_results_with_val_ptr_ptr = ctypes.POINTER(FoundResultWithValueStruct)()
                num_found_c = ctypes.c_int(0)
                dll_success = False

                if use_dll_for_this_type:
                    try:
                        v1_c, v2_c, comp_type_c = self._prepare_dll_scan_params(value_type_str, scan_type_str_ui,
                                                                                parsed_val1, parsed_val2)

                        if value_type_str == "String":
                            search_str_bytes = parsed_val1.encode('ascii' if not is_utf16 else 'utf-16-le')
                            if is_utf16:
                                dll_success = SCANNER_CORE_DLL.ScanChunkForStringW(dll_process_handle,
                                                                                   ctypes.c_void_p(current_chunk_addr),
                                                                                   chunk_to_scan_size,
                                                                                   ctypes.c_wchar_p(parsed_val1),
                                                                                   case_sensitive, comp_type_c,
                                                                                   ctypes.byref(found_addr_ptr_ptr),
                                                                                   ctypes.byref(num_found_c))
                            else:
                                dll_success = SCANNER_CORE_DLL.ScanChunkForStringA(dll_process_handle,
                                                                                   ctypes.c_void_p(current_chunk_addr),
                                                                                   chunk_to_scan_size,
                                                                                   ctypes.c_char_p(search_str_bytes),
                                                                                   case_sensitive, comp_type_c,
                                                                                   ctypes.byref(found_addr_ptr_ptr),
                                                                                   ctypes.byref(num_found_c))

                        elif value_type_str == "Array Of Byte":
                            pattern_bytes = bytes(parsed_val1)
                            dll_success = SCANNER_CORE_DLL.ScanChunkForAoB(dll_process_handle,
                                                                           ctypes.c_void_p(current_chunk_addr),
                                                                           chunk_to_scan_size,
                                                                           ctypes.c_char_p(pattern_bytes),
                                                                           len(pattern_bytes),
                                                                           ctypes.byref(found_addr_ptr_ptr),
                                                                           ctypes.byref(num_found_c))

                        elif value_type_str == "Byte":
                            dll_success = SCANNER_CORE_DLL.ScanChunkForInt8Ex(dll_process_handle,
                                                                              ctypes.c_void_p(current_chunk_addr),
                                                                              chunk_to_scan_size, v1_c, v2_c,
                                                                              comp_type_c, ctypes.byref(
                                    found_results_with_val_ptr_ptr), ctypes.byref(num_found_c))
                        elif value_type_str == "2 Bytes":
                            dll_success = SCANNER_CORE_DLL.ScanChunkForInt16Ex(dll_process_handle,
                                                                               ctypes.c_void_p(current_chunk_addr),
                                                                               chunk_to_scan_size, v1_c, v2_c,
                                                                               comp_type_c, ctypes.byref(
                                    found_results_with_val_ptr_ptr), ctypes.byref(num_found_c))
                        elif value_type_str == "4 Bytes":
                            dll_success = SCANNER_CORE_DLL.ScanChunkForInt32Ex(dll_process_handle,
                                                                               ctypes.c_void_p(current_chunk_addr),
                                                                               chunk_to_scan_size, v1_c, v2_c,
                                                                               comp_type_c, ctypes.byref(
                                    found_results_with_val_ptr_ptr), ctypes.byref(num_found_c))
                        elif value_type_str == "8 Bytes":
                            dll_success = SCANNER_CORE_DLL.ScanChunkForInt64Ex(dll_process_handle,
                                                                               ctypes.c_void_p(current_chunk_addr),
                                                                               chunk_to_scan_size, v1_c, v2_c,
                                                                               comp_type_c, ctypes.byref(
                                    found_results_with_val_ptr_ptr), ctypes.byref(num_found_c))
                        elif value_type_str == "Float":
                            dll_success = SCANNER_CORE_DLL.ScanChunkForFloatEx(dll_process_handle,
                                                                               ctypes.c_void_p(current_chunk_addr),
                                                                               chunk_to_scan_size, v1_c, v2_c,
                                                                               comp_type_c, ctypes.byref(
                                    found_results_with_val_ptr_ptr), ctypes.byref(num_found_c))
                        elif value_type_str == "Double":
                            dll_success = SCANNER_CORE_DLL.ScanChunkForDoubleEx(dll_process_handle,
                                                                                ctypes.c_void_p(current_chunk_addr),
                                                                                chunk_to_scan_size, v1_c, v2_c,
                                                                                comp_type_c, ctypes.byref(
                                    found_results_with_val_ptr_ptr), ctypes.byref(num_found_c))

                        if not dll_success:
                            last_error_dll = ctypes.get_last_error()
                            print(
                                f"DEBUG: DLL fucntion call for type {value_type_str} returned FALSE. Addr: {hex(current_chunk_addr)}, Size: {chunk_to_scan_size}. LastError from DLL context (approx): {last_error_dll}")

                        if dll_success and num_found_c.value > 0:
                            if value_type_str in ['String', "Array Of Byte"]:
                                addr_array_type = ctypes.c_void_p * num_found_c.value
                                addrs = ctypes.cast(found_addr_ptr_ptr, ctypes.POINTER(addr_array_type)).contents
                                for k_idx in range(num_found_c.value):
                                    val_to_store = parsed_val1
                                    item_length = len(parsed_val1)
                                    if value_type_str == "String":
                                        val_to_store = self._read_memory_value_ctypes(dll_process_handle, addrs[k_idx],
                                                                                      value_type_str)
                                        if val_to_store is not None:
                                            item_length = len(val_to_store.encode(is_utf16))

                                    entry = {
                                        'address': addrs[k_idx],
                                        'value': val_to_store,
                                        'previous_value': val_to_store,
                                        'type': value_type_str,
                                        'length': item_length
                                    }

                                    found_results_batch.append(entry)
                                    total_found_count += 1
                                SCANNER_CORE_DLL.FreeFoundAddress(found_addr_ptr_ptr)
                            else:
                                results_array_type = FoundResultWithValueStruct * num_found_c.value
                                results_c = ctypes.cast(found_results_with_val_ptr_ptr,
                                                        ctypes.POINTER(results_array_type)).contents
                                for k_idx in range(num_found_c.value):
                                    c_res = results_c[k_idx]
                                    actual_val = self._extract_value_from_c_struct(c_res.value, value_type_str)
                                    entry = {'address': c_res.address, 'value': actual_val,
                                             'previous_value': actual_val, 'type': value_type_str}
                                    found_results_batch.append(entry)
                                    total_found_count += 1
                                SCANNER_CORE_DLL.FreeFoundAddressesAndValues(found_results_with_val_ptr_ptr)
                        elif not dll_success and SCANNER_CORE_DLL:
                            self.error_occurred.emit(
                                f"DLL scan call failed at {hex(current_chunk_addr)}. Err. {ctypes.get_last_error()}")
                            use_dll_for_this_type = False
                    except ValueError as e_val:
                        self.error_occurred.emit(f"Error in DLL call section: {str(e_val)}")
                        use_dll_for_this_type = False
                    except Exception as e_dll:
                        self.error_occurred.emit(f"Error in DLL call section: {str(e_dll)}")
                        use_dll_for_this_type = False

                if not use_dll_for_this_type and python_fallback_read_handle:
                    buffer = ctypes.create_string_buffer(chunk_to_scan_size)
                    bytes_read_c = ctypes.c_size_t(0)
                    if ReadProcessMemory_Raw(python_fallback_read_handle, ctypes.c_void_p(current_chunk_addr), buffer,
                                             chunk_to_scan_size, ctypes.byref(bytes_read_c)):
                        if bytes_read_c.value > 0:
                            fmt_char, type_size_info = main_window_ref.value_types_map.get(value_type_str, (None, 0))
                            type_size = type_size_info if type_size_info is not None else 1

                            if type_size > 0 and bytes_read_c.value >= type_size:
                                step = 1 if value_type_str in ["String", "Array Of Byte"] else type_size
                                for offset in range(0, bytes_read_c.value - (type_size - 1), step):
                                    if self.is_cancelled:
                                        break

                                    try:
                                        actual_mem_val = None
                                        if value_type_str == "Byte":
                                            actual_mem_val = struct.unpack_from('<b', buffer.raw, offset)[0]
                                        elif value_type_str == "2 Bytes":
                                            actual_mem_val = struct.unpack_from('<h', buffer.raw, offset)[0]
                                        elif value_type_str == "4 Bytes":
                                            actual_mem_val = struct.unpack_from('<i', buffer.raw, offset)[0]
                                        elif value_type_str == "8 Bytes":
                                            actual_mem_val = struct.unpack_from('<q', buffer.raw, offset)[0]
                                        elif value_type_str == "Float":
                                            actual_mem_val = struct.unpack_from('<f', buffer.raw, offset)[0]
                                        elif value_type_str == "Double":
                                            actual_mem_val = struct.unpack_from('<d', buffer.raw, offset)[0]
                                        elif value_type_str == "String":
                                            temp_buff = buffer.raw[
                                                offset: offset + min(256, bytes_read_c.value - offset)]
                                            enc = 'utf-16-le' if is_utf16 else 'ascii'
                                            nt = b'\x00\x00' if enc == 'utf-16-le' else b'\x00'
                                            term_idx = temp_buff.find(nt)
                                            if term_idx != -1:
                                                temp_buff = temp_buff[:term_idx]
                                            try:
                                                actual_mem_val = temp_buff.decode(enc, errors='ignore')
                                            except:
                                                continue
                                        elif value_type_str == "Array Of Byte" and isinstance(parsed_val1, bytes):
                                            if offset + len(parsed_val1) <= bytes_read_c.value:
                                                actual_mem_val = buffer.raw[offset: offset + len(parsed_val1)]

                                        if actual_mem_val is not None and main_window_ref._compare_values(
                                                actual_mem_val, parsed_val1, scan_type_str_ui, value_type_str):
                                            item_length = len(actual_mem_val) if isinstance(actual_mem_val,
                                                                                            (bytes, str)) else type_size
                                            entry = {'address': current_chunk_addr + offset,
                                                     'value': actual_mem_val,
                                                     'previous_value': actual_mem_val,
                                                     'type': value_type_str,
                                                     'length': item_length}
                                            found_results_batch.append(entry)
                                            total_found_count += 1
                                    except (struct.error, IndexError):
                                        break
                                if self.is_cancelled:
                                    break
                    if self.is_cancelled:
                        break

                if len(found_results_batch) >= self.MAX_RESULTS_TO_COLLECT:
                    self.results_ready.emit(list(found_results_batch))
                    found_results_batch.clear()
                    if self._check_timeout(start_time):
                        break

                current_chunk_addr += chunk_to_scan_size

            if self.is_cancelled:
                break

        if dll_process_handle:
            SCANNER_CORE_DLL.CloseTargetProcess(dll_process_handle)

        if python_fallback_read_handle:
            CloseHandle_Raw(python_fallback_read_handle)

        if not self.is_cancelled and found_results_batch:
            self.results_ready.emit(list(found_results_batch))

        return total_found_count

    def _prepare_dll_scan_params(self, value_type_str, scan_type_str_ui, p_val1, p_val2):
        v1_c, v2_c = 0, 0
        comp_type_c = CppScanComparisonType.ExactValue

        if value_type_str in ["Byte", "2 Bytes", "4 Bytes", "8 Bytes", "Float", "Double"]:
            try:
                if value_type_str == "Float":
                    v1_c = ctypes.c_float(float(p_val1))
                    if p_val2 is not None:
                        v2_c = ctypes.c_float(float(p_val2))
                elif value_type_str == "Double":
                    v1_c = ctypes.c_double(float(p_val1))
                    if p_val2 is not None:
                        v2_c = ctypes.c_double(float(p_val2))
                elif value_type_str == "Byte":
                    v1_c = ctypes.c_int8(int(p_val1))
                    if p_val2 is not None:
                        v2_c = ctypes.c_int8(int(p_val2))
                elif value_type_str == "2 Bytes":
                    v1_c = ctypes.c_int16(int(p_val1))
                    if p_val2 is not None:
                        v2_c = ctypes.c_int16(int(p_val2))
                elif value_type_str == "4 Bytes":
                    v1_c = ctypes.c_int32(int(p_val1))
                    if p_val2 is not None:
                        v2_c = ctypes.c_int32(int(p_val2))
                elif value_type_str == "8 Bytes":
                    v1_c = ctypes.c_int64(int(p_val1))
                    if p_val2 is not None:
                        v2_c = ctypes.c_int64(int(p_val2))
            except (ValueError, TypeError) as e:
                raise ValueError(f"Invalid numeric value for DLL scan: {p_val1} or {p_val2}. Error: {e}")

            if scan_type_str_ui == "Value Between...":
                comp_type_c = CppScanComparisonType.ValueBetween
            elif scan_type_str_ui == "Bigger Than...":
                comp_type_c = CppScanComparisonType.BiggerThan
            elif scan_type_str_ui == "Smaller Than...":
                comp_type_c = CppScanComparisonType.SmallerThan


        elif value_type_str == "String":
            if scan_type_str_ui == "Search for text":
                comp_type_c = CppScanComparisonType.StringContains
            else:
                comp_type_c = CppScanComparisonType.StringExact


        elif value_type_str == "Array Of Byte":
            comp_type_c = CppScanComparisonType.AoBExact

        return v1_c, v2_c, comp_type_c


    def _extract_value_from_c_struct(self, c_union_value, value_type_str):
        if value_type_str == "Byte":
            return c_union_value.val_int8
        if value_type_str == "2 Bytes":
            return c_union_value.val_int16
        if value_type_str == "4 Bytes":
            return c_union_value.val_int32
        if value_type_str == "8 Bytes":
            return c_union_value.val_int64
        if value_type_str == "Float":
            return c_union_value.val_float
        if value_type_str == "Double":
            return c_union_value.val_double

        return None

    def _perform_next_scan_logic(self, start_time):
        global main_window_ref
        new_results_batch =[]
        total_narrowed_count = 0
        num_to_scan = len(self.previous_results)
        python_read_handle = OpenProcess_Raw(PROCESS_VM_READ, False, self.target_pid)
        if not python_read_handle:
            self.error_occurred.emit(f"NextScan: No read handle PID {self.target_pid}")
            return 0
        for i, old_results in enumerate(self.previous_results):
            if self._check_timeout(start_time, "Next Scan Item") or self.is_cancelled:
                break
            self.progress_update.emit(i + 1, num_to_scan, total_narrowed_count)
            address = old_results['address']
            original_type = old_results['type']

            current_mem_val_for_comparison = self._read_memory_value_ctypes(python_read_handle, address, self.scan_params['value_type'])
            if current_mem_val_for_comparison is not None:
                if main_window_ref._compare_values(current_mem_val_for_comparison, self.scan_params['parsed_val1'], self.scan_params['parsed_val2'], self.scan_params['scan_type'], self.scan_params['value_type']):
                    actual_current_val_as_original = self._read_memory_value_ctypes(python_read_handle, address, original_type)
                    item_length = old_results.get('length')
                    if item_length is None:
                        if original_type == "Array Of Byte" or original_type == "String":
                            item_length = len(actual_current_val_as_original) if actual_current_val_as_original else (len(old_results['value']) if old_results['value'] else 16)
                        else:
                            item_length = main_window_ref.value_types_map.get(original_type, (None, 0))[1]

                    entry = {'address': address,
                             'value': actual_current_val_as_original if actual_current_val_as_original is not None else old_results['value'],
                             'previous_value': old_results['value'],
                             'type': original_type,
                             'length': item_length}
                    new_results_batch.append(entry)
                    total_narrowed_count += 1
            if len(new_results_batch) >= self.MAX_RESULTS_TO_COLLECT:
                self.results_ready.emit(list(new_results_batch))
                new_results_batch.clear()
                if self._check_timeout(start_time):
                    break
        if python_read_handle:
            CloseHandle_Raw(python_read_handle)
        if not self.is_cancelled and new_results_batch:
            self.results_ready.emit(list(new_results_batch))
        return total_narrowed_count

    def _read_memory_value_ctypes(self, handle, address, value_type_str):
        global main_window_ref
        if not handle:
            return None

        fmt_char_ign, type_size = main_window_ref.value_types_map.get(value_type_str, (None, 0))
        read_size = type_size

        is_thread_utf16 = self.scan_params.get('is_utf16', main_window_ref.utf16_checkbox.isChecked() if main_window_ref else False)

        if value_type_str == "String":
            read_size = 256
        elif value_type_str == "Array Of Byte":
            read_size = 16
        if read_size is None or read_size == 0:
            return None

        buffer = ctypes.create_string_buffer(read_size)
        bytes_read_c = ctypes.c_size_t(0)
        if ReadProcessMemory_Raw(handle, ctypes.c_void_p(address), buffer, read_size, ctypes.byref(bytes_read_c)):
            actual_read = bytes_read_c.value
            if actual_read == 0:
                return None
            if value_type_str not in ["String", "Array Of Byte"] and actual_read < type_size:
                return None
            try:
                if value_type_str == "Byte":
                    return struct.unpack_from('<b', buffer.raw, 0)[0]
                elif value_type_str == "String":
                    raw_b = buffer.raw[:actual_read]
                    encoding = 'utf-16-le'if is_thread_utf16 else 'ascii'
                    nt = b'\x00\x00' if encoding == 'utf-16-le' else b'\x00'
                    idx = raw_b.find(nt)
                    if idx != -1:
                        raw_b = raw_b[:idx]
                    return raw_b.decode(encoding, errors="ignore")
                elif value_type_str == "Array Of Byte":
                    return buffer.raw[:actual_read]
            except (struct.error, UnicodeDecodeError):
                return None
        return None


