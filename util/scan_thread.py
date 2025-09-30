import ctypes
import time
from ctypes import wintypes

from PyQt5.QtCore import QThread, pyqtSignal

from main import OpenProcess_Raw, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, SCANNER_CORE_DLL, CloseHandle_Raw, \
    VirtualQueryEx_Raw

MEM_COMMIT = 0x1000
PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READWRITE = 0x40
PAGE_READONLY = 0x02
PAGE_EXECUTE_READ = 0x20

SCAN_CHUNK_SIZE = 1024 * 1024 * 1


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
