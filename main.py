import sys

# import psutil
import struct
import time
import os
import ctypes
from ctypes import wintypes

import psutil
from PyQt5.QtGui import QBrush, QColor
from PyQt5.QtWidgets import (
    QMainWindow,
    QApplication,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
    QStyle,
    QLabel,
    QTableWidget,
    QHeaderView,
    QAbstractItemView,
    QStackedWidget,
    QCheckBox,
    QLineEdit,
    QGridLayout,
    QFormLayout,
    QComboBox, QSpacerItem, QSizePolicy, QMessageBox, QTableWidgetItem,
)
from PyQt5.QtCore import Qt, QTimer

from util.process_window import ProcessWindow

NORMAL_BACKGROUND_BRUSH = QBrush(QColor("white"))
CHANGED_BACKGROUND_BRUSH = QBrush(QColor("red"))
NORMAL_TEXT_BRUSH = QBrush(QColor("black"))

# Win 32 API Definitions
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

OpenProcess_Raw = kernel32.OpenProcess

ReadProcessMemory_Raw = kernel32.ReadProcessMemory

CloseHandle_Raw = kernel32.CloseHandle
CloseHandle_Raw.argtypes = [wintypes.HANDLE]

VirtualQueryEx_Raw = kernel32.VirtualQueryEx

main_window_ref = None

SCANNER_CORE_DLL = None
FoundResultWithValue = None

class CppScanComparisonType(ctypes.c_int):
    ExactValue = 0
    ValueBetween = 1
    BiggerThan = 2
    SmallerThan = 3
    StringContains = 4
    StringExact = 5
    AoBExact = 6

try:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    dll_path_options = [
        os.path.join(script_dir, "ScannerCore.dll"),
        os.path.join(script_dir, "..", "x64", "Release", "ScannerCore.dll"),
        os.path.join(script_dir, "x64", "Release", "ScannerCore.dll"),
        os.path.join(script_dir, "..", "ScannerCore.dll"),
    ]

    dll_to_load_path = None
    for path_opt in dll_path_options:
        if os.path.exists(path_opt):
            dll_to_load_path = path_opt
            break

    if dll_to_load_path:
        SCANNER_CORE_DLL = ctypes.CDLL(dll_to_load_path)
        print(f"INFO: Successfully loaded ScannerCore.dll from {dll_to_load_path}")

        SCANNER_CORE_DLL.OpenTargetProcess.argtypes = [wintypes.DWORD]
        SCANNER_CORE_DLL.OpenTargetProcess.restype = wintypes.HANDLE

        SCANNER_CORE_DLL.CloseTargetProcess.argtypes = [wintypes.HANDLE]
        SCANNER_CORE_DLL.CloseTargetProcess.restype = wintypes.BOOL

        SCANNER_CORE_DLL.FreeFoundAddresses.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
        SCANNER_CORE_DLL.FreeFoundAddresses.restype = None

        class FoundResultWithValue_UNION_CTYPES(ctypes.Union):
            _fields_ = [
                ('val_int8', ctypes.c_int8), ('val_int16', ctypes.c_int16),
                ('val_int32', ctypes.c_int32), ('val_int64', ctypes.c_int64),
                ('val_float', ctypes.c_float), ('val_double', ctypes.c_double)
            ]
        class FoundResultWithValue_CTYPES(ctypes.Structure):
            _fields_ = [
                ('address', ctypes.c_void_p),
                ('value', FoundResultWithValue_UNION_CTYPES)
            ]

        FoundResultWithValue = FoundResultWithValue_CTYPES

        SCANNER_CORE_DLL.FoundResultWithValue = FoundResultWithValue

        SCANNER_CORE_DLL.FreeFoundAddressesAndValues.argtypes = [ctypes.c_void_p]
        SCANNER_CORE_DLL.FreeFoundAddressesAndValues.restype = None

        common_args_numeric_ex = [
            wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t,
            None, None,
            CppScanComparisonType,
            ctypes.POINTER(ctypes.POINTER(FoundResultWithValue)),
            ctypes.POINTER(ctypes.c_int)
        ]

        type_map_to_ctypes = {
            "Byte": (SCANNER_CORE_DLL.ScanChunkForInt8Ex, ctypes.c_int8),
            "2 Bytes": (SCANNER_CORE_DLL.ScanChunkForInt16Ex, ctypes.c_int16),
            "4 Bytes": (SCANNER_CORE_DLL.ScanChunkForInt32Ex, ctypes.c_int32),
            "8 Bytes": (SCANNER_CORE_DLL.ScanChunkForInt64Ex, ctypes.c_int64),
            "Float": (SCANNER_CORE_DLL.ScanChunkForFloatEx, ctypes.c_float),
            "Double": (SCANNER_CORE_DLL.ScanChunkForDoubleEx, ctypes.c_double),
        }

        for type_name, (func, c_type) in type_map_to_ctypes.items():
            if hasattr(SCANNER_CORE_DLL, func.__name__):
                func.argtypes = common_args_numeric_ex[:3] + [c_type, c_type] + common_args_numeric_ex[5:]
                func.restype = wintypes.BOOL

            if hasattr(SCANNER_CORE_DLL, 'ScanChunkForStringA'):
                SCANNER_CORE_DLL.ScanChunkForStringA.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_char_p, wintypes.BOOL, CppScanComparisonType, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p)), ctypes.POINTER(ctypes.c_int)]
                SCANNER_CORE_DLL.ScanChunkForStringA.restype = wintypes.BOOL
            if hasattr(SCANNER_CORE_DLL, 'ScanChunkForStringW'):
                SCANNER_CORE_DLL.ScanChunkForStringW.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_char_p, wintypes.BOOL, CppScanComparisonType, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p)), ctypes.POINTER(ctypes.c_int)]
                SCANNER_CORE_DLL.ScanChunkForStringW.restype = wintypes.BOOL
            if hasattr(SCANNER_CORE_DLL, 'ScanChunkForAoB'):
                SCANNER_CORE_DLL.ScanChunkForAoB.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_char_p, wintypes.BOOL, CppScanComparisonType, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p)), ctypes.POINTER(ctypes.c_int)]
                SCANNER_CORE_DLL.ScanChunkForAoB.restype = wintypes.BOOL

    else:
        print(f"ERROR: ScannerCore.dll not found in expected paths. C++ accelerated scanning will be disabled")
        print(f"Checked paths: {dll_path_options}")
        SCANNER_CORE_DLL = None

except OSError as e:
    print(f"OSError loading ScannerCore.dll: {e}. C++ accelerated scanning will be disabled")
    SCANNER_CORE_DLL = None

except AttributeError as e:
    print(f"AttributeError during DLL function setup (function likely not found or DLL not loaded properly): {e}. C++ acceleration likely disabled.")
    SCANNER_CORE_DLL = None


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.MAX_DISPLAY_RESULTS = 5000
        global main_window_ref
        main_window_ref = self

        self.setWindowTitle("Memory Scanner")
        self.setGeometry(100, 100, 950, 600)

        self.selected_pid = None
        self.selected_process_name = ""

        self.process_handle_main_python = None

        self.current_scan_results = []
        self.scan_thread = None
        self.progress_dialog = None
        self.current_scan_results_temp_for_next_scan = []

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # Top Bar
        top_bar_layout = QHBoxLayout()
        self.process_list_button = QPushButton("Process List")
        self.process_list_button.setIcon(
            self.style().standardIcon(
                getattr(QStyle, "SP_ComputerIcon", QStyle.SP_DriveNetIcon)
            )
        )
        self.process_list_button.clicked.connect(self.open_process_window)

        self.selected_process_label = QLabel("No process attached.")
        self.selected_process_label.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)

        top_bar_layout.addWidget(self.process_list_button)
        top_bar_layout.addWidget(self.selected_process_label)
        top_bar_layout.addStretch()
        main_layout.addLayout(top_bar_layout)

        # Middle Layout
        middle_layout = QHBoxLayout()

        # Left Panel
        results_panel_layout = QVBoxLayout()
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(3)
        self.results_table.setHorizontalHeaderLabels(["Address", "Value", "Previous"])
        self.results_table.verticalHeader().setVisible(False)
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.results_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.results_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.results_table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        results_panel_layout.addWidget(self.results_table)

        self.move_to_bottom_button = QPushButton()
        self.move_to_bottom_button.setIcon(
            self.style().standardIcon(QStyle.SP_ArrowDown)
        )
        self.move_to_bottom_button.setToolTip(
            "Add selected address(es) to the bottom list"
        )
        self.move_to_bottom_button.clicked.connect(self.move_selected_to_bottom_table)
        self.move_to_bottom_button.setFixedWidth(40)

        results_button_layout = QHBoxLayout()
        results_button_layout.addStretch()
        results_button_layout.addWidget(self.move_to_bottom_button)
        results_panel_layout.addLayout(results_button_layout)
        middle_layout.addLayout(results_panel_layout, 2)

        # Right Panel
        scan_controls_widget = QWidget()
        scan_controls_layout = QVBoxLayout(scan_controls_widget)
        scan_controls_layout.setAlignment(Qt.AlignTop)
        scan_controls_layout.setSpacing(0)
        scan_controls_layout.setContentsMargins(0, 0, 0, 0)

        # Scan Buttons
        scan_buttons_container_widget = QWidget()
        scan_controls_widget.setContentsMargins(0, 0, 0, 0)
        scan_buttons_layout_internal = QHBoxLayout(scan_buttons_container_widget)
        scan_buttons_layout_internal.setContentsMargins(0, 0, 0, 0)
        self.first_scan_button = QPushButton("First Scan")
        # self.first_scan_button.clicked.connect(self.initiate_first_scan)
        self.next_scan_button = QPushButton("Next Scan")
        # self.next_scan_button.clicked.connect(self.initiate_next_scan)
        self.cancel_scan_button = QPushButton("Cancel Scan")
        # self.cancel_scan_button.clicked.connect(self.cancel_current_scan)
        self.cancel_scan_button.setEnabled(False)
        scan_buttons_layout_internal.addWidget(self.first_scan_button)
        scan_buttons_layout_internal.addWidget(self.next_scan_button)
        scan_buttons_layout_internal.addWidget(self.cancel_scan_button)
        scan_controls_layout.addWidget(scan_buttons_container_widget)

        # Input Area
        self.input_area_stacked_widget = QStackedWidget()
        self.input_area_stacked_widget.setContentsMargins(0, 0, 0, 0)

        # Single Input Area
        self.single_input_widget = QWidget()
        single_input_layout = QHBoxLayout(self.single_input_widget)
        single_input_layout.setContentsMargins(0, 5, 0, 5)
        self.hex_checkbox_single = QCheckBox()
        self.hex_label_single = QLabel("Hex")
        self.text_label_single = QLabel("Value: ")
        self.value_input_single = QLineEdit("0")
        single_input_layout.addWidget(self.hex_checkbox_single)
        single_input_layout.addWidget(self.hex_label_single)
        single_input_layout.addSpacing(5)
        single_input_layout.addWidget(self.text_label_single)
        single_input_layout.addWidget(self.value_input_single)
        self.input_area_stacked_widget.addWidget(self.single_input_widget)

        # Double Input Widget
        self.double_input_widget = QWidget()
        double_grid_layout = QGridLayout(self.double_input_widget)
        double_grid_layout.setContentsMargins(0, 5, 0, 5)
        self.hex_checkbox_double = QCheckBox()
        self.hex_label_double = QLabel("Hex")
        self.value_label1_double = QLabel("Value: ")
        self.value_input1_double = QLineEdit("0")
        self.and_label_double = QLabel("and")
        self.value_label2_double = QLabel("Value: ")
        self.value_input2_double = QLineEdit("0")
        double_grid_layout.addWidget(self.value_label1_double, 0, 1, Qt.AlignBottom)
        double_grid_layout.addWidget(self.value_label2_double, 0, 3, Qt.AlignBottom)
        hex_widget_double = QWidget()
        hex_layout_double = QHBoxLayout(hex_widget_double)
        hex_layout_double.setContentsMargins(0, 0, 0, 0)
        hex_layout_double.addWidget(self.hex_checkbox_double)
        hex_layout_double.addWidget(self.hex_checkbox_double)
        hex_layout_double.addStretch()
        double_grid_layout.addWidget(hex_widget_double, 1, 0)
        double_grid_layout.addWidget(self.value_input1_double, 1, 1)
        double_grid_layout.addWidget(self.and_label_double, 1, 2, Qt.AlignCenter)
        double_grid_layout.addWidget(self.value_input2_double, 1, 3)
        double_grid_layout.setColumnStretch(1, 1)
        double_grid_layout.setColumnStretch(3, 1)
        double_grid_layout.setColumnMinimumWidth(
            0,
            self.hex_label_double.fontMetrics().width("Hex")
            + self.hex_checkbox_double.sizeHint().width()
            + 10,
        )
        self.input_area_stacked_widget.addWidget(self.double_input_widget)
        scan_controls_layout.addWidget(self.input_area_stacked_widget)

        # Hex Checkbox Synchronization
        self.hex_checkbox_single.stateChanged.connect(
            lambda state, cb=self.hex_checkbox_double: (
                cb.isChecked(state) if cb.isChecked() != state else None
            )
        )
        self.hex_checkbox_single.stateChanged.connect(
            lambda state, cb=self.hex_checkbox_single: (
                cb.isChecked(state) if cb.isChecked() != state else None
            )
        )

        # Scan Type and Value Type Form
        form_container_widget = QWidget()
        form_container_widget.setContentsMargins(0, 0, 0, 0)
        form_layout_internal = QFormLayout(form_container_widget)
        form_layout_internal.setContentsMargins(0, 5, 0, 5)
        form_layout_internal.setVerticalSpacing(3)
        form_layout_internal.setLabelAlignment(Qt.AlignLeft)
        self.scan_type_combo = QComboBox()
        self.value_type_combo = QComboBox()
        form_layout_internal.addRow(QLabel("Scan Type:"), self.scan_type_combo)
        form_layout_internal.addRow(QLabel("Value Type:", self.value_type_combo))
        scan_controls_layout.addWidget(form_container_widget)

        # Value Type Options and Map (struct format char, size in bytes)
        self.value_types_map = {
            "Byte": ("b", 1),
            "2 Bytes": ("h", 2),
            "4 Bytes": ("i", 4),
            "8 Bytes": ("q", 8),
            "Float": ("f", 4),
            "Double": ("d", 8),
            "String": (None, None),
            "Array of Byte": (None, None)
        }

        self.value_type_combo.addItems(self.value_types_map.keys())

        # String Specific Checkboxes
        checkbox_widget = QWidget()
        checkbox_widget.setContentsMargins(0, 0, 0, 0)
        checkbox_layout = QVBoxLayout(checkbox_widget)
        checkbox_layout.setContentsMargins(0, 5, 0, 0)
        checkbox_layout.setSpacing(3)
        self.case_sensitive_checkbox = QCheckBox("Case Sensitive")
        self.utf16_checkbox = QCheckBox("UTF-16")
        checkbox_layout.addWidget(self.case_sensitive_checkbox)
        checkbox_layout.addWidget(self.utf16_checkbox)
        scan_controls_layout.addWidget(checkbox_widget)

        scan_controls_layout.addSpacerItem(QSpacerItem(20, 0, QSizePolicy.Minimum, QSizePolicy.Expanding))

        middle_layout.addWidget(scan_controls_widget, 1)
        main_layout.addLayout(middle_layout, 1)

        # Bottom Panel
        self.manual_address_table = QTableWidget()
        self.manual_address_table.setColumnCount(3)
        self.manual_address_table.verticalHeader().setVisible(False)
        self.manual_address_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        main_layout.addWidget(self.manual_address_table, 0)

        # Connect Signals for UI Updates
        # self.value_type_combo.currentIndexChanged.connect(self.update_scan_options)
        # self.scan_type_combo.currentIndexChanged.connect(self.update_input_fields_layout)

        # Initial UI State
        self.value_type_combo.setCurrentText("4 Bytes")
        # self.update_scan_options

        # Timer for Real-time Value Updates in Tables
        self.update_timer = QTimer(self)
        self.update_timer.setInterval(1000)
        self.update_timer.timeout.connect(self.update_displayed_values)

    def open_process_window(self):
        dialog = ProcessWindow(self)
        dialog.process_selected_signal.connect(self.handle_process_attached)
        dialog.exec_()

    def handle_process_attached(self, pid, name):
        self.selected_pid = pid
        self.selected_process_name = name
        self.current_scan_results.clear()
        self.results_table.setRowCount(0)
        self.update_timer.stop()
        if self.process_handle_main_python:
            CloseHandle_Raw(self.process_handle_main_python)
            self.process_handle_main_python = None
        if pid == 0:
            self.selected_process_label.setText("No process attached")
            self.selected_pid = None
            return

        try:
            self.process_handle_main_python = OpenProcess_Raw(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
            if not self.process_handle_main_python:
                raise Exception(f"OpenProcess_Raw failed with error: {ctypes.get_last_error()}")
            self.selected_process_label.setText(f"Attached to: {name} (PID: {pid})")
            QMessageBox.information(self, "Process Attached", f"Successfully attached to {name} (PID: {pid})")
        except Exception as e:
            self.selected_pid = None
            self.selected_process_name = ""
            self.process_handle_main_python = None
            self.selected_process_label.setText("No process attached")
            QMessageBox.critical(self, "Attachment Error", f"Could not open process {name} (PID: {pid}): {e}")

    def update_displayed_values(self):
        if not self.process_handle_main_python or not self.current_scan_results or not self.results_table.isVisible():
            return

        if not psutil.pid_exists(self.selected_pid):
            QMessageBox.warning(self, "Process Ended", "The attached process has ended")
            self.handle_process_attached(0, "")
            self.update_timer.stop()
            return

        self.results_table.blockSignals(True)

        viewport = self.results_table.viewport()
        viewport_rect = viewport.rect()

        first_visible_row = self.results_table.indexAt(viewport_rect.topLeft()).row()
        last_visible_row_approx = self.results_table.indexAt(viewport_rect.bottomLeft()).row()
        if first_visible_row == -1:
            first_visible_row = 0
        if last_visible_row_approx == -1:
            if self.results_table.rowCount() > 0 and self.results_table.rowHeight(0) > 0:
                last_visible_row_approx = first_visible_row + (
                        viewport_rect.height() // self.results_table.rowHeight(0)) + 2
            else:
                last_visible_row_approx = self.results_table.rowCount() - 1
        start_row = max(0, first_visible_row)
        end_row = min(self.results_table.rowCount(), last_visible_row_approx + 2)

        for row_idx_in_table in range(start_row, end_row):
            addr_item = self.results_table.item(row_idx_in_table, 0)
            val_item_cell = self.results_table.item(row_idx_in_table, 1)

            if not addr_item or not val_item_cell:
                continue

            address = addr_item.data(Qt.UserRole)
            value_type = addr_item.data(Qt.UserRole + 1)

            if address is not None and value_type is not None and 0 <= row_idx_in_table < len(
                    self.current_scan_results):
                current_result_entry = self.current_scan_results[row_idx_in_table]
                if current_result_entry['address'] != address:
                    continue

                # Modified Read Logic For Aob
                read_length_for_live_update = None
                if value_type == "Array Of Byte":
                    read_length_for_live_update = current_result_entry.get("length", 16)

                current_mem_val = self._read_memory_value(address, value_type, length_hint=read_length_for_live_update)

                new_value_text = self._format_value_for_display(current_mem_val, value_type)

                previous_scan_value = current_result_entry['previous_value']

                if current_mem_val is not None:
                    current_result_entry['value'] = current_mem_val

                    if val_item_cell.text() != new_value_text:
                        val_item_cell.setText(new_value_text)

                    values_are_different_from_previous = False
                    if value_type == "String" or value_type == "Array Of Byte":
                        values_are_different_from_previous = (current_mem_val != previous_scan_value)
                    else:
                        try:
                            values_are_different_from_previous = (current_mem_val != previous_scan_value)
                        except TypeError:
                            values_are_different_from_previous = (
                                    new_value_text != self._format_value_for_display(previous_scan_value,
                                                                                     value_type))
                    if values_are_different_from_previous:
                        val_item_cell.setBackground(CHANGED_BACKGROUND_BRUSH)
                    else:
                        val_item_cell.setBackground(CHANGED_BACKGROUND_BRUSH)
                        val_item_cell.setForeground(NORMAL_TEXT_BRUSH)
                else:
                    if val_item_cell.text() != "???":
                        val_item_cell.setText("???")

                    val_item_cell.setBackground(NORMAL_BACKGROUND_BRUSH)
                    val_item_cell.setForeground(NORMAL_TEXT_BRUSH)

            else:
                if val_item_cell.text() != "ERR_DATA":
                    val_item_cell.setText("ERR_DATA")

        self.results_table.blockSignals(False)

    def move_selected_to_bottom_table(self):
        sel_items = self.results_table.selectedItems()
        if not sel_items:
            QMessageBox.information(self, "No Selection", "Please select rows first.")
            return
        unique_rows = sorted(list(set(item.row() for item in sel_items)))
        for r_idx in unique_rows:
            addr_i = self.results_table.item(r_idx, 0)
            if not addr_i:
                continue
            addr_val = addr_i.data(Qt.UserRole)
            type_val = addr_i.data(Qt.UserRole + 1)
            res_data = next((r for r in self.current_scan_results if r['address'] == addr_val), None)
            if not res_data:
                continue
            exists = any(self.manual_address_table.item(r, 0) and self.manual_address_table.item(r,
                                                                                                 0).text() == f"0x{res_data['address']:X}"
                         for r in range(self.manual_address_table.rowCount()))

            if exists:
                continue

            b_r_c = self.manual_address_table.rowCount()
            self.manual_address_table.insertRow(b_r_c)
            live_val = self._read_memory_value(res_data['address'], type_val)
            val_txt = self._format_value_for_display(live_val if live_val is not None else res_data['value'], type_val)
            self.manual_address_table.setItem(b_r_c, 0, QTableWidgetItem(f"0x{res_data['address']:X}"))
            self.manual_address_table.setItem(b_r_c, 1, QTableWidgetItem(type_val))
            self.manual_address_table.setItem(b_r_c, 2, QTableWidgetItem(val_txt))

    # Scanning Biyatch
    def initiate_first_scan(self):
        if not self.selected_pid:
            QMessageBox.warning(self, "Scan Error", "No process attached")
            return
        if self.scan_thread and self.scan_thread.isRunning():
            QMessageBox.warning(self, "Scan Info", "A scan is already in progress.")
            return
        scan_params = self._get_scan_parameters()
        if scan_params is None:
            return
        self.current_scan_results.clear()
        self.results_table.setRowCount(0)
        self.update_timer.stop()
        if SCANNER_CORE_DLL is None and scan_params['value_type'] == "4 Bytes":
            QMessageBox.warning(self, "DLL Error", "ScannerCore.dll not loaded. 4-byte scan will use slower Python fallback")
        self.scan_thread = ScanThread(self.selected_pid, scan_params, timeout_seconds=30)
        self.scan_thread.results_ready.connect(self.handle_scan_results_batch)
        self.scan_thread.progress_update.connect(self.handle_scan_progress)
        self.scan_thread.scan_finished.connect(self.handle_scan_finished)
        self.scan_thread.error_occured.connect(self.handle_scan_error)
        self._setup_progress_dialog("First Scan")
        self.first_scan_button.setEnabled(False)
        self.next_scan_button.setEnabled(False)
        self.cancel_scan_button.setEnabled(True)
        self.scan_thread.start()

    # Private Utils
    def _format_value_for_display(self, value, value_type_str):
        if value is None:
            return "???"
        if value_type_str == "String":
            return str(value)
        if value_type_str == "Array Of Byte":
            return value.hex().upper() if isinstance(value, bytes) else "ERR_BYTES"
        if isinstance(value, (int, float)):
            if value_type_str in ["Float", "Double"]:
                return f"{value:.4f}"
            else:
                fmt_char, size_bytes = self.value_types_map.get(value_type_str, (None, 0))
                if size_bytes is None:
                    return str(value)
                hex_len = size_bytes * 2
                value_to_format = value
                if value < 0 and value_type_str != "Byte":
                    value_to_format = (1 << (size_bytes * 8)) + value
                elif value_type_str == "Byte" and value < 0:
                    value_to_format = value & 0xFF
                return f"0x{value_to_format:0{hex_len}X}"
        return str(value)

    def _read_memory_value(self, address, value_type_str, length_hint=None):
        if not self.process_handle_main_python:
            return None

        fmt_char_ign, type_size = self.value_types_map.get(value_type_str, (None, 0))
        read_size = type_size

        if value_type_str == "String":
            read_size = length_hint if length_hint is not None else 256
        elif value_type_str == "Array Of Byte":
            read_size = length_hint if length_hint is not None else 16

        if read_size is None or read_size <= 0:
            return None

        buffer = ctypes.create_string_buffer(read_size)
        bytes_read_c = ctypes.c_size_t(0)

        if ReadProcessMemory_Raw(self.process_handle_main_python, ctypes.c_void_p(address), buffer, read_size,
                                 ctypes.byref(bytes_read_c)):
            actual_read = bytes_read_c.value
            if actual_read == 0:
                return None

            if value_type_str not in ["String", "Array Of Byte"] and actual_read < type_size:
                return None

            if value_type_str in ["String", "Array Of Byte"]:
                effective_data = buffer.raw[:actual_read]
            else:
                effective_data = buffer.raw

            try:
                if value_type_str == "Byte":
                    return struct.unpack_from('<b', effective_data, 0)[0]
                elif value_type_str == "2 Bytes":
                    return struct.unpack_from('<h', effective_data, 0)[0]
                elif value_type_str == "4 Bytes":
                    return struct.unpack_from('<i', effective_data, 0)[0]
                elif value_type_str == "8 Bytes":
                    return struct.unpack_from('<q', effective_data, 0)[0]
                elif value_type_str == "Float":
                    return struct.unpack_from('<f', effective_data, 0)[0]
                elif value_type_str == "Double":
                    return struct.unpack_from('<d', effective_data, 0)[0]
                elif value_type_str == "String":
                    raw_b = effective_data
                    enc = 'utf-16-le' if self.utf16_checkbox.isChecked() else 'ascii'
                    nt = b'\x00\x00' if enc == 'utf-16-le' else b'\x00'
                    idx = raw_b.find(nt)
                    if idx != -1:
                        raw_b = raw_b[:idx]
                    return raw_b.decode(enc, errors="ignore")
                elif value_type_str == "Array Of Byte":
                    return effective_data
            except (struct.error, UnicodeDecodeError):
                return None

        return None

    def _get_scan_parameters(self):
        value_type_str = self.value_type_combo.currentText()
        scan_type_str = self.scan_type_combo.currentText()
        is_hex_input = self.hex_checkbox_single.isChecked() if self.input_area_stacked_widget.currentWidget() == self.single_input_widget else self.hex_checkbox_double.isChecked()
        input_val1_str = self.value_input_single.text() if self.input_area_stacked_widget.currentWidget() == self.single_input_widget else self.value_input1_double.text()
        input_val2_str = self.value_input2_double.text() if self.input_area_stacked_widget.currentWidget() == self.double_input_widget and scan_type_str == "Value Between..." else None
        try:
            parsed_val1 = self._parse_input_value(input_val2_str, value_type_str, is_hex_input)
            parsed_val2 = None
            if input_val2_str:
                parsed_val2 = self._parse_input_value(input_val2_str, value_type_str, is_hex_input)
        except ValueError as e:
            QMessageBox.warning(self, "Input Error", str(e))
            return None
        return {'value_type': value_type_str, 'scan_type': scan_type_str, 'parsed_val1': parsed_val1,
                'parsed_val2': parsed_val2, 'case_sensitive': self.case_sensitive_checkbox.isChecked(),
                'is_utf_16': self.utf16_checkbox.isChecked()}


if __name__ == "__main__":
    app = QApplication(sys.argv)
    main_win = MainWindow()
    main_win.show()
    sys.exit(app.exec_())
