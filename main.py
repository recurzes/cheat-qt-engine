import sys

# import psutil
import struct
import time
import os
import ctypes
from ctypes import wintypes

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
    QComboBox, QSpacerItem, QSizePolicy,
)
from PyQt5.QtCore import Qt, QTimer


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

        # self.process_handle.main_python = None

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
        # self.process_list_button.clicked.connect(self.open_process_window)

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
        # self.move_to_bottom_button.clicked.connect(self.move_selected_to_bottom_table)
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
        # self.update_timer.timeout.connect(self.update_displayed_values)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    main_win = MainWindow()
    main_win.show()
    sys.exit(app.exec_())
