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
)
from PyQt5.QtCore import Qt


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.MAX_DISPLAT_RESULTS = 5000
        global main_window_ref
        main_window_ref = self

        self.setWindowTitle("Memory Scanner")
        self.setGeometry(100, 100, 950, 600)

        self.selected_pid = None
        self.selected_process_name = ""

        self.process_handle.main_python = None

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


if __name__ == "__main__":
    app = QApplication(sys.argv)
    main_win = MainWindow()
    main_win.show()
    sys.exit(app.exec_())
