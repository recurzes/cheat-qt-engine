import psutil
from PyQt5.QtCore import pyqtSignal
from PyQt5.QtWidgets import QDialog, QVBoxLayout, QTableWidget, QAbstractItemView, QHeaderView, QPushButton, \
    QDialogButtonBox, QTableWidgetItem
from typing import Callable


class ProcessWindow(QDialog):
    process_selected_signal = pyqtSignal(int, str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Process List")
        self.setGeometry(200, 200, 500, 400)
        layout = QVBoxLayout(self)
        self.process_table = QTableWidget()
        self.process_table.setColumnCount(2)
        self.process_table.setHorizontalHeaderLabels(["Process ID", "Process Name"])
        self.process_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.process_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.process_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.process_table.verticalHeader().setVisible(False)
        header = self.process_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        layout.addWidget(self.process_table)
        self.refresh_button = QPushButton("Refresh List")
        self.refresh_button.clicked.connect(self.populate_process)
        button_box = QDialogButtonBox()
        self.attach_button = button_box.addButton("Attach to Process", QDialogButtonBox.ActionRole)
        self.attach_button.setEnabled(False)
        close_button = button_box.addButton(QDialogButtonBox.Close)
        self.attach_button.clicked.connect(self.reject)
        layout.addWidget(self.refresh_button)
        layout.addWidget(button_box)
        self.process_table.itemSelectionChanged.connect(self.on_selection_changed)
        self.populate_process()

    def populate_process(self):
        self.process_table.setRowCount(0)
        try:
            current_pid = psutil.Process().pid
        except psutil.Error:
            current_pid = -1

        processes = []
        for proc_info in psutil.process_iter(['pid', 'name']):
            try:
                pid = proc_info.info['pid']
                name = proc_info.info['name']
                if pid == 0 or pid == current_pid: continue
                if name: processes.append((pid, name))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

            self.process_table.setRowCount(len(processes))
            for row, (pid, name) in enumerate(processes):
                self.process_table.setItem(row, 0, QTableWidgetItem(str(pid)))
                self.process_table.setItem(row, 1, QTableWidgetItem(name))
