import os
import hashlib
import json
import threading
import schedule
import time
import blake3
from PyQt5.QtWidgets import (QApplication, QMainWindow, QFileDialog, QPushButton, 
                             QVBoxLayout, QWidget, QProgressBar, QStatusBar, 
                             QMessageBox, QListWidget, QLabel, QListWidgetItem)
from PyQt5.QtCore import Qt, QTimer, pyqtSlot
from PyQt5 import QtGui

class ScanThread(threading.Thread):
    def __init__(self, file_path, algorithms):
        super().__init__()
        self.file_path = file_path
        self.algorithms = algorithms
        self.result = None

    def run(self):
        self.result = self.calculateChecksums(self.file_path, self.algorithms)

    def get_result(self):
        return self.result
    
    def calculateChecksums(self, filePath, algorithms):
        checksums = {}
        for algorithm in algorithms:
            if algorithm == 'blake3':
                hash_object = blake3.blake3()
                with open(filePath, "rb") as f: 
                    while True:
                        data = f.read(65536)
                        if not data:
                            break
                        hash_object.update(data)
                checksums[algorithm] = hash_object.hexdigest()
            else:
                hash_func = getattr(hashlib, algorithm, None)
                if hash_func:
                    hash_object = hash_func()
                    with open(filePath, "rb") as f: 
                        while True:
                            data = f.read(65536)
                            if not data:
                                break
                            hash_object.update(data)
                    checksums[algorithm] = hash_object.hexdigest()
        return checksums

class FileIntegrityChecker(QMainWindow):    
    def __init__(self):
        super().__init__()
        self.supported_algorithms = ['md5', 'sha1', 'sha256', 'sha512', 'blake3']
        self.initUI()

    def initUI(self):
        self.setWindowTitle("File Integrity Checker")
        self.setGeometry(100, 100, 800, 600)

        self.btnSelectFolder = QPushButton("Select Folder", self)
        self.btnSelectFolder.clicked.connect(self.selectFolder)
        self.btnStartScan = QPushButton("Start Scan", self)
        self.btnStartScan.clicked.connect(self.startScan)
        self.progressBar = QProgressBar(self)
        self.statusBar = QStatusBar(self)
        self.algorithmList = QListWidget(self)
        self.algorithmList.setSelectionMode(QListWidget.MultiSelection)
        self.algorithmList.addItems(self.supported_algorithms)
        self.algorithmLabel = QLabel("Select Algorithms:", self)
        self.selectedFolderLabel = QLabel(self)
        self.selectedFolderLabel.setAlignment(Qt.AlignCenter)
        self.selectedFolderLabel.setText("Selected Folder: ")

        self.resetProgressBarTimer = QTimer(self)
        self.resetProgressBarTimer.setSingleShot(True)
        self.resetProgressBarTimer.timeout.connect(self.resetProgressBar)

        self.mismatchedList = QListWidget(self)
        self.mismatchedLabel = QLabel("Checksum Mismatched Files:", self)

        layout = QVBoxLayout()
        layout.addWidget(self.btnSelectFolder)
        layout.addWidget(self.selectedFolderLabel)  
        layout.addWidget(self.algorithmLabel)
        layout.addWidget(self.algorithmList)
        layout.addWidget(self.btnStartScan)
        layout.addWidget(self.progressBar)
        layout.addWidget(self.statusBar)
        layout.addWidget(self.mismatchedLabel)
        layout.addWidget(self.mismatchedList)

        widget = QWidget()
        widget.setLayout(layout)
        self.setCentralWidget(widget)

    def resetProgressBar(self): 
        self.progressBar.setValue(0)

    @pyqtSlot()
    def selectFolder(self):
        folderPath = QFileDialog.getExistingDirectory(self, "Select Folder")
        if folderPath:
            self.folderPath = folderPath
            self.selectedFolderLabel.setText(f"Selected Folder: {folderPath}")

    @pyqtSlot()
    def startScan(self):
        if hasattr(self, 'folderPath'):
            algorithms = [self.algorithmList.item(i).text() for i in range(self.algorithmList.count()) if
                          self.algorithmList.item(i).isSelected()]
            self.scanFolder(self.folderPath, algorithms)
        else:
            self.statusBar.showMessage("No folder selected. Please select a folder to scan.")
    
    def scanFolder(self, folderPath, algorithms):
        file_count = sum(len(files) for _, _, files in os.walk(folderPath))
        progress_step = 100 / file_count if file_count else 0
        current_progress = 0
        threads = []
        modified_files = []

        self.statusBar.showMessage(f"Starting scan of {file_count} files...")
        files_processed = 0  

        for root, dirs, files in os.walk(folderPath):
            for file in files:
                filePath = os.path.join(root, file)
                thread = ScanThread(filePath, algorithms)
                threads.append(thread)
                thread.start()

        for thread in threads:
            thread.join()
            checksums = thread.get_result()
            modified_files += self.updateDatabase(thread.file_path, checksums)
            files_processed += 1
            current_progress += progress_step
            self.progressBar.setValue(int(current_progress))
            QApplication.processEvents()

        if modified_files:
            self.displayChangedFiles(modified_files)
        self.statusBar.showMessage("Scan completed.")
        self.resetProgressBarTimer.start(5000)

    def displayChangedFiles(self, modified_files):
        msgBox = QMessageBox()
        msgBox.setIcon(QMessageBox.Information)
        msgBox.setWindowTitle("Modified Files Detected")
        msgBox.setText("Files with modified checksums were detected during the scan:")
        msgBox.setDetailedText("\n".join(modified_files))
        msgBox.exec_()
        self.displayMismatchedFiles(modified_files)

    def displayMismatchedFiles(self, modified_files):
        self.mismatchedList.clear()
        database_file = "scan_results.json"
        existing_results = {}
        
        if os.path.exists(database_file):
            with open(database_file, "r") as f:
                try:
                    existing_results = json.load(f)
                except json.JSONDecodeError as e:
                    print(f"Error loading JSON data: {e}")
                    return
        
        for file_path in modified_files:
            current_checksums = self.calculateChecksums(file_path, self.supported_algorithms)
            existing_checksums = existing_results.get(file_path, {})
            
            print(f"Processing file: {file_path}")
            print(f"Current checksums: {current_checksums}")
            print(f"Existing checksums: {existing_checksums}")

            for algorithm in self.supported_algorithms:
                current_checksum = current_checksums.get(algorithm, 'Not Available')
                original_checksum = existing_checksums.get(algorithm, 'Not Available')
                
                item_text = f"File: {file_path}\nAlgorithm: {algorithm}\nOriginal: {original_checksum}  Current: {current_checksum}"
                item = QListWidgetItem(item_text)
                
                if current_checksum != original_checksum:
                    item.setForeground(QtGui.QColor(255, 0, 0))
                else:
                    item.setForeground(QtGui.QColor(0, 100, 0))
                
                self.mismatchedList.addItem(item)

    def calculateChecksums(self, filePath, algorithms):
        checksums = {}
        for algorithm in algorithms:
            if algorithm == 'blake3':
                hash_object = blake3.blake3()
                with open(filePath, "rb") as f:  
                    while True:
                        data = f.read(65536)
                        if not data:
                            break
                        hash_object.update(data)
                checksums[algorithm] = hash_object.hexdigest()
            else:
                hash_func = getattr(hashlib, algorithm, None)
                if hash_func:
                    hash_object = hash_func()
                    with open(filePath, "rb") as f:  
                        while True:
                            data = f.read(65536)
                            if not data:
                                break
                            hash_object.update(data)
                    checksums[algorithm] = hash_object.hexdigest()
        return checksums

    def updateDatabase(self, filePath, checksums):
        database_file = "scan_results.json"
        modified_files = []
        existing_results = {}

        if os.path.exists(database_file):
            if os.path.getsize(database_file) > 0: 
                with open(database_file, "r") as f:
                    try:
                        existing_results = json.load(f)
                    except json.JSONDecodeError:
                        print(f"Error decoding JSON from {database_file}. Initializing empty results.")
                        existing_results = {}
            else:
                print(f"{database_file} is empty. Initializing empty results.")
        else:
            print(f"{database_file} does not exist. Initializing empty results.")
        if filePath in existing_results:
            if existing_results[filePath] != checksums:
                modified_files.append(filePath)
                existing_results[filePath] = checksums
        else:
            existing_results[filePath] = checksums
        self.current_scan_results = existing_results
        with open(database_file, "w") as f:
            json.dump(existing_results, f, indent=4)
        return modified_files

    def closeEvent(self, event):
        database_file = "scan_results.json"
        if hasattr(self, 'current_scan_results'):
            with open(database_file, "w") as f:
                json.dump(self.current_scan_results, f, indent=4) 
        
        msgBox = QMessageBox()
        msgBox.setIcon(QMessageBox.Information)
        msgBox.setWindowTitle("Checksums Updated")
        msgBox.setText("Checksums have been updated.")
        msgBox.exec_()

        event.accept()

    def compareResults(self, current_results, previous_results):
        for file_path, current_checksums in current_results.items():
            if file_path in previous_results:
                previous_checksums = previous_results[file_path]
                for algorithm, current_checksum in current_checksums.items():
                    if algorithm in previous_checksums:
                        previous_checksum = previous_checksums[algorithm]
                        if current_checksum != previous_checksum:
                            self.handleChecksumMismatch(file_path, algorithm, previous_checksum, current_checksum)

    def handleChecksumMismatch(self, file_path, algorithm, previous_checksum, current_checksum):
        print(f"Checksum mismatch detected for file: {file_path}, algorithm: {algorithm}")
        print(f"Previous checksum: {previous_checksum}, Current checksum: {current_checksum}")

def main():
    app = QApplication([])
    window = FileIntegrityChecker()
    window.show()
    app.exec_()

if __name__ == "__main__":
    main()
