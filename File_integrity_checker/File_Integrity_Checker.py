


"""
File Integrity Checker
Programming Language: Python
Difficulty (1 to 10): 5

This program provides a GUI-based file integrity checker using PyQt5. It allows users to select a folder, choose checksum algorithms, and scan files within the folder to verify their integrity. The program can detect changes in file contents by comparing current checksums with previously stored values and display the results in a user-friendly interface.

Functions
- **initUI()
    Initializes the graphical user interface, creating buttons for selecting a folder and starting the scan, a progress bar, status bar, a list of checksum algorithms, and a list to display files with mismatched checksums.

- **resetProgressBar()
    Resets the progress bar to zero after the scan is completed.

- **selectFolder()
    Opens a file dialog to allow the user to select a folder for scanning. Updates the UI to show the selected folder path.

- **startScan()
    Validates if a folder has been selected and initiates the scanning process by calling scanFolder() with the selected algorithms.

- **canFolder(folderPath, algorithms)
    Scans the specified folder for files, calculates checksums for each file using the selected algorithms, and updates the database with the new checksums. It displays mismatched files if any discrepancies are found.

- **calculateChecksums(filePath, algorithms)
    Calculates the checksums of a given file using the specified algorithms. Returns a dictionary containing the checksums.

- **displayChangedFiles(modified_files)
    Displays a message box with the list of files that have modified checksums detected during the scan. Calls displayMismatchedFiles() to update the UI.

- **displayMismatchedFiles(modified_files)
    Updates the mismatched files list in the UI, showing the details of checksum mismatches with color-coding (dark green for matching, red for mismatching).

- **updateDatabase(filePath, checksums)
    Updates the checksum database with the new checksums for the given file. Detects and records any modifications by comparing with previous checksums.

- **compareResults(current_results, previous_results)
    Compares the current and previous checksum results to detect any mismatches. Handles mismatches by calling handleChecksumMismatch().

- **handleChecksumMismatch(file_path, algorithm, previous_checksum, current_checksum)
    Handles detected checksum mismatches by logging the event and optionally alerting the user.

### Usage
1. Open the application.
2. Click "Select Folder" to choose the folder you want to scan.
3. Select the desired checksum algorithms from the list.
4. Click "Start Scan" to initiate the scanning process.
5. View the results in the status bar and the list of mismatched files.
6. If any files have modified checksums, they will be highlighted in the list.

### Dependencies
- **os**: Module for interacting with the operating system.
- **hashlib**: Module for secure hash and message digest algorithms.
- **json**: Module for parsing and manipulating JSON data.
- **threading**: Module for concurrent execution using threads.
- **schedule**: Python library for scheduling tasks.
- **time**: Module for time-related functions.
- **blake3**: Python library for the BLAKE3 cryptographic hash function.
- **PyQt5.QtWidgets**: Module for creating graphical user interfaces (GUIs) with PyQt5.
  - **QApplication**: Manages application-wide resources and settings.
  - **QMainWindow**: Provides a main application window with a menu bar, toolbars, and a status bar.
  - **QFileDialog**: Provides a dialog for file selection.
  - **QPushButton**: Provides a clickable button widget.
  - **QVBoxLayout**: Provides a vertical layout for arranging widgets.
  - **QWidget**: Base class for all UI objects.
  - **QProgressBar**: Provides a horizontal progress bar.
  - **QStatusBar**: Provides a status bar for displaying status information.
  - **QMessageBox**: Provides a message box dialog.
  - **QListWidget**: Provides a list widget that allows the user to select one or more items.
  - **QLabel**: Provides a text or image display.
  - **QListWidgetItem**: Represents an item in a QListWidget.
- **PyQt5.QtCore**: Module for core non-GUI functionality in PyQt5.
  - **Qt**: Namespace for various identifiers used throughout the PyQt5 library.
  - **QTimer**: Provides repetitive and single-shot timers.
  - **pyqtSlot**: Decorator for defining slots in PyQt5.
- **PyQt5**: Module for creating cross-platform applications with a native look and feel.
  - **QtGui**: Module for graphical user interface functionality within PyQt5.
"""

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
    """
    A class to handle the scanning of files in a separate thread.
    This class extends threading.Thread and is used to calculate checksums
    for a given file using specified algorithms.

    Attributes:
    file_path (str): The path to the file to be scanned.
    algorithms (list): A list of algorithms to use for checksum calculation.
    result (dict): The calculated checksums.
    """

    def __init__(self, file_path, algorithms):
        """
        Initializes the ScanThread with the file path and algorithms.

        Args:
        file_path (str): The path to the file to be scanned.
        algorithms (list): A list of algorithms to use for checksum calculation.
        """
        super().__init__()
        self.file_path = file_path
        self.algorithms = algorithms
        self.result = None

    def run(self):
        """
        The run method that is executed when the thread starts.
        It calculates the checksums for the file.
        """
        self.result = self.calculateChecksums(self.file_path, self.algorithms)

    def get_result(self):
        """
        Retrieves the result of the checksum calculation.

        Returns:
        dict: The calculated checksums.
        """
        return self.result
    
    def calculateChecksums(self, filePath, algorithms):
        """
        Calculates checksums for a given file using specified algorithms.

        Args:
        filePath (str): The path to the file.
        algorithms (list): A list of algorithms to use for checksum calculation.

        Returns:
        dict: A dictionary containing the checksums for each algorithm.
        """
        checksums = {}
        for algorithm in algorithms:
            if algorithm == 'blake3':
                hash_object = blake3.blake3()
                with open(filePath, "rb") as f:
                    while True:
                        data = f.read(65536)  # 64kb chunks
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
                            data = f.read(65536)  # 64kb chunks
                            if not data:
                                break
                            hash_object.update(data)
                    checksums[algorithm] = hash_object.hexdigest()
        return checksums

class FileIntegrityChecker(QMainWindow):
    """
    A class to create a GUI for file integrity checking using PyQt5.
    This class extends QMainWindow and provides functionalities to select a folder,
    choose algorithms, and start scanning files for checksum verification.

    Attributes:
    supported_algorithms (list): A list of supported algorithms for checksum calculation.
    """
    
    def __init__(self):
        """
        Initializes the FileIntegrityChecker with the supported algorithms and UI setup.
        """
        super().__init__()
        self.supported_algorithms = ['md5', 'sha1', 'sha256', 'sha512', 'blake3']
        self.initUI()

    def initUI(self):
        """
        Initializes the user interface elements and layout.
        """
        self.setWindowTitle("File Integrity Checker")
        self.setGeometry(100, 100, 800, 600)

        # UI Elements for file selection and starting the scan
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

        # Label to display selected folder path
        self.selectedFolderLabel = QLabel(self)
        self.selectedFolderLabel.setAlignment(Qt.AlignCenter)
        self.selectedFolderLabel.setText("Selected Folder: ")

        # Timer to reset progress bar after scan
        self.resetProgressBarTimer = QTimer(self)
        self.resetProgressBarTimer.setSingleShot(True)
        self.resetProgressBarTimer.timeout.connect(self.resetProgressBar)

        # Mismatched files list
        self.mismatchedList = QListWidget(self)
        self.mismatchedLabel = QLabel("Checksum Mismatched Files:", self)

        # Layout
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
        """
        Resets the progress bar to 0 after a scan is completed.
        """
        self.progressBar.setValue(0)

    @pyqtSlot()
    def selectFolder(self):
        """
        Opens a dialog for selecting a folder and updates the selected folder label.

        Uses:
        QFileDialog: To open a folder selection dialog.
        """
        folderPath = QFileDialog.getExistingDirectory(self, "Select Folder")
        if folderPath:
            self.folderPath = folderPath
            self.selectedFolderLabel.setText(f"Selected Folder: {folderPath}")

    @pyqtSlot()
    def startScan(self):
        """
        Starts the scanning process for the selected folder with the chosen algorithms.
        """
        if hasattr(self, 'folderPath'):
            algorithms = [self.algorithmList.item(i).text() for i in range(self.algorithmList.count()) if
                        self.algorithmList.item(i).isSelected()]
            self.scanFolder(self.folderPath, algorithms)
        else:
            self.statusBar.showMessage("No folder selected. Please select a folder to scan.")
    
    def scanFolder(self, folderPath, algorithms):
        """
        Scans the selected folder for files and calculates checksums using multiple threads.

        Args:
        folderPath (str): The path to the folder to be scanned.
        algorithms (list): A list of algorithms to use for checksum calculation.
        """
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
        """
        Displays a message box with the list of files whose checksums have changed.

        Args:
        modified_files (list): A list of files with modified checksums.
        """
        msgBox = QMessageBox()
        msgBox.setIcon(QMessageBox.Information)
        msgBox.setWindowTitle("Modified Files Detected")
        msgBox.setText("Files with modified checksums were detected during the scan:")
        msgBox.setDetailedText("\n".join(modified_files))
        msgBox.exec_()
        self.displayMismatchedFiles(modified_files)  # Displaying mismatched files in the UI

    def displayMismatchedFiles(self, modified_files):
        """
        Updates the mismatched files list in the UI with details of the changes.

        Args:
        modified_files (list): A list of files with modified checksums.
        """
        self.mismatchedList.clear()  # Clear previous entries if any
        database_file = "scan_results.json"
        existing_results = {}
        
        # Load existing results if the database file exists
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
                    item.setForeground(QtGui.QColor(255, 0, 0))  # Red color for mismatch
                else:
                    item.setForeground(QtGui.QColor(0, 100, 0))  # Dark green color for match
                
                self.mismatchedList.addItem(item)

    def calculateChecksums(self, filePath, algorithms):
        """
        Calculates checksums for a given file using specified algorithms.

        Args:
        filePath (str): The path to the file.
        algorithms (list): A list of algorithms to use for checksum calculation.

        Returns:
        dict: A dictionary containing the checksums for each algorithm.
        """
        checksums = {}
        for algorithm in algorithms:
            if algorithm == 'blake3':
                hash_object = blake3.blake3()
                with open(filePath, "rb") as f:
                    while True:
                        data = f.read(65536)  # 64kb chunks
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
                            data = f.read(65536)  # 64kb chunks
                            if not data:
                                break
                            hash_object.update(data)
                    checksums[algorithm] = hash_object.hexdigest()
        return checksums

    def updateDatabase(self, filePath, checksums):
        """
        Updates the checksum database with the new checksums and identifies modified files.

        Args:
        filePath (str): The path to the file.
        checksums (dict): The calculated checksums for the file.

        Returns:
        list: A list of files that have been modified.
        """
        database_file = "scan_results.json" #specify path and filename 
        modified_files = []
        existing_results = {}

        if os.path.exists(database_file):
            with open(database_file, "r") as f:
                existing_results = json.load(f)

        if filePath in existing_results:
            if existing_results[filePath] != checksums:
                modified_files.append(filePath)
                existing_results[filePath] = checksums  
        else:
            existing_results[filePath] = checksums

        self.current_scan_results = existing_results

        return modified_files

    def closeEvent(self, event):
        """
        Handles the close event of the main window.
        Updates the checksum database with the new scan results and displays a message box.

        Args:
        event (QCloseEvent): The close event.
        """
        # Update the checksum database with the latest results
        database_file = "scan_results.json"
        if hasattr(self, 'current_scan_results'):
            with open(database_file, "w") as f:
                json.dump(self.current_scan_results, f, indent=4) 
        
        # Show a message box to inform the user that checksums have been updated
        msgBox = QMessageBox()
        msgBox.setIcon(QMessageBox.Information)
        msgBox.setWindowTitle("Checksums Updated")
        msgBox.setText("Checksums have been updated.")
        msgBox.exec_()

        event.accept()  # Accept the event to close the window

        self.closeEvent = self.closeEvent 

    

    def compareResults(self, current_results, previous_results):
        """
        Compares the current and previous checksum results and handles mismatches.

        Args:
        current_results (dict): The current checksum results.
        previous_results (dict): The previous checksum results.
        """
        for file_path, current_checksums in current_results.items():
            if file_path in previous_results:
                previous_checksums = previous_results[file_path]
                for algorithm, current_checksum in current_checksums.items():
                    if algorithm in previous_checksums:
                        previous_checksum = previous_checksums[algorithm]
                        if current_checksum != previous_checksum:
                            # Handle checksum mismatch
                            self.handleChecksumMismatch(file_path, algorithm, previous_checksum, current_checksum)

    def handleChecksumMismatch(self, file_path, algorithm, previous_checksum, current_checksum):
        """
        Handles actions to be taken when a checksum mismatch is detected.

        Args:
        file_path (str): The path to the file with a mismatch.
        algorithm (str): The algorithm used for checksum calculation.
        previous_checksum (str): The previous checksum value.
        current_checksum (str): The current checksum value.
        """
        print(f"Checksum mismatch detected for file: {file_path}, algorithm: {algorithm}")
        print(f"Previous checksum: {previous_checksum}, Current checksum: {current_checksum}")

def main():
    """
    The main entry point of the application.
    Initializes the QApplication and displays the main window.
    """
    app = QApplication([])
    window = FileIntegrityChecker()
    window.show()
    app.exec_()

if __name__ == "__main__":
    main()
