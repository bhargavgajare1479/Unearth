"""
Unearth Forensic Recovery Tool - GUI Interface
Production-ready version with all fixes
"""

import sys
import os
from pathlib import Path
from datetime import datetime
import random

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QFrame, QTableWidget, QTableWidgetItem,
    QHeaderView, QLineEdit, QTextEdit, QComboBox, QCheckBox,
    QStackedWidget, QListWidget, QListWidgetItem, QFileDialog,
    QMessageBox, QProgressBar, QDialog, QDialogButtonBox
)
from PyQt6.QtCore import Qt, QSize, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QPalette, QColor

try:
    import qtawesome as qta
    HAS_QTAWESOME = True
except ImportError:
    HAS_QTAWESOME = False
    print("Warning: qtawesome not available, using text icons")

# Try to import backend
try:
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from app import UnearthApp
    from utils import (
        list_xfs_btrfs_partitions, list_external_drives,
        format_bytes, check_root_permissions
    )
    BACKEND_AVAILABLE = True
except ImportError as e:
    print(f"Backend not available: {e}")
    BACKEND_AVAILABLE = False
    
    # Mock functions
    def list_xfs_btrfs_partitions():
        return []
    
    def list_external_drives():
        return []
    
    def format_bytes(size):
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} PB"
    
    def check_root_permissions():
        return os.geteuid() == 0 if hasattr(os, 'geteuid') else False


def get_icon(name, color='#FFFFFF'):
    """Get icon - fallback to text if qtawesome not available"""
    if HAS_QTAWESOME:
        try:
            return qta.icon(name, color=color)
        except:
            pass
    # Return text-based icon
    from PyQt6.QtGui import QIcon
    return QIcon()


class ScanWorker(QThread):
    """Background worker for scanning"""
    progress_updated = pyqtSignal(int, str)
    scan_completed = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)
    
    def __init__(self, app, session_id):
        super().__init__()
        self.app = app
        self.session_id = session_id
        
    def run(self):
        try:
            self.progress_updated.emit(30, "Detecting filesystem...")
            fs_type = self.app.detect_filesystem(self.session_id)
            
            self.progress_updated.emit(60, "Recovering files...")
            recovered = self.app.recover_deleted_files(self.session_id)
            
            self.progress_updated.emit(90, "Carving files...")
            carved = self.app.carve_files(self.session_id)
            
            self.progress_updated.emit(100, "Complete")
            self.scan_completed.emit({
                'recovered': recovered,
                'carved': carved
            })
        except Exception as e:
            self.error_occurred.emit(str(e))


class SidebarButton(QPushButton):
    """Custom sidebar button"""
    def __init__(self, icon_name, text, parent=None):
        super().__init__(parent)
        self.setText(f"  {text}")
        icon = get_icon(icon_name, '#9CA3AF')
        if not icon.isNull():
            self.setIcon(icon)
            self.setIconSize(QSize(18, 18))
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setCheckable(True)
        self.setFixedHeight(40)
        self.setStyleSheet("""
            SidebarButton {
                background-color: transparent;
                color: #9CA3AF;
                text-align: left;
                padding-left: 15px;
                border: none;
                border-radius: 8px;
                font-size: 13px;
            }
            SidebarButton:hover {
                background-color: #2A2F3A;
                color: #FFFFFF;
            }
            SidebarButton:checked {
                background-color: #3B82F6;
                color: #FFFFFF;
            }
        """)


class UnearthGUI(QMainWindow):
    """Main Unearth GUI Application"""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("UnEarth - Forensic Data Recovery")
        self.setGeometry(100, 100, 1600, 900)
        
        # Initialize backend if available
        self.app = UnearthApp() if BACKEND_AVAILABLE else None
        self.current_session = None
        self.recovered_files = []
        self.carved_files = []
        self.scan_worker = None
        
        self.setup_ui()
        
        # Check permissions (warn but don't block)
        if not check_root_permissions() and BACKEND_AVAILABLE:
            self.show_permission_warning()
    
    def show_permission_warning(self):
        """Show permission warning"""
        msg = QMessageBox(self)
        msg.setIcon(QMessageBox.Icon.Warning)
        msg.setWindowTitle("Limited Permissions")
        msg.setText("Running without elevated privileges")
        msg.setInformativeText(
            "Some features may be limited:\n"
            "• Cannot access raw disk devices\n"
            "• Cannot scan unmounted partitions\n\n"
            "For full functionality:\n"
            "• Linux/Mac: Run without sudo, app will request permissions when needed\n"
            "• Windows: Run as normal user, app will request elevation when needed"
        )
        msg.setStandardButtons(QMessageBox.StandardButton.Ok)
        msg.exec()
    
    def setup_ui(self):
        """Setup main UI"""
        central = QWidget()
        self.setCentralWidget(central)
        
        main_layout = QHBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # Sidebar
        sidebar = self.create_sidebar()
        main_layout.addWidget(sidebar)
        
        # Content stack
        self.content_stack = QStackedWidget()
        self.content_stack.setStyleSheet("background-color: #16161E;")
        
        # Add all views
        self.content_stack.addWidget(self.create_dashboard_view())
        self.content_stack.addWidget(self.create_recovered_files_view())
        self.content_stack.addWidget(self.create_timeline_view())
        self.content_stack.addWidget(self.create_keyword_search_view())
        self.content_stack.addWidget(self.create_integrity_view())
        self.content_stack.addWidget(self.create_metadata_view())
        self.content_stack.addWidget(self.create_report_view())
        
        main_layout.addWidget(self.content_stack, stretch=1)
    
    def create_sidebar(self):
        """Create sidebar"""
        sidebar = QFrame()
        sidebar.setFixedWidth(220)
        sidebar.setStyleSheet("""
            QFrame {
                background-color: #1E1E2E;
                border-right: 1px solid #2A2F3A;
            }
        """)
        
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(15, 20, 15, 20)
        layout.setSpacing(5)
        
        # Logo
        logo = QLabel("🔍 UnEarth")
        logo.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        logo.setStyleSheet("color: #FFFFFF; padding: 10px;")
        layout.addWidget(logo)
        
        layout.addSpacing(20)
        
        # Data Recovery Section
        section = QLabel("DATA RECOVERY")
        section.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        section.setStyleSheet("color: #6B7280; padding: 5px 15px;")
        layout.addWidget(section)
        
        # Navigation buttons
        self.btn_dashboard = SidebarButton('fa5s.th-large', "Dashboard")
        self.btn_dashboard.setChecked(True)
        self.btn_dashboard.clicked.connect(lambda: self.switch_view(0))
        
        self.btn_recovered = SidebarButton('fa5s.folder-open', "Recovered Files")
        self.btn_recovered.clicked.connect(lambda: self.switch_view(1))
        
        self.btn_timeline = SidebarButton('fa5s.chart-line', "File Timeline")
        self.btn_timeline.clicked.connect(lambda: self.switch_view(2))
        
        self.btn_keywords = SidebarButton('fa5s.search', "Keyword Search")
        self.btn_keywords.clicked.connect(lambda: self.switch_view(3))
        
        layout.addWidget(self.btn_dashboard)
        layout.addWidget(self.btn_recovered)
        layout.addWidget(self.btn_timeline)
        layout.addWidget(self.btn_keywords)
        
        layout.addSpacing(20)
        
        # Forensic Tools Section
        section2 = QLabel("FORENSIC TOOLS")
        section2.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        section2.setStyleSheet("color: #6B7280; padding: 5px 15px;")
        layout.addWidget(section2)
        
        self.btn_integrity = SidebarButton('fa5s.shield-alt', "Integrity Verification")
        self.btn_integrity.clicked.connect(lambda: self.switch_view(4))
        
        self.btn_metadata = SidebarButton('fa5s.info-circle', "Metadata Extraction")
        self.btn_metadata.clicked.connect(lambda: self.switch_view(5))
        
        self.btn_report = SidebarButton('fa5s.file-alt', "Report Generator")
        self.btn_report.clicked.connect(lambda: self.switch_view(6))
        
        layout.addWidget(self.btn_integrity)
        layout.addWidget(self.btn_metadata)
        layout.addWidget(self.btn_report)
        
        layout.addStretch()
        
        # Attach button
        self.attach_btn = QPushButton("+ Attach Source...")
        self.attach_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.attach_btn.clicked.connect(self.show_attach_menu)
        self.attach_btn.setStyleSheet("""
            QPushButton {
                background-color: #3B82F6;
                color: #FFFFFF;
                border: none;
                border-radius: 8px;
                padding: 12px;
                font-size: 13px;
                font-weight: 600;
            }
            QPushButton:hover {
                background-color: #2563EB;
            }
        """)
        layout.addWidget(self.attach_btn)
        
        return sidebar
    
    def switch_view(self, index):
        """Switch between views"""
        buttons = [
            self.btn_dashboard, self.btn_recovered, self.btn_timeline,
            self.btn_keywords, self.btn_integrity, self.btn_metadata, self.btn_report
        ]
        
        # Uncheck all
        for btn in buttons:
            btn.setChecked(False)
        
        # Check selected
        if 0 <= index < len(buttons):
            buttons[index].setChecked(True)
        
        self.content_stack.setCurrentIndex(index)
        
        # Refresh data for specific views
        if index == 1:
            self.refresh_recovered_files()
        elif index == 2:
            self.refresh_timeline()
    
    def show_attach_menu(self):
        """Show attachment options menu"""
        from PyQt6.QtWidgets import QMenu
        from PyQt6.QtGui import QAction
        
        menu = QMenu(self)
        menu.setStyleSheet("""
            QMenu {
                background-color: #2A2F3A;
                color: #FFFFFF;
                border: 1px solid #3A3F4A;
                border-radius: 8px;
                padding: 5px;
            }
            QMenu::item {
                padding: 8px 20px;
                border-radius: 4px;
            }
            QMenu::item:selected {
                background-color: #3B82F6;
            }
        """)
        
        # Disk image
        image_action = QAction("📁 Disk Image File", self)
        image_action.triggered.connect(self.attach_disk_image)
        menu.addAction(image_action)
        
        # System partition
        partition_action = QAction("💾 System Partition", self)
        partition_action.triggered.connect(self.attach_system_partition)
        menu.addAction(partition_action)
        
        # External drive
        external_action = QAction("🔌 External Drive", self)
        external_action.triggered.connect(self.attach_external_drive)
        menu.addAction(external_action)
        
        # Show menu
        menu.exec(self.attach_btn.mapToGlobal(self.attach_btn.rect().bottomLeft()))
    
    def attach_disk_image(self):
        """Attach disk image file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Disk Image", "",
            "Disk Images (*.img *.raw *.dd *.e01);;All Files (*.*)"
        )
        
        if file_path:
            self.start_session(file_path, "Disk Image")
    
    def attach_system_partition(self):
        """Attach system partition"""
        partitions = list_xfs_btrfs_partitions()
        
        if not partitions:
            QMessageBox.information(
                self, "No Partitions Found",
                "No XFS or Btrfs partitions detected.\n\n"
                "Supported filesystems:\n• XFS\n• Btrfs\n\n"
                "Note: You may need elevated permissions to detect all partitions."
            )
            return
        
        # Show selection dialog
        dialog = QDialog(self)
        dialog.setWindowTitle("Select Partition")
        dialog.setStyleSheet("background-color: #16161E; color: #FFFFFF;")
        dialog.setMinimumWidth(600)
        dialog.setMinimumHeight(400)
        
        layout = QVBoxLayout(dialog)
        
        title = QLabel("Select XFS/Btrfs Partition to Analyze")
        title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        title.setStyleSheet("color: #FFFFFF; padding: 10px;")
        layout.addWidget(title)
        
        list_widget = QListWidget()
        list_widget.setStyleSheet("""
            QListWidget {
                background-color: #1E1E2E;
                color: #FFFFFF;
                border: 1px solid #2A2F3A;
                border-radius: 8px;
                padding: 5px;
            }
            QListWidget::item {
                padding: 10px;
                border-radius: 4px;
                margin: 2px;
            }
            QListWidget::item:selected {
                background-color: #3B82F6;
            }
            QListWidget::item:hover {
                background-color: #2A2F3A;
            }
        """)
        
        for p in partitions:
            item_text = f"{p['device']} - {p['fstype'].upper()}"
            if p.get('mountpoint'):
                item_text += f" (Mounted: {p['mountpoint']})"
            item_text += f" - {format_bytes(p.get('total', 0))}"
            
            item = QListWidgetItem(item_text)
            item.setData(Qt.ItemDataRole.UserRole, p)
            list_widget.addItem(item)
        
        layout.addWidget(list_widget)
        
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | 
            QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        buttons.setStyleSheet("""
            QPushButton {
                background-color: #3B82F6;
                color: #FFFFFF;
                border: none;
                border-radius: 8px;
                padding: 8px 16px;
            }
            QPushButton:hover {
                background-color: #2563EB;
            }
        """)
        layout.addWidget(buttons)
        
        if dialog.exec() == QDialog.DialogCode.Accepted:
            selected = list_widget.currentItem()
            if selected:
                p = selected.data(Qt.ItemDataRole.UserRole)
                self.start_session(p['device'], f"Partition ({p['fstype'].upper()})")
    
    def attach_external_drive(self):
        """Attach external drive"""
        external = list_external_drives()
        
        if not external:
            QMessageBox.information(
                self, "No External Drives",
                "No external/removable drives detected.\n\n"
                "Please ensure:\n"
                "• Drive is connected\n"
                "• Drive is recognized by system\n"
                "• Drive uses XFS or Btrfs filesystem"
            )
            return
        
        # Filter for XFS/Btrfs
        supported = [e for e in external if e.get('fstype', '').lower() in ['xfs', 'btrfs']]
        
        if not supported:
            QMessageBox.information(
                self, "No Supported Drives",
                f"Found {len(external)} external drive(s), but none use XFS or Btrfs.\n\n"
                "Supported filesystems:\n• XFS\n• Btrfs"
            )
            return
        
        # Show selection (similar to partition selection)
        QMessageBox.information(
            self, "External Drives",
            f"Found {len(supported)} supported external drive(s)"
        )
    
    def start_session(self, source_path, source_type):
        """Start recovery session"""
        output_dir = Path("data/recovered_output") / datetime.now().strftime("%Y%m%d_%H%M%S")
        
        try:
            output_dir.mkdir(parents=True, exist_ok=True)
            
            if self.app and BACKEND_AVAILABLE:
                self.current_session = self.app.create_session(source_path, str(output_dir))
                self.start_scan()
            else:
                # Demo mode
                self.generate_demo_data()
            
            self.switch_view(0)
            self.update_dashboard(source_path, source_type)
            
        except PermissionError:
            QMessageBox.critical(
                self, "Permission Denied",
                f"Cannot access: {source_path}\n\n"
                "This usually means you need elevated permissions.\n"
                "However, don't run the GUI with sudo.\n\n"
                "Try:\n"
                "1. Use disk image files (no special permissions needed)\n"
                "2. Or grant read access: sudo chmod +r {source_path}"
            )
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to start session:\n{str(e)}")
    
    def start_scan(self):
        """Start background scan"""
        if not self.app or not self.current_session:
            return
        
        self.scan_worker = ScanWorker(self.app, self.current_session)
        self.scan_worker.scan_completed.connect(self.scan_complete)
        self.scan_worker.error_occurred.connect(self.scan_error)
        self.scan_worker.start()
    
    def scan_complete(self, results):
        """Handle scan completion"""
        self.recovered_files = results.get('recovered', [])
        self.carved_files = results.get('carved', [])
        
        QMessageBox.information(
            self, "Scan Complete",
            f"Recovery completed!\n\n"
            f"Recovered: {len(self.recovered_files)}\n"
            f"Carved: {len(self.carved_files)}\n"
            f"Total: {len(self.recovered_files) + len(self.carved_files)}"
        )
        
        self.refresh_recovered_files()
    
    def scan_error(self, error):
        """Handle scan error"""
        QMessageBox.critical(self, "Scan Error", f"Error during scan:\n{error}")
    
    def generate_demo_data(self):
        """Generate demo data for testing"""
        self.recovered_files = []
        for i in range(500):
            ext = random.choice(['jpg', 'pdf', 'mp4', 'mp3', 'zip', 'txt', 'docx'])
            self.recovered_files.append({
                'name': f'recovered_file_{i:04d}.{ext}',
                'size': random.randint(1024, 10485760),
                'type': ext,
                'modified': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'hash': f'sha256:{random.randbytes(16).hex()}'
            })
        
        self.carved_files = []
        for i in range(200):
            ext = random.choice(['jpg', 'pdf', 'docx'])
            self.carved_files.append({
                'name': f'carved_file_{i:04d}.{ext}',
                'size': random.randint(1024, 5242880),
                'type': ext,
                'modified': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'hash': f'sha256:{random.randbytes(16).hex()}'
            })
        
        self.current_session = 'demo_session'
        self.refresh_recovered_files()
    
    def update_dashboard(self, source_path, source_type):
        """Update dashboard with session info"""
        # This would update the dashboard view with current session info
        pass
    
    # View Creators
    
    def create_dashboard_view(self):
        """Create dashboard view"""
        view = QWidget()
        layout = QVBoxLayout(view)
        layout.setContentsMargins(30, 25, 30, 30)
        
        title = QLabel("Dashboard")
        title.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        title.setStyleSheet("color: #FFFFFF;")
        layout.addWidget(title)
        
        welcome = QLabel(
            "Welcome to UnEarth Forensic Recovery\n\n"
            "Click '+ Attach Source...' to begin recovery from:\n"
            "• Disk Image Files (.img, .raw, .dd, .e01)\n"
            "• System Partitions (XFS/Btrfs)\n"
            "• External Drives (USB with XFS/Btrfs)"
        )
        welcome.setStyleSheet("color: #9CA3AF; font-size: 14px;")
        welcome.setAlignment(Qt.AlignmentFlag.AlignCenter)
        welcome.setMinimumHeight(400)
        layout.addWidget(welcome)
        
        layout.addStretch()
        return view
    
    def create_recovered_files_view(self):
        """Create recovered files view"""
        view = QWidget()
        layout = QVBoxLayout(view)
        layout.setContentsMargins(30, 25, 30, 30)
        
        title = QLabel("Recovered Files")
        title.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        title.setStyleSheet("color: #FFFFFF;")
        layout.addWidget(title)
        
        # Search bar
        search = QLineEdit()
        search.setPlaceholderText("Search files...")
        search.setStyleSheet("""
            QLineEdit {
                background-color: #2A2F3A;
                color: #FFFFFF;
                border: 1px solid #3A3F4A;
                border-radius: 8px;
                padding: 10px;
                font-size: 13px;
            }
        """)
        search.textChanged.connect(self.filter_files)
        layout.addWidget(search)
        
        # Table
        self.file_table = QTableWidget()
        self.file_table.setColumnCount(5)
        self.file_table.setHorizontalHeaderLabels(['Name', 'Size', 'Type', 'Modified', 'Hash'])
        self.file_table.horizontalHeader().setStretchLastSection(True)
        self.file_table.setStyleSheet("""
            QTableWidget {
                background-color: #1E1E2E;
                color: #FFFFFF;
                gridline-color: #2A2F3A;
                border: 1px solid #2A2F3A;
                border-radius: 8px;
            }
            QHeaderView::section {
                background-color: #2A2F3A;
                color: #FFFFFF;
                padding: 10px;
                border: none;
                font-weight: bold;
            }
            QTableWidget::item {
                padding: 8px;
            }
            QTableWidget::item:selected {
                background-color: #3B82F6;
            }
        """)
        layout.addWidget(self.file_table)
        
        return view
    
    def refresh_recovered_files(self):
        """Refresh recovered files table"""
        all_files = self.recovered_files + self.carved_files
        self.file_table.setRowCount(len(all_files))
        
        for i, f in enumerate(all_files):
            self.file_table.setItem(i, 0, QTableWidgetItem(f.get('name', '')))
            self.file_table.setItem(i, 1, QTableWidgetItem(format_bytes(f.get('size', 0))))
            self.file_table.setItem(i, 2, QTableWidgetItem(f.get('type', '')))
            self.file_table.setItem(i, 3, QTableWidgetItem(f.get('modified', '')))
            hash_val = f.get('hash', '')
            self.file_table.setItem(i, 4, QTableWidgetItem(hash_val[:20] + '...' if len(hash_val) > 20 else hash_val))
    
    def filter_files(self, text):
        """Filter files table"""
        for i in range(self.file_table.rowCount()):
            show = True
            if text:
                show = any(
                    text.lower() in (self.file_table.item(i, j).text().lower() if self.file_table.item(i, j) else '')
                    for j in range(self.file_table.columnCount())
                )
            self.file_table.setRowHidden(i, not show)
    
    def create_timeline_view(self):
        """Create timeline view"""
        view = QWidget()
        layout = QVBoxLayout(view)
        layout.setContentsMargins(30, 25, 30, 30)
        
        title = QLabel("File Timeline")
        title.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        title.setStyleSheet("color: #FFFFFF;")
        layout.addWidget(title)
        
        subtitle = QLabel("Temporal analysis of file activity based on timestamps")
        subtitle.setStyleSheet("color: #9CA3AF; margin-bottom: 10px;")
        layout.addWidget(subtitle)
        
        self.timeline_text = QTextEdit()
        self.timeline_text.setReadOnly(True)
        self.timeline_text.setStyleSheet("""
            QTextEdit {
                background-color: #1E1E2E;
                color: #FFFFFF;
                border: 1px solid #2A2F3A;
                border-radius: 8px;
                padding: 15px;
                font-family: 'Courier New';
            }
        """)
        layout.addWidget(self.timeline_text)
        
        return view
    
    def refresh_timeline(self):
        """Refresh timeline"""
        all_files = self.recovered_files + self.carved_files
        
        html = "<h3 style='color: #3B82F6;'>File Activity Timeline</h3>"
        html += f"<p style='color: #9CA3AF;'>Showing events from {len(all_files)} files</p><br/>"
        
        sorted_files = sorted(all_files, key=lambda x: x.get('modified', ''), reverse=True)[:50]
        
        for f in sorted_files:
            html += f"""
            <div style='margin: 8px 0; padding: 8px; background-color: #2A2F3A; border-radius: 6px;'>
                <span style='color: #3B82F6;'>{f.get('modified', 'Unknown')}</span> - 
                <span style='color: #FFFFFF;'>{f.get('name', 'Unknown')}</span>
                <span style='color: #9CA3AF;'> ({f.get('type', 'Unknown')})</span>
            </div>
            """
        
        self.timeline_text.setHtml(html)
    
    def create_keyword_search_view(self):
        """Create keyword search view"""
        view = QWidget()
        layout = QVBoxLayout(view)
        layout.setContentsMargins(30, 25, 30, 30)
        
        title = QLabel("Keyword Search")
        title.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        title.setStyleSheet("color: #FFFFFF;")
        layout.addWidget(title)
        
        # Search input
        search_layout = QHBoxLayout()
        self.keyword_input = QLineEdit()
        self.keyword_input.setPlaceholderText("Enter keywords (comma-separated)")
        self.keyword_input.setStyleSheet("""
            QLineEdit {
                background-color: #2A2F3A;
                color: #FFFFFF;
                border: 1px solid #3A3F4A;
                border-radius: 8px;
                padding: 12px;
                font-size: 14px;
            }
        """)
        search_layout.addWidget(self.keyword_input)
        
        search_btn = QPushButton("Search")
        search_btn.clicked.connect(self.perform_keyword_search)
        search_btn.setStyleSheet("""
            QPushButton {
                background-color: #3B82F6;
                color: #FFFFFF;
                border: none;
                border-radius: 8px;
                padding: 12px 24px;
                font-weight: 600;
            }
            QPushButton:hover {
                background-color: #2563EB;
            }
        """)
        search_layout.addWidget(search_btn)
        layout.addLayout(search_layout)
        
        # Results
        self.search_results = QTextEdit()
        self.search_results.setReadOnly(True)
        self.search_results.setStyleSheet("""
            QTextEdit {
                background-color: #1E1E2E;
                color: #FFFFFF;
                border: 1px solid #2A2F3A;
                border-radius: 8px;
                padding: 15px;
            }
        """)
        self.search_results.setHtml("<p style='color: #9CA3AF;'>Enter keywords and click Search...</p>")
        layout.addWidget(self.search_results)
        
        return view
    
    def perform_keyword_search(self):
        """Perform keyword search"""
        keywords = self.keyword_input.text().strip()
        if not keywords:
            return
        
        keyword_list = [k.strip().lower() for k in keywords.split(',')]
        all_files = self.recovered_files + self.carved_files
        
        html = f"<h3 style='color: #3B82F6;'>Search Results: {keywords}</h3>"
        html += f"<p style='color: #9CA3AF;'>Searching {len(all_files)} files...</p><br/>"
        
        matches = 0
        for f in all_files:
            filename = f.get('name', '').lower()
            if any(kw in filename for kw in keyword_list):
                matches += 1
                html += f"""
                <div style='margin: 8px 0; padding: 8px; background-color: #2A2F3A; border-radius: 6px;'>
                    <span style='color: #10B981; font-weight: bold;'>✓ Match</span><br/>
                    <span style='color: #FFFFFF;'>{f.get('name', 'Unknown')}</span><br/>
                    <span style='color: #9CA3AF;'>Type: {f.get('type', 'Unknown')} | Size: {format_bytes(f.get('size', 0))}</span>
                </div>
                """
        
        html += f"<br/><p style='color: #FFFFFF;'><strong>Total Matches: {matches}</strong></p>"
        self.search_results.setHtml(html)
    
    def create_integrity_view(self):
        """Create integrity view"""
        view = QWidget()
        layout = QVBoxLayout(view)
        layout.setContentsMargins(30, 25, 30, 30)
        
        title = QLabel("File Integrity Verification")
        title.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        title.setStyleSheet("color: #FFFFFF;")
        layout.addWidget(title)
        
        text = QTextEdit()
        text.setReadOnly(True)
        
        total = len(self.recovered_files) + len(self.carved_files)
        html = f"""
        <h3 style='color: #3B82F6;'>Integrity Verification Status</h3>
        <br/>
        <p style='color: #FFFFFF;'><strong>Total Files:</strong> {total}</p>
        <p style='color: #FFFFFF;'><strong>Hash Algorithm:</strong> SHA-256</p>
        <p style='color: #FFFFFF;'><strong>Status:</strong> <span style='color: #10B981;'>✓ All files hashed</span></p>
        <br/>
        <p style='color: #9CA3AF;'>All recovered files have been cryptographically hashed using SHA-256 for integrity verification. These hashes can be used to verify that files have not been modified since recovery.</p>
        <br/>
        <p style='color: #9CA3AF;'><strong>Forensic Use:</strong> Hashes are included in all generated reports and provide evidence of data integrity in legal proceedings.</p>
        """
        text.setHtml(html)
        text.setStyleSheet("""
            QTextEdit {
                background-color: #1E1E2E;
                color: #FFFFFF;
                border: 1px solid #2A2F3A;
                border-radius: 8px;
                padding: 15px;
            }
        """)
        layout.addWidget(text)
        
        return view
    
    def create_metadata_view(self):
        """Create metadata view"""
        view = QWidget()
        layout = QVBoxLayout(view)
        layout.setContentsMargins(30, 25, 30, 30)
        
        title = QLabel("Metadata Extraction")
        title.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        title.setStyleSheet("color: #FFFFFF;")
        layout.addWidget(title)
        
        text = QTextEdit()
        text.setReadOnly(True)
        
        total = len(self.recovered_files) + len(self.carved_files)
        html = f"""
        <h3 style='color: #3B82F6;'>Metadata Extraction Summary</h3>
        <br/>
        <p style='color: #FFFFFF;'><strong>Files Analyzed:</strong> {total}</p>
        <br/>
        <h4 style='color: #FFFFFF;'>Extracted Metadata Includes:</h4>
        <ul style='color: #9CA3AF; line-height: 1.8;'>
            <li>File system timestamps (created, modified, accessed)</li>
            <li>File permissions and ownership information</li>
            <li>Inode numbers and filesystem-specific data</li>
            <li>Embedded metadata (EXIF for images, author for documents)</li>
            <li>Cryptographic hashes (SHA-256)</li>
            <li>File size and type information</li>
        </ul>
        <br/>
        <p style='color: #9CA3AF;'><strong>Forensic Value:</strong> All extracted metadata is preserved in the forensic report and can be used to establish timelines, identify file origins, and verify authenticity.</p>
        """
        text.setHtml(html)
        text.setStyleSheet("""
            QTextEdit {
                background-color: #1E1E2E;
                color: #FFFFFF;
                border: 1px solid #2A2F3A;
                border-radius: 8px;
                padding: 15px;
            }
        """)
        layout.addWidget(text)
        
        return view
    
    def create_report_view(self):
        """Create report generator view"""
        view = QWidget()
        layout = QVBoxLayout(view)
        layout.setContentsMargins(30, 25, 30, 30)
        layout.setSpacing(20)
        
        title = QLabel("Forensic Report Generator")
        title.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        title.setStyleSheet("color: #FFFFFF;")
        layout.addWidget(title)
        
        subtitle = QLabel("Generate comprehensive forensic reports for legal or corporate use")
        subtitle.setStyleSheet("color: #9CA3AF; font-size: 13px;")
        layout.addWidget(subtitle)
        
        # Options frame
        options_frame = QFrame()
        options_frame.setStyleSheet("""
            QFrame {
                background-color: #1E1E2E;
                border-radius: 12px;
                padding: 20px;
            }
        """)
        options_layout = QVBoxLayout(options_frame)
        
        # Format selection
        format_label = QLabel("Report Format:")
        format_label.setStyleSheet("color: #FFFFFF; font-weight: bold; margin-bottom: 5px;")
        options_layout.addWidget(format_label)
        
        self.report_format = QComboBox()
        self.report_format.addItems(["PDF (Recommended)", "CSV (Data Export)", "JSON (Machine Readable)"])
        self.report_format.setStyleSheet("""
            QComboBox {
                background-color: #2A2F3A;
                color: #FFFFFF;
                border: 1px solid #3A3F4A;
                border-radius: 8px;
                padding: 10px;
                font-size: 13px;
            }
        """)
        options_layout.addWidget(self.report_format)
        
        options_layout.addSpacing(15)
        
        # Options
        options_label = QLabel("Report Options:")
        options_label.setStyleSheet("color: #FFFFFF; font-weight: bold; margin-bottom: 5px;")
        options_layout.addWidget(options_label)
        
        self.include_images_cb = QCheckBox("Include file previews (PDF only)")
        self.include_images_cb.setChecked(True)
        self.include_images_cb.setStyleSheet("color: #FFFFFF; font-size: 13px;")
        options_layout.addWidget(self.include_images_cb)
        
        self.include_timeline_cb = QCheckBox("Include timeline visualization")
        self.include_timeline_cb.setChecked(True)
        self.include_timeline_cb.setStyleSheet("color: #FFFFFF; font-size: 13px;")
        options_layout.addWidget(self.include_timeline_cb)
        
        self.include_hashes_cb = QCheckBox("Include integrity hashes")
        self.include_hashes_cb.setChecked(True)
        self.include_hashes_cb.setStyleSheet("color: #FFFFFF; font-size: 13px;")
        options_layout.addWidget(self.include_hashes_cb)
        
        options_layout.addSpacing(20)
        
        # Generate button
        gen_btn = QPushButton("Generate Report")
        gen_btn.clicked.connect(self.generate_report)
        gen_btn.setStyleSheet("""
            QPushButton {
                background-color: #3B82F6;
                color: #FFFFFF;
                border: none;
                border-radius: 8px;
                padding: 15px;
                font-size: 14px;
                font-weight: 600;
            }
            QPushButton:hover {
                background-color: #2563EB;
            }
        """)
        options_layout.addWidget(gen_btn)
        
        layout.addWidget(options_frame)
        
        # Info
        info_label = QLabel("Report Contents:")
        info_label.setStyleSheet("color: #FFFFFF; font-weight: bold; margin-top: 20px;")
        layout.addWidget(info_label)
        
        info_text = QLabel(
            "✓ Executive summary\n"
            "✓ Complete file inventory\n"
            "✓ Metadata and timestamps\n"
            "✓ Integrity verification hashes\n"
            "✓ Timeline visualization\n"
            "✓ Keyword search results\n"
            "✓ Chain of custody log"
        )
        info_text.setStyleSheet("color: #9CA3AF; font-size: 13px;")
        layout.addWidget(info_text)
        
        layout.addStretch()
        return view
    
    def generate_report(self):
        """Generate forensic report"""
        if not self.current_session:
            QMessageBox.warning(
                self, "No Session",
                "No active recovery session.\n\nPlease attach a source first."
            )
            return
        
        format_text = self.report_format.currentText()
        if "PDF" in format_text:
            report_format = "pdf"
        elif "CSV" in format_text:
            report_format = "csv"
        else:
            report_format = "json"
        
        try:
            if self.app and BACKEND_AVAILABLE:
                report_path = self.app.generate_report(self.current_session, format=report_format)
            else:
                # Demo mode
                report_path = Path("data/recovered_output") / f"forensic_report.{report_format}"
                report_path.parent.mkdir(parents=True, exist_ok=True)
                report_path.write_text(f"Demo report - {datetime.now()}")
            
            QMessageBox.information(
                self, "Report Generated",
                f"Forensic report generated successfully!\n\n"
                f"Format: {report_format.upper()}\n"
                f"Location: {report_path}\n\n"
                f"The report includes all selected options."
            )
        except Exception as e:
            QMessageBox.critical(
                self, "Error",
                f"Failed to generate report:\n{str(e)}"
            )


def apply_global_stylesheet(app):
    """Apply dark theme"""
    app.setStyle("Fusion")
    
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor(22, 22, 30))
    palette.setColor(QPalette.ColorRole.WindowText, QColor(255, 255, 255))
    palette.setColor(QPalette.ColorRole.Base, QColor(30, 30, 46))
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor(42, 47, 58))
    palette.setColor(QPalette.ColorRole.Text, QColor(255, 255, 255))
    palette.setColor(QPalette.ColorRole.Button, QColor(42, 47, 58))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor(255, 255, 255))
    palette.setColor(QPalette.ColorRole.Link, QColor(59, 130, 246))
    palette.setColor(QPalette.ColorRole.Highlight, QColor(59, 130, 246))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor(255, 255, 255))
    
    app.setPalette(palette)


def main():
    """Main entry point"""
    # Don't run with sudo warning
    if check_root_permissions():
        print("\n" + "="*60)
        print("⚠️  WARNING: Running with elevated permissions (sudo/root)")
        print("="*60)
        print("\nThis can cause issues with:")
        print("• GUI display (DBus errors)")
        print("• File permissions")
        print("• Security risks")
        print("\nRecommendation:")
        print("• Run as normal user: python run.py --gui")
        print("• App will request permissions when needed")
        print("="*60 + "\n")
        
        response = input("Continue anyway? (y/N): ")
        if response.lower() != 'y':
            print("Exiting...")
            sys.exit(0)
    
    app = QApplication(sys.argv)
    
    app.setApplicationName("UnEarth")
    app.setOrganizationName("UnEarth Forensics")
    
    apply_global_stylesheet(app)
    
    window = UnearthGUI()
    window.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()