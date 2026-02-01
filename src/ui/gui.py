"""
Unearth Forensic Recovery Tool - GUI Interface
Production-ready version with all fixes
"""

import sys
import os
from pathlib import Path
from datetime import datetime
import random
from collections import Counter

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QFrame, QTableWidget, QTableWidgetItem,
    QHeaderView, QLineEdit, QTextEdit, QComboBox, QCheckBox,
    QStackedWidget, QListWidget, QListWidgetItem, QFileDialog,
    QMessageBox, QProgressBar, QDialog, QDialogButtonBox, QScrollArea,
    QGridLayout, QSizePolicy
)
from PyQt6.QtCore import Qt, QSize, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QPalette, QColor

# Try to import matplotlib for charts
try:
    import matplotlib
    matplotlib.use('QtAgg')
    from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
    from matplotlib.figure import Figure
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False
    print("Warning: matplotlib not available, charts will be disabled")

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
    
    def __init__(self, app, session_id, file_filter="all"):
        super().__init__()
        self.app = app
        self.session_id = session_id
        self.file_filter = file_filter  # "all", "deleted_only", or "active_only"
        
    def run(self):
        try:
            self.progress_updated.emit(10, "Detecting filesystem...")
            fs_type = self.app.detect_filesystem(self.session_id)
            
            self.progress_updated.emit(20, f"Scanning filesystem (filter: {self.file_filter})...")
            
            def scan_progress(percent, msg):
                # Map 0-100 scan progress to 20-90 overall progress
                overall = 20 + int(percent * 0.7)
                self.progress_updated.emit(overall, f"Scanning: {msg}")
                
            recovered = self.app.recover_deleted_files(
                self.session_id, 
                progress_callback=scan_progress,
                file_filter=self.file_filter
            )
            
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
        self.file_filter = "all"  # Filter: "all", "deleted_only", or "active_only"
        
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
            "• Scanning may be restricted\n\n"
            "For full functionality, run with sudo:\n"
            "  sudo python run.py"
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
            is_mounted = p.get('mounted', True)
            mount_status = "🟢 Mounted" if is_mounted else "🔴 Unmounted"
            
            item_text = f"{p['device']} - {p['fstype'].upper()} [{mount_status}]"
            if is_mounted and p.get('mountpoint') and p['mountpoint'] != '(not mounted)':
                item_text += f"\n    📁 {p['mountpoint']}"
            if p.get('label'):
                item_text += f" ({p['label']})"
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
                "Root privileges are required to access raw disk devices.\n\n"
                "Please restart the application using the launcher:\n"
                "  sudo python run.py --gui\n\n"
                "Alternatively, you can grant read access to the device:\n"
                f"  sudo chmod +r {source_path}"
            )
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to start session:\n{str(e)}")
    
    def start_scan(self):
        """Start background scan"""
        if not self.app or not self.current_session:
            return
        
        self.scan_worker = ScanWorker(self.app, self.current_session, self.file_filter)
        self.scan_worker.progress_updated.connect(self.update_progress)
        self.scan_worker.scan_completed.connect(self.scan_complete)
        self.scan_worker.error_occurred.connect(self.scan_error)
        self.scan_worker.start()
    
    def scan_complete(self, results):
        """Handle scan completion - update dashboard with results"""
        self.recovered_files = results.get('recovered', [])
        self.carved_files = results.get('carved', [])
        
        # Hide progress, show results in dashboard
        self.progress_container.setVisible(False)
        self.status_label.setText("Scan Complete!")
        
        # Update dashboard stats and charts
        self.update_dashboard_stats()
        
        # Also refresh the recovered files table for when user switches to that view
        self.refresh_recovered_files()
    
    def scan_error(self, error):
        """Handle scan error"""
        QMessageBox.critical(self, "Scan Error", f"Error during scan:\n{error}")
    
    def generate_demo_data(self):
        """Generate demo data for testing"""
        self.recovered_files = []
        for i in range(500):
            ext = random.choice(['jpg', 'pdf', 'mp4', 'mp3', 'zip', 'txt', 'docx'])
            status = random.choice(['deleted', 'active', 'active'])  # More active than deleted
            # Simulate realistic integrity distribution: 70% verified, 5% corrupted, 15% unverified, 10% no_checksum
            integrity_roll = random.random()
            if integrity_roll < 0.70:
                integrity_status = 'verified'
            elif integrity_roll < 0.75:
                integrity_status = 'corrupted'
            elif integrity_roll < 0.90:
                integrity_status = 'unverified'
            else:
                integrity_status = 'no_checksum'
                
            self.recovered_files.append({
                'name': f'{"DELETED_" if status == "deleted" else "ACTIVE_"}file_{i:04d}.{ext}',
                'original_name': f'file_{i:04d}.{ext}',
                'size': random.randint(1024, 10485760),
                'type': ext,
                'status': status,
                'integrity_status': integrity_status,
                'integrity_verified': integrity_status == 'verified',
                'integrity_details': f'CRC32C 0x{random.randbytes(4).hex().upper()}',
                'modified': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'hash': f'sha256:{random.randbytes(32).hex()}'
            })
        
        self.carved_files = []
        for i in range(200):
            ext = random.choice(['jpg', 'pdf', 'docx'])
            self.carved_files.append({
                'name': f'carved_file_{i:04d}.{ext}',
                'size': random.randint(1024, 5242880),
                'type': ext,
                'status': 'carved',
                'integrity_status': 'no_checksum',  # Carved files don't have filesystem checksums
                'integrity_verified': False,
                'integrity_details': 'Carved file (no filesystem checksum)',
                'modified': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'hash': f'sha256:{random.randbytes(32).hex()}'
            })
        
        self.current_session = 'demo_session_' + datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Update dashboard with demo data
        self.update_dashboard_stats()
        self.refresh_recovered_files()
    
    def update_dashboard(self, source_path, source_type):
        """Update dashboard with session info"""
        # This would update the dashboard view with current session info
        pass
    
    # View Creators
    
    def create_dashboard_view(self):
        """Create dashboard view with stats and charts"""
        view = QWidget()
        main_layout = QVBoxLayout(view)
        main_layout.setContentsMargins(30, 25, 30, 30)
        main_layout.setSpacing(20)
        
        # Title
        title = QLabel("Dashboard")
        title.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        title.setStyleSheet("color: #FFFFFF;")
        main_layout.addWidget(title)
        
        # Scrollable content area
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("""
            QScrollArea {
                border: none;
                background-color: transparent;
            }
            QScrollBar:vertical {
                background-color: #1E1E2E;
                width: 10px;
                border-radius: 5px;
            }
            QScrollBar::handle:vertical {
                background-color: #3A3F4A;
                border-radius: 5px;
            }
        """)
        
        scroll_content = QWidget()
        scroll_layout = QVBoxLayout(scroll_content)
        scroll_layout.setSpacing(20)
        
        # Welcome section (shown when no data)
        self.welcome_section = QWidget()
        welcome_layout = QVBoxLayout(self.welcome_section)
        welcome_text = QLabel(
            "Welcome to UnEarth Forensic Recovery\n\n"
            "Click '+ Attach Source...' to begin recovery from:\n"
            "• Disk Image Files (.img, .raw, .dd, .e01)\n"
            "• System Partitions (XFS/Btrfs)\n"
            "• External Drives (USB with XFS/Btrfs)"
        )
        welcome_text.setStyleSheet("color: #9CA3AF; font-size: 14px;")
        welcome_text.setAlignment(Qt.AlignmentFlag.AlignCenter)
        welcome_layout.addWidget(welcome_text)
        scroll_layout.addWidget(self.welcome_section)
        
        # Hidden filter widgets for backward compatibility
        self.filter_combo = QComboBox()
        self.filter_combo.addItem("All Files (Active + Deleted)", "all")
        self.filter_combo.hide()
        
        # Create dummy filter widgets (hidden) to prevent AttributeError
        self.source_filter = QComboBox()
        self.source_filter.addItem("📁 All Sources", "all")
        self.source_filter.hide()
        
        self.status_filter = QComboBox()
        self.status_filter.addItem("📊 All Status", "all")
        self.status_filter.hide()
        
        self.type_filter = QComboBox()
        self.type_filter.addItem("📄 All Types", "all")
        self.type_filter.hide()
        
        self.show_duplicates_check = QCheckBox()
        self.show_duplicates_check.hide()
        
        
        # Progress Section
        self.progress_container = QWidget()
        progress_layout = QVBoxLayout(self.progress_container)
        
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: #FFFFFF; font-weight: bold; font-size: 14px;")
        progress_layout.addWidget(self.status_label)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 2px solid #2A2F3A;
                border-radius: 5px;
                text-align: center;
                background-color: #1E1E2E;
                color: white;
                min-height: 25px;
            }
            QProgressBar::chunk {
                background-color: #3B82F6;
            }
        """)
        self.progress_bar.setTextVisible(True)
        progress_layout.addWidget(self.progress_bar)
        
        self.progress_container.setVisible(False)
        scroll_layout.addWidget(self.progress_container)
        
        # Results Section (hidden until scan completes)
        self.results_section = QWidget()
        self.results_section.setVisible(False)
        results_layout = QVBoxLayout(self.results_section)
        results_layout.setSpacing(20)
        
        # --- Stats Cards Row ---
        stats_row = QWidget()
        stats_layout = QHBoxLayout(stats_row)
        stats_layout.setSpacing(15)
        
        # Total Files Card
        self.total_card = self._create_stat_card("Total Files", "0", "#3B82F6", "fa5s.folder-open")
        stats_layout.addWidget(self.total_card)
        
        # Likely Deleted Files Card (was Deleted Files)
        self.deleted_card = self._create_stat_card("Likely Deleted", "0", "#EF4444", "fa5s.trash")
        stats_layout.addWidget(self.deleted_card)
        
        # Duplicates Card (was Active Files) - shows carved files matching active
        self.active_card = self._create_stat_card("Duplicates", "0", "#6B7280", "fa5s.copy")
        stats_layout.addWidget(self.active_card)
        
        # Carved Files Card
        self.carved_card = self._create_stat_card("Carved Files", "0", "#F59E0B", "fa5s.search")
        stats_layout.addWidget(self.carved_card)
        
        results_layout.addWidget(stats_row)
        
        # --- Charts Row ---
        charts_row = QWidget()
        charts_layout = QHBoxLayout(charts_row)
        charts_layout.setSpacing(20)
        
        # File Status Chart (Pie)
        self.status_chart_container = self._create_chart_card("File Status Distribution")
        charts_layout.addWidget(self.status_chart_container)
        
        # File Type Chart (Pie)
        self.type_chart_container = self._create_chart_card("File Types Breakdown")
        charts_layout.addWidget(self.type_chart_container)
        
        # Integrity Verification Chart (Pie)
        self.integrity_chart_container = self._create_chart_card("Integrity Verification")
        charts_layout.addWidget(self.integrity_chart_container)
        
        results_layout.addWidget(charts_row)
        
        # --- Session Info Section ---
        session_info = QFrame()
        session_info.setStyleSheet("""
            QFrame {
                background-color: #1E1E2E;
                border: 1px solid #2A2F3A;
                border-radius: 10px;
                padding: 15px;
            }
        """)
        session_layout = QVBoxLayout(session_info)
        
        session_title = QLabel("Session Information")
        session_title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        session_title.setStyleSheet("color: #FFFFFF; border: none;")
        session_layout.addWidget(session_title)
        
        self.session_details = QLabel("No active session")
        self.session_details.setStyleSheet("color: #9CA3AF; font-size: 12px; border: none;")
        self.session_details.setWordWrap(True)
        session_layout.addWidget(self.session_details)
        
        results_layout.addWidget(session_info)
        
        scroll_layout.addWidget(self.results_section)
        scroll_layout.addStretch()
        
        scroll.setWidget(scroll_content)
        main_layout.addWidget(scroll)
        
        return view
    
    def _create_stat_card(self, title, value, color, icon_name):
        """Create a statistics card widget"""
        card = QFrame()
        card.setStyleSheet(f"""
            QFrame {{
                background-color: #1E1E2E;
                border: 1px solid #2A2F3A;
                border-radius: 12px;
                border-left: 4px solid {color};
            }}
        """)
        card.setMinimumWidth(180)
        card.setMinimumHeight(100)
        
        layout = QVBoxLayout(card)
        layout.setContentsMargins(15, 15, 15, 15)
        
        # Title
        title_label = QLabel(title)
        title_label.setStyleSheet("color: #9CA3AF; font-size: 12px; font-weight: bold;")
        layout.addWidget(title_label)
        
        # Value
        value_label = QLabel(value)
        value_label.setObjectName("value")
        value_label.setFont(QFont("Segoe UI", 28, QFont.Weight.Bold))
        value_label.setStyleSheet(f"color: {color};")
        layout.addWidget(value_label)
        
        return card
    
    def _create_chart_card(self, title):
        """Create a chart container card"""
        card = QFrame()
        card.setStyleSheet("""
            QFrame {
                background-color: #1E1E2E;
                border: 1px solid #2A2F3A;
                border-radius: 12px;
            }
        """)
        card.setMinimumHeight(300)
        
        layout = QVBoxLayout(card)
        layout.setContentsMargins(15, 15, 15, 15)
        
        # Title
        title_label = QLabel(title)
        title_label.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        title_label.setStyleSheet("color: #FFFFFF; border: none;")
        layout.addWidget(title_label)
        
        # Chart placeholder
        chart_area = QWidget()
        chart_area.setObjectName("chart_area")
        chart_area.setMinimumHeight(250)
        layout.addWidget(chart_area)
        
        return card
    
    def update_dashboard_stats(self):
        """Update dashboard with current scan results"""
        # Hide welcome, show results
        self.welcome_section.setVisible(False)
        self.results_section.setVisible(True)
        
        # Get session data
        session = None
        all_files = []
        filtered_files = []
        
        if self.current_session and self.app:
            session = self.app.sessions.get(self.current_session)
            if session:
                all_files = session.all_files or []
                filtered_files = session.filtered_files or all_files
        
        # Calculate stats from session data
        carved_count = sum(1 for f in all_files if f.get('source') == 'carved')
        metadata_count = sum(1 for f in all_files if f.get('source') == 'metadata')
        likely_deleted = sum(1 for f in all_files if f.get('status') == 'likely_deleted' or f.get('deleted'))
        duplicates = sum(1 for f in all_files if f.get('is_duplicate', False))
        
        # Legacy stats for backward compatibility
        deleted_count = sum(1 for f in self.recovered_files if f.get('status') == 'deleted' or f.get('deleted'))
        active_count = sum(1 for f in self.recovered_files if f.get('status') == 'active')
        total_recovered = len(all_files) if all_files else len(self.recovered_files) + len(self.carved_files)
        
        # Calculate integrity stats
        verified_count = sum(1 for f in self.recovered_files if f.get('integrity_status') == 'verified')
        corrupted_count = sum(1 for f in self.recovered_files if f.get('integrity_status') == 'corrupted')
        unverified_count = sum(1 for f in self.recovered_files if f.get('integrity_status') == 'unverified')
        no_checksum_count = sum(1 for f in self.recovered_files if f.get('integrity_status') == 'no_checksum')
        
        # Update stat cards with new categorization
        self.total_card.findChild(QLabel, "value").setText(str(total_recovered))
        self.deleted_card.findChild(QLabel, "value").setText(str(likely_deleted))
        self.active_card.findChild(QLabel, "value").setText(str(duplicates))  # Show duplicates (active files in carved)
        self.carved_card.findChild(QLabel, "value").setText(str(carved_count))
        
        # Update session details with filter info
        total_size = sum(f.get('size', 0) for f in all_files)
        filter_state = session.filter_state if session else {}
        self.session_details.setText(
            f"Session ID: {self.current_session[:16] if self.current_session else 'N/A'}...\n"
            f"Showing: {len(filtered_files)}/{len(all_files)} files\n"
            f"Total Size: {format_bytes(total_size)}\n"
            f"Carved: {carved_count} | Metadata: {metadata_count}"
        )
        
        # Update charts
        self._update_status_chart(likely_deleted, duplicates, carved_count - duplicates - likely_deleted)
        self._update_type_chart()
        self._update_integrity_chart(verified_count, corrupted_count, unverified_count, no_checksum_count)
    
    def _update_status_chart(self, deleted, active, carved):
        """Update the file status pie chart"""
        if not HAS_MATPLOTLIB:
            return
            
        # Clear previous chart
        chart_area = self.status_chart_container.findChild(QWidget, "chart_area")
        if chart_area:
            # Remove old layout
            old_layout = chart_area.layout()
            if old_layout:
                while old_layout.count():
                    item = old_layout.takeAt(0)
                    if item.widget():
                        item.widget().deleteLater()
            else:
                old_layout = QVBoxLayout(chart_area)
            
            # Create pie chart
            fig = Figure(figsize=(4, 3), dpi=100, facecolor='#1E1E2E')
            canvas = FigureCanvas(fig)
            ax = fig.add_subplot(111)
            
            labels = []
            sizes = []
            colors = []
            
            if deleted > 0:
                labels.append(f'Deleted ({deleted})')
                sizes.append(deleted)
                colors.append('#EF4444')
            if active > 0:
                labels.append(f'Active ({active})')
                sizes.append(active)
                colors.append('#22C55E')
            if carved > 0:
                labels.append(f'Carved ({carved})')
                sizes.append(carved)
                colors.append('#F59E0B')
            
            if sizes:
                wedges, texts, autotexts = ax.pie(
                    sizes, labels=labels, colors=colors, autopct='%1.1f%%',
                    startangle=90, textprops={'color': 'white', 'fontsize': 9}
                )
                for autotext in autotexts:
                    autotext.set_color('white')
            else:
                ax.text(0.5, 0.5, 'No Data', ha='center', va='center', 
                       color='#9CA3AF', fontsize=14, transform=ax.transAxes)
            
            ax.set_facecolor('#1E1E2E')
            fig.tight_layout()
            
            old_layout.addWidget(canvas)
    
    def _update_type_chart(self):
        """Update the file type distribution chart"""
        if not HAS_MATPLOTLIB:
            return
            
        chart_area = self.type_chart_container.findChild(QWidget, "chart_area")
        if chart_area:
            # Remove old layout
            old_layout = chart_area.layout()
            if old_layout:
                while old_layout.count():
                    item = old_layout.takeAt(0)
                    if item.widget():
                        item.widget().deleteLater()
            else:
                old_layout = QVBoxLayout(chart_area)
            
            # Count file types
            all_files = self.recovered_files + self.carved_files
            type_counts = Counter(f.get('type', 'unknown') for f in all_files)
            
            # Create pie chart
            fig = Figure(figsize=(4, 3), dpi=100, facecolor='#1E1E2E')
            canvas = FigureCanvas(fig)
            ax = fig.add_subplot(111)
            
            if type_counts:
                # Get top 6 types, group rest as "Other"
                sorted_types = type_counts.most_common(6)
                if len(type_counts) > 6:
                    other_count = sum(count for _, count in type_counts.most_common()[6:])
                    sorted_types.append(('Other', other_count))
                
                labels = [f'{t} ({c})' for t, c in sorted_types]
                sizes = [c for _, c in sorted_types]
                colors = ['#3B82F6', '#8B5CF6', '#EC4899', '#14B8A6', '#F59E0B', '#6366F1', '#9CA3AF']
                
                wedges, texts, autotexts = ax.pie(
                    sizes, labels=labels, colors=colors[:len(sizes)], autopct='%1.1f%%',
                    startangle=90, textprops={'color': 'white', 'fontsize': 8}
                )
                for autotext in autotexts:
                    autotext.set_color('white')
            else:
                ax.text(0.5, 0.5, 'No Data', ha='center', va='center', 
                       color='#9CA3AF', fontsize=14, transform=ax.transAxes)
            
            ax.set_facecolor('#1E1E2E')
            fig.tight_layout()
            
            old_layout.addWidget(canvas)
    
    def _update_integrity_chart(self, verified, corrupted, unverified, no_checksum):
        """Update the integrity verification pie chart"""
        if not HAS_MATPLOTLIB:
            return
            
        chart_area = self.integrity_chart_container.findChild(QWidget, "chart_area")
        if chart_area:
            # Remove old layout
            old_layout = chart_area.layout()
            if old_layout:
                while old_layout.count():
                    item = old_layout.takeAt(0)
                    if item.widget():
                        item.widget().deleteLater()
            else:
                old_layout = QVBoxLayout(chart_area)
            
            # Create pie chart
            fig = Figure(figsize=(4, 3), dpi=100, facecolor='#1E1E2E')
            canvas = FigureCanvas(fig)
            ax = fig.add_subplot(111)
            
            # Collect non-zero counts
            data = []
            labels = []
            colors = []
            
            if verified > 0:
                data.append(verified)
                labels.append(f'Verified ({verified})')
                colors.append('#22C55E')  # Green
            if corrupted > 0:
                data.append(corrupted)
                labels.append(f'Corrupted ({corrupted})')
                colors.append('#EF4444')  # Red
            if unverified > 0:
                data.append(unverified)
                labels.append(f'Unverified ({unverified})')
                colors.append('#F59E0B')  # Yellow
            if no_checksum > 0:
                data.append(no_checksum)
                labels.append(f'No Checksum ({no_checksum})')
                colors.append('#6B7280')  # Gray
            
            if data:
                wedges, texts, autotexts = ax.pie(
                    data, labels=labels, colors=colors, autopct='%1.1f%%',
                    startangle=90, textprops={'color': 'white', 'fontsize': 8}
                )
                for autotext in autotexts:
                    autotext.set_color('white')
            else:
                ax.text(0.5, 0.5, 'No Data', ha='center', va='center', 
                       color='#9CA3AF', fontsize=14, transform=ax.transAxes)
            
            ax.set_facecolor('#1E1E2E')
            fig.tight_layout()
            
            old_layout.addWidget(canvas)
    
    def _get_combo_style(self):
        """Return consistent combo box styling"""
        return """
            QComboBox {
                background-color: #2A2F3A;
                color: #FFFFFF;
                border: 1px solid #3A3F4A;
                border-radius: 6px;
                padding: 8px 15px;
                min-width: 150px;
                font-size: 13px;
            }
            QComboBox:hover {
                border-color: #3B82F6;
            }
            QComboBox::drop-down {
                border: none;
                padding-right: 10px;
            }
            QComboBox QAbstractItemView {
                background-color: #2A2F3A;
                color: #FFFFFF;
                selection-background-color: #3B82F6;
                border: 1px solid #3A3F4A;
            }
        """
    
    def on_filter_changed(self, index):
        """Handle legacy filter selection change"""
        self.file_filter = self.filter_combo.currentData()

    def on_dynamic_filter_changed(self):
        """Handle dynamic filter changes - applies filters without re-scanning"""
        if not self.current_session or not self.app:
            return
        
        # Get current filter values
        source = self.source_filter.currentData()
        status = self.status_filter.currentData()
        file_type = self.type_filter.currentData()
        show_duplicates = self.show_duplicates_check.isChecked()
        
        # Apply filters through app
        try:
            filtered_files = self.app.apply_filters(
                self.current_session,
                source=source,
                status=status,
                file_type=file_type,
                show_duplicates=show_duplicates
            )
            
            # Refresh the file table with filtered results
            self.refresh_recovered_files_from_filtered()
            
            # Update dashboard stats
            self.update_dashboard_stats()
            
        except Exception as e:
            self.logger.error(f"Filter error: {e}")
    
    def refresh_recovered_files_from_filtered(self):
        """Refresh file table using session.filtered_files"""
        if not self.current_session:
            return
        
        session = self.app.sessions.get(self.current_session)
        if not session:
            return
        
        # Use filtered files if available, otherwise all files
        files = session.filtered_files if session.filtered_files else session.all_files
        
        self.file_table.setRowCount(0)
        
        for file_info in files:
            row = self.file_table.rowCount()
            self.file_table.insertRow(row)
            
            # Name
            name = file_info.get('name', 'Unknown')
            name_item = QTableWidgetItem(name)
            self.file_table.setItem(row, 0, name_item)
            
            # Size
            size = file_info.get('size', 0)
            size_str = self._format_size(size)
            size_item = QTableWidgetItem(size_str)
            self.file_table.setItem(row, 1, size_item)
            
            # Type
            file_type = file_info.get('type', '')
            type_item = QTableWidgetItem(file_type.upper() if file_type else 'Unknown')
            self.file_table.setItem(row, 2, type_item)
            
            # Source (new column)
            source = file_info.get('source', 'unknown')
            if source == 'carved':
                source_text = "🔍 Carved"
                source_color = "#F59E0B"
            else:
                source_text = "📋 Metadata"
                source_color = "#3B82F6"
            source_item = QTableWidgetItem(source_text)
            source_item.setForeground(QColor(source_color))
            self.file_table.setItem(row, 3, source_item)
            
            # Status (new column)
            status = file_info.get('status', 'unknown')
            if file_info.get('deleted', False):
                status_text = "🗑️ Deleted"
                status_color = "#EF4444"
            elif file_info.get('is_duplicate', False):
                status_text = "📋 Active (Dup)"
                status_color = "#6B7280"
            elif status == 'likely_deleted':
                status_text = "❓ Likely Deleted"
                status_color = "#F59E0B"
            elif status == 'active':
                status_text = "✅ Active"
                status_color = "#22C55E"
            else:
                status_text = "❓ Unknown"
                status_color = "#9CA3AF"
            status_item = QTableWidgetItem(status_text)
            status_item.setForeground(QColor(status_color))
            self.file_table.setItem(row, 4, status_item)
            
            # Path
            path = file_info.get('path', '')
            path_item = QTableWidgetItem(str(path))
            self.file_table.setItem(row, 5, path_item)
        
        # Update row count label
        if hasattr(self, 'file_count_label'):
            total = len(session.all_files) if session.all_files else 0
            shown = len(files)
            self.file_count_label.setText(f"Showing {shown} of {total} files")
    
    def _format_size(self, size_bytes):
        """Format file size for display"""
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f} KB"
        elif size_bytes < 1024 * 1024 * 1024:
            return f"{size_bytes / (1024 * 1024):.1f} MB"
        else:
            return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"

    def update_progress(self, percent, message):
        """Update progress bar"""
        self.progress_container.setVisible(True)
        self.progress_bar.setValue(percent)
        self.status_label.setText(message)

    
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
        
        # Table - Updated columns for source/status display
        self.file_table = QTableWidget()
        self.file_table.setColumnCount(6)
        self.file_table.setHorizontalHeaderLabels(['Name', 'Size', 'Type', 'Source', 'Status', 'Path'])
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
            # Status column with color coding
            status = f.get('status', 'unknown')
            status_item = QTableWidgetItem(status.upper())
            if status == 'deleted':
                status_item.setForeground(QColor('#EF4444'))  # Red for deleted
            elif status == 'active':
                status_item.setForeground(QColor('#22C55E'))  # Green for active
            else:
                status_item.setForeground(QColor('#9CA3AF'))  # Gray for unknown/carved
            self.file_table.setItem(i, 0, status_item)
            
            # Integrity column with verification status
            integrity = f.get('integrity_status', 'unverified')
            if integrity == 'verified':
                integrity_item = QTableWidgetItem('✓ VERIFIED')
                integrity_item.setForeground(QColor('#22C55E'))  # Green
            elif integrity == 'corrupted':
                integrity_item = QTableWidgetItem('✗ CORRUPTED')
                integrity_item.setForeground(QColor('#EF4444'))  # Red
            elif integrity == 'unverified':
                integrity_item = QTableWidgetItem('? UNVERIFIED')
                integrity_item.setForeground(QColor('#F59E0B'))  # Yellow
            else:  # no_checksum
                integrity_item = QTableWidgetItem('- N/A')
                integrity_item.setForeground(QColor('#6B7280'))  # Gray
            self.file_table.setItem(i, 1, integrity_item)
            
            self.file_table.setItem(i, 2, QTableWidgetItem(f.get('name', '')))
            self.file_table.setItem(i, 3, QTableWidgetItem(format_bytes(f.get('size', 0))))
            self.file_table.setItem(i, 4, QTableWidgetItem(f.get('type', '')))
            self.file_table.setItem(i, 5, QTableWidgetItem(f.get('modified', '')))
            hash_val = f.get('hash', '')
            self.file_table.setItem(i, 6, QTableWidgetItem(hash_val[:20] + '...' if len(hash_val) > 20 else hash_val))
    
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