"""
Unearth Forensic Recovery Tool - Central Application Controller

This module provides the main application interface for coordinating
forensic recovery operations across XFS and Btrfs file systems.

Author: Unearth Development Team
Version: 1.0.0
"""

import logging
import json
from pathlib import Path
from typing import Optional, Dict, List, Any
from datetime import datetime
from enum import Enum
import hashlib


class FileSystemType(Enum):
    """Supported file system types"""
    XFS = "xfs"
    BTRFS = "btrfs"
    UNKNOWN = "unknown"


class RecoverySession:
    """
    Manages a forensic recovery session with state tracking and audit logging.
    """
    
    def __init__(self, session_id: str, image_path: Path, output_dir: Path):
        """
        Initialize a recovery session.
        
        Args:
            session_id: Unique identifier for this session
            image_path: Path to the disk image file
            output_dir: Directory for recovered files and reports
        """
        self.session_id = session_id
        self.image_path = image_path
        self.output_dir = output_dir
        self.created_at = datetime.now()
        self.fs_type = FileSystemType.UNKNOWN
        self.recovered_files = []
        self.carved_files = []
        self.metadata = {}
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert session to dictionary for serialization"""
        return {
            "session_id": self.session_id,
            "image_path": str(self.image_path),
            "output_dir": str(self.output_dir),
            "created_at": self.created_at.isoformat(),
            "fs_type": self.fs_type.value,
            "recovered_files_count": len(self.recovered_files),
            "carved_files_count": len(self.carved_files),
            "metadata": self.metadata
        }


class UnearthApp:
    """
    Main application class coordinating all forensic recovery operations.
    
    This class provides a unified interface for:
    - File system detection and parsing
    - File recovery and carving
    - Metadata extraction
    - AI-powered analysis
    - Report generation
    """
    
    def __init__(self, config_path: Optional[Path] = None):
        """
        Initialize the Unearth application.
        
        Args:
            config_path: Optional path to configuration file
        """
        self.config = self._load_config(config_path)
        self.sessions: Dict[str, RecoverySession] = {}
        self.logger = self._setup_logging()
        
        # Module references (will be initialized when needed)
        self.xfs_parser = None
        self.btrfs_parser = None
        self.file_carver = None
        self.ai_classifier = None
        self.anomaly_detector = None
        self.keyword_search = None
        self.report_generator = None
        
        self.logger.info("Unearth application initialized")
    
    def _load_config(self, config_path: Optional[Path]) -> Dict[str, Any]:
        """
        Load application configuration.
        
        Args:
            config_path: Path to JSON configuration file
            
        Returns:
            Configuration dictionary with defaults
        """
        default_config = {
            "version": "1.0.0",
            "log_level": "INFO",
            "max_file_size_mb": 500,
            "chunk_size_kb": 4096,
            "enable_ai_analysis": True,
            "enable_hash_verification": True,
            "supported_hash_algorithms": ["md5", "sha256"],
            "carving_signatures": {},
            "output_formats": ["pdf", "csv", "json"]
        }
        
        if config_path and config_path.exists():
            try:
                with open(config_path, 'r') as f:
                    user_config = json.load(f)
                default_config.update(user_config)
            except Exception as e:
                logging.warning(f"Failed to load config from {config_path}: {e}")
        
        return default_config
    
    def _setup_logging(self) -> logging.Logger:
        """
        Configure forensic-grade logging with audit trail.
        
        Returns:
            Configured logger instance
        """
        log_level = getattr(logging, self.config.get("log_level", "INFO"))
        
        # Create logs directory
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        
        # Configure logger
        logger = logging.getLogger("unearth")
        logger.setLevel(log_level)
        
        # File handler with timestamp
        log_file = log_dir / f"unearth_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(log_level)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(log_level)
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        
        return logger
    
    def create_session(self, image_path: str, output_dir: str) -> str:
        """
        Create a new forensic recovery session.
        
        Args:
            image_path: Path to disk image file
            output_dir: Directory for output files
            
        Returns:
            Session ID for tracking
            
        Raises:
            FileNotFoundError: If image file doesn't exist
            ValueError: If output directory cannot be created
        """
        image_path_obj = Path(image_path)
        if not image_path_obj.exists():
            raise FileNotFoundError(f"Disk image not found: {image_path}")
        
        output_dir_obj = Path(output_dir)
        output_dir_obj.mkdir(parents=True, exist_ok=True)
        
        # Generate session ID
        session_id = hashlib.md5(
            f"{image_path}{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]
        
        # Create session
        session = RecoverySession(session_id, image_path_obj, output_dir_obj)
        self.sessions[session_id] = session
        
        self.logger.info(f"Created session {session_id} for image: {image_path}")
        return session_id
    
    def detect_filesystem(self, session_id: str) -> FileSystemType:
        """
        Detect the file system type of the disk image.
        
        Args:
            session_id: Session identifier
            
        Returns:
            Detected file system type
            
        Raises:
            KeyError: If session not found
        """
        session = self.sessions.get(session_id)
        if not session:
            raise KeyError(f"Session not found: {session_id}")
        
        self.logger.info(f"Detecting filesystem for session {session_id}")
        
        # Read magic bytes from image
        try:
            with open(session.image_path, 'rb') as f:
                # XFS magic: 0x58465342 at offset 0
                f.seek(0)
                magic = f.read(4)
                if magic == b'XFSB':
                    session.fs_type = FileSystemType.XFS
                    self.logger.info(f"Detected XFS filesystem")
                    return FileSystemType.XFS
                
                # Btrfs magic: "_BHRfS_M" at offset 0x10040
                f.seek(0x10040)
                magic = f.read(8)
                if magic == b'_BHRfS_M':
                    session.fs_type = FileSystemType.BTRFS
                    self.logger.info(f"Detected Btrfs filesystem")
                    return FileSystemType.BTRFS
                
        except Exception as e:
            self.logger.error(f"Filesystem detection failed: {e}")
        
        session.fs_type = FileSystemType.UNKNOWN
        self.logger.warning(f"Unknown filesystem type")
        return FileSystemType.UNKNOWN
    
    def recover_deleted_files(self, session_id: str) -> List[Dict[str, Any]]:
        """
        Recover deleted files from the disk image.
        
        Args:
            session_id: Session identifier
            
        Returns:
            List of recovered file metadata
            
        Raises:
            KeyError: If session not found
            NotImplementedError: If filesystem parser not available
        """
        session = self.sessions.get(session_id)
        if not session:
            raise KeyError(f"Session not found: {session_id}")
        
        self.logger.info(f"Starting file recovery for session {session_id}")
        
        # Detect filesystem if not already done
        if session.fs_type == FileSystemType.UNKNOWN:
            self.detect_filesystem(session_id)
        
        recovered_files = []
        
        # TODO: Initialize parser based on filesystem type
        # This will be implemented when parsers are ready
        if session.fs_type == FileSystemType.XFS:
            self.logger.info("Using XFS parser (to be implemented)")
            # self.xfs_parser = XFSParser(session.image_path)
            # recovered_files = self.xfs_parser.recover_deleted()
            
        elif session.fs_type == FileSystemType.BTRFS:
            self.logger.info("Using Btrfs parser (to be implemented)")
            # self.btrfs_parser = BtrfsParser(session.image_path)
            # recovered_files = self.btrfs_parser.recover_deleted()
            
        else:
            raise NotImplementedError(f"Parser not available for {session.fs_type.value}")
        
        session.recovered_files = recovered_files
        self.logger.info(f"Recovered {len(recovered_files)} files")
        return recovered_files
    
    def carve_files(self, session_id: str, file_types: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        Perform file carving based on magic numbers.
        
        Args:
            session_id: Session identifier
            file_types: Optional list of file types to carve (e.g., ['jpg', 'pdf'])
            
        Returns:
            List of carved file metadata
            
        Raises:
            KeyError: If session not found
        """
        session = self.sessions.get(session_id)
        if not session:
            raise KeyError(f"Session not found: {session_id}")
        
        self.logger.info(f"Starting file carving for session {session_id}")
        
        # TODO: Initialize file carver (will be implemented in next module)
        # self.file_carver = FileCarver(session.image_path, session.output_dir)
        # carved_files = self.file_carver.carve(file_types)
        
        carved_files = []
        session.carved_files = carved_files
        self.logger.info(f"Carved {len(carved_files)} files")
        return carved_files
    
    def analyze_files(self, session_id: str, enable_ai: bool = True) -> Dict[str, Any]:
        """
        Perform AI-powered analysis on recovered files.
        
        Args:
            session_id: Session identifier
            enable_ai: Whether to enable AI classification and anomaly detection
            
        Returns:
            Analysis results dictionary
            
        Raises:
            KeyError: If session not found
        """
        session = self.sessions.get(session_id)
        if not session:
            raise KeyError(f"Session not found: {session_id}")
        
        self.logger.info(f"Starting file analysis for session {session_id}")
        
        analysis_results = {
            "classifications": [],
            "anomalies": [],
            "keywords": []
        }
        
        # TODO: Initialize analysis modules (will be implemented later)
        # if enable_ai and self.config.get("enable_ai_analysis"):
        #     self.ai_classifier = AIClassifier()
        #     self.anomaly_detector = AnomalyDetector()
        #     analysis_results["classifications"] = self.ai_classifier.classify(files)
        #     analysis_results["anomalies"] = self.anomaly_detector.detect(files)
        
        self.logger.info(f"Analysis complete for session {session_id}")
        return analysis_results
    
    def generate_report(self, session_id: str, format: str = "pdf") -> Path:
        """
        Generate forensic report for the session.
        
        Args:
            session_id: Session identifier
            format: Report format ('pdf', 'csv', 'json')
            
        Returns:
            Path to generated report file
            
        Raises:
            KeyError: If session not found
            ValueError: If format not supported
        """
        session = self.sessions.get(session_id)
        if not session:
            raise KeyError(f"Session not found: {session_id}")
        
        if format not in self.config.get("output_formats", ["pdf"]):
            raise ValueError(f"Unsupported format: {format}")
        
        self.logger.info(f"Generating {format} report for session {session_id}")
        
        # TODO: Initialize report generator (will be implemented later)
        # self.report_generator = ReportGenerator(session)
        # report_path = self.report_generator.generate(format)
        
        report_path = session.output_dir / f"report_{session_id}.{format}"
        self.logger.info(f"Report generated: {report_path}")
        return report_path
    
    def get_session_info(self, session_id: str) -> Dict[str, Any]:
        """
        Get information about a session.
        
        Args:
            session_id: Session identifier
            
        Returns:
            Session information dictionary
            
        Raises:
            KeyError: If session not found
        """
        session = self.sessions.get(session_id)
        if not session:
            raise KeyError(f"Session not found: {session_id}")
        
        return session.to_dict()
    
    def list_sessions(self) -> List[Dict[str, Any]]:
        """
        List all active sessions.
        
        Returns:
            List of session information dictionaries
        """
        return [session.to_dict() for session in self.sessions.values()]
    
    def cleanup_session(self, session_id: str) -> None:
        """
        Clean up and close a session.
        
        Args:
            session_id: Session identifier
            
        Raises:
            KeyError: If session not found
        """
        if session_id not in self.sessions:
            raise KeyError(f"Session not found: {session_id}")
        
        self.logger.info(f"Cleaning up session {session_id}")
        del self.sessions[session_id]


# Example usage and testing
if __name__ == "__main__":
    # Initialize application
    app = UnearthApp()
    
    # Create a test session (assuming test image exists)
    try:
        session_id = app.create_session(
            image_path="data/test_images/test_disk.img",
            output_dir="data/recovered_output/test_session"
        )
        print(f"Created session: {session_id}")
        
        # Detect filesystem
        fs_type = app.detect_filesystem(session_id)
        print(f"Detected filesystem: {fs_type.value}")
        
        # Get session info
        info = app.get_session_info(session_id)
        print(f"Session info: {json.dumps(info, indent=2)}")
        
    except FileNotFoundError as e:
        print(f"Note: {e}")
        print("This is expected if test image doesn't exist yet.")