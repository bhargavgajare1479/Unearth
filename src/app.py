"""
Unearth Forensic Recovery Tool - Central Application Controller

This module provides the main application interface for coordinating
forensic recovery operations across XFS and Btrfs file systems.

Author: Unearth Development Team
Version: 1.0.0
"""
import logging
import json
import os
from pathlib import Path
from typing import Optional, Dict, List, Any
from datetime import datetime
from enum import Enum
import hashlib
import zipfile
import re
import xml.etree.ElementTree as ET
from core.btrfs_parser import BtrfsParser


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
        self.recovered_files = []  # From metadata parser
        self.carved_files = []     # From file carver
        self.all_files = []        # Combined list for filtering (carved + metadata)
        self.filtered_files = []   # Currently displayed after filtering
        self.metadata = {}
        
        # Filter state for dynamic filtering
        self.filter_state = {
            'source': 'all',           # 'all', 'carved', 'metadata'
            'status': 'all',           # 'all', 'deleted', 'active', 'unknown'
            'file_type': 'all',        # 'all' or specific extension
            'show_duplicates': False,  # Whether to show duplicate carved files
        }
        
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
            "all_files_count": len(self.all_files),
            "filtered_files_count": len(self.filtered_files),
            "metadata": self.metadata,
            "filter_state": self.filter_state
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
        self.keyword_searcher = None  # Renamed to avoid shadowing keyword_search() method
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
        
        # Configure root logger to capture ALL module logs
        root_logger = logging.getLogger()
        root_logger.setLevel(log_level)
        
        # Configure unearth logger specifically
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
        
        # Add handlers to root logger (captures all modules including child loggers)
        root_logger.addHandler(file_handler)
        root_logger.addHandler(console_handler)
        
        # Don't add handlers to unearth logger — it inherits from root via propagation.
        # Adding to both causes every message to be printed twice.
        
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
        
        # Try Btrfs parser first
        try:
            btrfs_parser = BtrfsParser(str(session.image_path))
            with btrfs_parser:
                if btrfs_parser.detect_filesystem():
                    session.fs_type = FileSystemType.BTRFS
                    self.logger.info("Detected Btrfs filesystem using parser")
                    return FileSystemType.BTRFS
        except Exception as e:
            self.logger.debug(f"Btrfs detection failed: {e}")
        
        if session.fs_type == FileSystemType.UNKNOWN:
            try:
                from core.partition_parser import PartitionTableParser
                partition_parser = PartitionTableParser(str(session.image_path))
                partitions = partition_parser.parse()
                
                if partitions:
                    self.logger.info(f"Found {len(partitions)} partitions")
                    
                    # Try to detect filesystem in each partition
                    for partition in partitions:
                        self.logger.info(f"Checking partition {partition.index}: offset={partition.offset}, size={partition.size}")
                        
                        # Try Btrfs with offset
                        try:
                            btrfs_parser = BtrfsParser(str(session.image_path), offset=partition.offset)
                            with btrfs_parser:
                                if btrfs_parser.detect_filesystem():
                                    session.fs_type = FileSystemType.BTRFS
                                    session.metadata['partition_offset'] = partition.offset
                                    self.logger.info(f"Detected Btrfs filesystem in partition {partition.index}")
                                    return FileSystemType.BTRFS
                        except Exception as e:
                            self.logger.debug(f"Partition {partition.index} check failed: {e}")
                            
            except Exception as e:
                self.logger.error(f"Partition detection failed: {e}")

        # Fallback to manual detection for other filesystems (raw)
        try:
            with open(session.image_path, 'rb') as f:
                # XFS magic: 0x58465342 at offset 0
                f.seek(0)
                magic = f.read(4)
                if magic == b'XFSB':
                    session.fs_type = FileSystemType.XFS
                    self.logger.info("Detected XFS filesystem")
                    return FileSystemType.XFS
                
                # Btrfs magic: "_BHRfS_M" at offset 0x10040 (backup check)
                f.seek(0x10040)
                magic = f.read(8)
                if magic == b'_BHRfS_M':
                    session.fs_type = FileSystemType.BTRFS
                    self.logger.info("Detected Btrfs filesystem (manual)")
                    return FileSystemType.BTRFS
                
        except Exception as e:
            self.logger.error(f"Filesystem detection failed: {e}")
        
        session.fs_type = FileSystemType.UNKNOWN
        self.logger.warning("Unknown filesystem type")
        return FileSystemType.UNKNOWN
    
    def recover_deleted_files(self, session_id: str, progress_callback=None, file_filter: str = "all") -> List[Dict]:
        """
        Recover deleted files from the disk image.
        
        Args:
            session_id: Session identifier
            progress_callback: Optional callback function for progress updates (percent, message)
            file_filter: Filter for which files to recover:
                - "all": Recover all files found (default)
                - "deleted_only": Only recover deleted files
                - "active_only": Only recover active/existing files
            
        Returns:
            List of recovered file metadata
            
        Raises:
            KeyError: If session not found
            NotImplementedError: If filesystem parser not available
        """
        session = self.sessions.get(session_id)
        if not session:
            raise KeyError(f"Session not found: {session_id}")
        
        self.logger.info(f"Starting file recovery for session {session_id} (filter: {file_filter})")
        
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
            self.logger.info("Using Btrfs parser")
            try:
                offset = session.metadata.get('partition_offset', 0)
                
                # Adapter for raw (current, total, msg) -> (percent, msg)
                def parser_callback(curr, total, msg):
                    if progress_callback and total > 0:
                        percent = int((curr / total) * 100)
                        progress_callback(percent, msg)
                
                self.btrfs_parser = BtrfsParser(str(session.image_path), offset=offset, progress_callback=parser_callback)
                with self.btrfs_parser:
                    recovered_files = self.btrfs_parser.recover_deleted_files(session.output_dir, file_filter=file_filter)
                self.logger.info(f"Btrfs parser recovered {len(recovered_files)} files")
            except Exception as e:
                self.logger.error(f"Btrfs recovery failed: {e}")
                recovered_files = []
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
        
        from core.file_carver import FileCarver
        
        self.file_carver = FileCarver(str(session.image_path), session.output_dir)
        carved_files = self.file_carver.carve(file_types)
        
        session.carved_files = carved_files
        self.logger.info(f"Carved {len(carved_files)} files")
        
        # After carving, combine and deduplicate
        self.deduplicate_and_combine(session_id)
        
        return carved_files
    
    def deduplicate_and_combine(self, session_id: str) -> None:
        """
        Combine recovered and carved files, marking duplicates.
        
        Deduplication logic:
        - Compute hash of metadata-recovered files (active ones)
        - Mark carved files with matching hash as duplicates
        - Combine all files into session.all_files
        """
        session = self.sessions.get(session_id)
        if not session:
            return
        
        import hashlib
        
        # Build hash set from metadata-recovered files that are active (not deleted)
        active_hashes = set()
        for f in session.recovered_files:
            # Check if file has hash, if not compute from path
            file_hash = f.get('hash')
            if not file_hash and f.get('path') and os.path.exists(f.get('path', '')):
                try:
                    with open(f['path'], 'rb') as fp:
                        file_hash = hashlib.sha256(fp.read(65536)).hexdigest()
                        f['hash'] = file_hash
                except Exception:
                    pass
            
            # If file is active (not deleted), add to active set
            if file_hash and not f.get('deleted', False):
                active_hashes.add(file_hash)
            
            # Ensure source field
            f['source'] = 'metadata'
            f['is_duplicate'] = False
        
        # Mark carved files as duplicates if they match active files
        duplicates_found = 0
        for f in session.carved_files:
            file_hash = f.get('hash')
            if file_hash and file_hash in active_hashes:
                f['is_duplicate'] = True
                f['status'] = 'active'  # It's a copy of an active file
                duplicates_found += 1
            else:
                f['is_duplicate'] = False
                f['status'] = 'likely_deleted'  # Not matching active = likely deleted
        
        self.logger.info(f"Deduplication: {duplicates_found} carved files match active files")
        
        # Combine all files
        session.all_files = []
        session.all_files.extend(session.recovered_files)
        session.all_files.extend(session.carved_files)
        
        # Apply current filter
        self.apply_filters(session_id)
    
    def apply_filters(self, session_id: str, 
                      source: Optional[str] = None,
                      status: Optional[str] = None,
                      file_type: Optional[str] = None,
                      show_duplicates: Optional[bool] = None) -> List[Dict[str, Any]]:
        """
        Apply filters to all_files and update filtered_files.
        Does NOT re-scan - just filters existing results.
        
        Args:
            session_id: Session identifier
            source: 'all', 'carved', or 'metadata'
            status: 'all', 'deleted', 'active', 'likely_deleted', or 'unknown'
            file_type: 'all' or specific extension (e.g., 'pdf', 'jpg')
            show_duplicates: Whether to include duplicate carved files
            
        Returns:
            Filtered list of files
        """
        session = self.sessions.get(session_id)
        if not session:
            return []
        
        # Update filter state if provided
        if source is not None:
            session.filter_state['source'] = source
        if status is not None:
            session.filter_state['status'] = status
        if file_type is not None:
            session.filter_state['file_type'] = file_type
        if show_duplicates is not None:
            session.filter_state['show_duplicates'] = show_duplicates
        
        fs = session.filter_state
        filtered = []
        
        for f in session.all_files:
            # Source filter
            if fs['source'] != 'all' and f.get('source') != fs['source']:
                continue
            
            # Status filter
            file_status = f.get('status', 'unknown')
            if f.get('deleted', False):
                file_status = 'deleted'
            elif f.get('is_duplicate', False):
                file_status = 'active'
                
            if fs['status'] != 'all' and file_status != fs['status']:
                continue
            
            # File type filter
            if fs['file_type'] != 'all':
                file_ext = f.get('type', '') or os.path.splitext(f.get('name', ''))[1].lower().strip('.')
                if file_ext != fs['file_type']:
                    continue
            
            # Duplicate filter
            if not fs['show_duplicates'] and f.get('is_duplicate', False):
                continue
            
            filtered.append(f)
        
        session.filtered_files = filtered
        self.logger.debug(f"Filter applied: {len(filtered)}/{len(session.all_files)} files shown")
        return filtered
    
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
    
    def _extract_text_lines(self, filepath: str, file_type: str) -> List[str]:
        """
        Extract searchable text lines from a file based on its format.
        
        Supports:
        - PDF files: extracts text per page using PyPDF2
        - DOCX files: unzips and parses word/document.xml
        - ODT/ODS files: unzips and parses content.xml
        - XLSX files: unzips and parses shared strings + sheet data
        - Plain text: reads as UTF-8 line by line
        
        Args:
            filepath: absolute path to the file
            file_type: file extension/type (e.g. 'pdf', 'zip', 'jpg')
            
        Returns:
            List of text lines extracted from the file.
            Returns empty list if the file can't be read or is unsupported binary.
        """
        ext = file_type.lower().strip('.')
        
        # Also check the actual file extension (carved files may have wrong type)
        actual_ext = os.path.splitext(filepath)[1].lower().strip('.')
        
        # --- PDF extraction via PyPDF2 ---
        if ext == 'pdf' or actual_ext == 'pdf':
            return self._extract_pdf_text(filepath)
        
        # --- DOCX / ODT / XLSX extraction via ZIP + XML ---
        # These are all ZIP archives containing XML files with the actual text
        if ext in ('zip', 'docx', 'odt', 'ods', 'xlsx') or \
           actual_ext in ('docx', 'odt', 'ods', 'xlsx'):
            return self._extract_office_text(filepath, actual_ext or ext)
        
        # --- Plain text fallback ---
        # Skip known binary formats that can never contain readable text
        binary_formats = {'jpg', 'jpeg', 'png', 'gif', 'bmp', 'tiff', 'webp',
                         'heic', 'mp3', 'mp4', 'avi', 'mp3_id3', '7z', 'rar'}
        if ext in binary_formats or actual_ext in binary_formats:
            return []
        
        return self._extract_plaintext(filepath)
    
    def _extract_pdf_text(self, filepath: str) -> List[str]:
        """Extract text from a PDF file using PyPDF2."""
        lines = []
        try:
            from PyPDF2 import PdfReader
            reader = PdfReader(filepath)
            for page_num, page in enumerate(reader.pages, start=1):
                page_text = page.extract_text()
                if page_text:
                    # Split into lines and add page context
                    for line in page_text.splitlines():
                        stripped = line.strip()
                        if stripped:  # skip blank lines
                            lines.append(stripped)
        except ImportError:
            self.logger.debug("PyPDF2 not installed — PDF content search disabled")
        except Exception as e:
            self.logger.debug(f"Could not extract PDF text from {filepath}: {e}")
        return lines
    
    def _extract_office_text(self, filepath: str, ext: str) -> List[str]:
        """
        Extract text from Office/ODF documents by reading their internal XML.
        
        DOCX → word/document.xml (Office Open XML)
        ODT/ODS → content.xml (OpenDocument Format)
        XLSX → xl/sharedStrings.xml + xl/worksheets/sheet*.xml
        """
        lines = []
        try:
            with zipfile.ZipFile(filepath, 'r') as zf:
                names = zf.namelist()
                
                # --- DOCX: Microsoft Word ---
                if 'word/document.xml' in names:
                    xml_data = zf.read('word/document.xml')
                    # Strip XML tags to get plain text
                    text = self._strip_xml_tags(xml_data.decode('utf-8', errors='ignore'))
                    lines.extend(line.strip() for line in text.splitlines() if line.strip())
                
                # --- ODT/ODS: LibreOffice / OpenDocument ---
                elif 'content.xml' in names:
                    xml_data = zf.read('content.xml')
                    text = self._strip_xml_tags(xml_data.decode('utf-8', errors='ignore'))
                    lines.extend(line.strip() for line in text.splitlines() if line.strip())
                
                # --- XLSX: Microsoft Excel ---
                elif 'xl/sharedStrings.xml' in names:
                    xml_data = zf.read('xl/sharedStrings.xml')
                    text = self._strip_xml_tags(xml_data.decode('utf-8', errors='ignore'))
                    lines.extend(line.strip() for line in text.splitlines() if line.strip())
                
                # --- Generic ZIP: try to find any readable text files inside ---
                else:
                    for name in names:
                        if name.endswith(('.txt', '.csv', '.xml', '.html', '.json')):
                            try:
                                data = zf.read(name).decode('utf-8', errors='ignore')
                                lines.extend(
                                    line.strip() for line in data.splitlines() if line.strip()
                                )
                            except Exception:
                                pass
                                
        except zipfile.BadZipFile:
            # Not actually a ZIP — try as plain text
            return self._extract_plaintext(filepath)
        except Exception as e:
            self.logger.debug(f"Could not extract office text from {filepath}: {e}")
        return lines
    
    def _extract_plaintext(self, filepath: str) -> List[str]:
        """Read a file as plain UTF-8 text, returning lines. Skips binary files."""
        lines = []
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                for line in f:
                    lines.append(line)
        except UnicodeDecodeError:
            # Binary file — can't read as text
            pass
        except PermissionError:
            self.logger.warning(f"Permission denied reading: {filepath}")
        except Exception as e:
            self.logger.debug(f"Could not read file {filepath}: {e}")
        return lines
    
    def _strip_xml_tags(self, xml_text: str) -> str:
        """Remove all XML/HTML tags from a string, leaving only the text content."""
        # Use regex to strip tags — faster than full XML parsing for search
        clean = re.sub(r'<[^>]+>', ' ', xml_text)
        # Collapse whitespace
        clean = re.sub(r'\s+', ' ', clean)
        return clean
    
    def keyword_search(self, session_id: str, keywords: List[str],
                       case_sensitive: bool = False,
                       search_content: bool = True,
                       max_snippet_length: int = 120) -> List[Dict[str, Any]]:
        """
        Search for keywords in recovered file names AND file contents.
        
        This is the core forensic keyword search capability. It performs:
        1. Filename matching — checks if any keyword appears in the file's name
        2. Content matching — reads each file as text and searches line-by-line,
           recording the line number and a context snippet for each hit
        
        Binary files (those that fail UTF-8 decoding) are skipped for content
        search but still checked for filename matches.
        
        Args:
            session_id: Active session identifier
            keywords: List of keyword strings to search for
            case_sensitive: If False (default), search is case-insensitive
            search_content: If True (default), search inside file contents too
            max_snippet_length: Max characters to include in content snippets
            
        Returns:
            List of match result dicts, each containing:
              - name: filename
              - path: full file path
              - size: file size in bytes
              - type: file extension/type
              - match_type: 'filename', 'content', or 'both'
              - matched_keywords: list of keywords that matched
              - content_matches: list of {line_number, line_text, keyword} dicts
              
        Raises:
            KeyError: If session not found
        """
        session = self.sessions.get(session_id)
        if not session:
            raise KeyError(f"Session not found: {session_id}")
        
        self.logger.info(f"Keyword search: {keywords} (case_sensitive={case_sensitive}, content={search_content})")
        
        # Combine all recovered + carved files into one list to search through
        all_files = session.recovered_files + session.carved_files
        
        # Normalize keywords for case-insensitive comparison if needed
        if not case_sensitive:
            search_keywords = [kw.lower() for kw in keywords]
        else:
            search_keywords = list(keywords)
        
        results = []
        
        for file_info in all_files:
            filename = file_info.get('name', '')
            filepath = file_info.get('path', '')
            
            # --- Step 1: Check filename for keyword matches ---
            # Compare against the filename (not the full path) to avoid
            # false positives from directory names
            compare_name = filename if case_sensitive else filename.lower()
            filename_matched_keywords = [
                kw for kw in search_keywords if kw in compare_name
            ]
            
            # --- Step 2: Check file content for keyword matches ---
            # Only attempt content search if:
            #   a) search_content is enabled
            #   b) the file path exists on disk (it may have been recovered)
            content_matches = []
            content_matched_keywords = set()
            
            if search_content and filepath and os.path.isfile(filepath):
                # Extract text lines from the file based on its format.
                # Different file types need different extraction methods:
                #   - PDF: extract text per page using PyPDF2
                #   - DOCX/ODT/XLSX: unzip and parse XML content
                #   - Plain text: read as UTF-8 line by line
                text_lines = self._extract_text_lines(filepath, file_info.get('type', ''))
                
                # Search through extracted text lines for keyword matches
                for line_number, line in enumerate(text_lines, start=1):
                    compare_line = line if case_sensitive else line.lower()
                    
                    for kw in search_keywords:
                        if kw in compare_line:
                            # Found a keyword — record the match with context
                            snippet = line.strip()
                            if len(snippet) > max_snippet_length:
                                snippet = snippet[:max_snippet_length] + '...'
                            
                            content_matches.append({
                                'line_number': line_number,
                                'line_text': snippet,
                                'keyword': kw
                            })
                            content_matched_keywords.add(kw)
            
            # --- Step 3: Build result if any match was found ---
            all_matched = set(filename_matched_keywords) | content_matched_keywords
            
            if all_matched:
                # Determine the match type so the UI can show appropriate icons
                has_filename = len(filename_matched_keywords) > 0
                has_content = len(content_matched_keywords) > 0
                
                if has_filename and has_content:
                    match_type = 'both'
                elif has_filename:
                    match_type = 'filename'
                else:
                    match_type = 'content'
                
                results.append({
                    'name': filename,
                    'path': filepath,
                    'size': file_info.get('size', 0),
                    'type': file_info.get('type', 'unknown'),
                    'match_type': match_type,
                    'matched_keywords': list(all_matched),
                    'content_matches': content_matches,
                })
        
        self.logger.info(f"Keyword search complete: {len(results)} files matched out of {len(all_files)} total")
        return results
    
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