import os
import logging
import hashlib
from pathlib import Path
from typing import List, Dict, Optional, Tuple

from core.metadata_extractor import MetadataExtractor

class FileCarver:
    """
    File Carving Engine.
    Scans raw disk data for magic numbers/signatures to recover files 
    without filesystem metadata.
    """
    
    # Common file signatures
    SIGNATURES = {
        'jpg': {
            'header': b'\xFF\xD8\xFF',
            'footer': b'\xFF\xD9',
            'max_size': 20 * 1024 * 1024, # 20MB
        },
        'png': {
            'header': b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A',
            'footer': b'\x49\x45\x4E\x44\xAE\x42\x60\x82',
            'max_size': 20 * 1024 * 1024,
        },
        'pdf': {
            'header': b'%PDF-',
            'footer': b'%%EOF',
            'max_size': 50 * 1024 * 1024,
        },
        'gif': {
            'header': b'GIF89a',
            'footer': b'\x00\x3B',
            'max_size': 10 * 1024 * 1024,
        },
        'gif87': {
            'header': b'GIF87a',
            'footer': b'\x00\x3B',
            'max_size': 10 * 1024 * 1024,
        },
        'zip': { # Covers docx, xlsx, pptx, odt, etc.
            'header': b'\x50\x4B\x03\x04',
            'footer': None, # Hard to determine end easily without parsing
            'max_size': 100 * 1024 * 1024, # 100MB for office docs
        },
        'mp3': {
            'header': b'\xFF\xFB',  # MP3 frame sync
            'footer': None,
            'max_size': 30 * 1024 * 1024, # 30MB
        },
        'mp3_id3': {
            'header': b'ID3',  # MP3 with ID3 tag
            'footer': None,
            'max_size': 30 * 1024 * 1024,
        },
        'mp4': {
            'header': b'\x00\x00\x00',  # ftyp atom (will need extra validation)
            'footer': None,
            'max_size': 500 * 1024 * 1024, # 500MB for video
        },
        'bmp': {
            'header': b'BM',
            'footer': None,
            'max_size': 50 * 1024 * 1024,
        },
        'webp': {
            'header': b'RIFF',  # RIFF....WEBP
            'footer': None,
            'max_size': 20 * 1024 * 1024,
        },
        'avi': {
            'header': b'RIFF',  # RIFF....AVI
            'footer': None,
            'max_size': 500 * 1024 * 1024,
        },
        'tiff': {
            'header': b'\x49\x49\x2A\x00',  # Little-endian TIFF
            'footer': None,
            'max_size': 100 * 1024 * 1024,
        },
        'tiff_be': {
            'header': b'\x4D\x4D\x00\x2A',  # Big-endian TIFF
            'footer': None,
            'max_size': 100 * 1024 * 1024,
        },
        'heic': {
            'header': b'\x00\x00\x00',  # ftyp heic/mif1
            'footer': None,
            'max_size': 50 * 1024 * 1024,
        },
        '7z': {
            'header': b'\x37\x7A\xBC\xAF\x27\x1C',
            'footer': None,
            'max_size': 100 * 1024 * 1024,
        },
        'rar': {
            'header': b'\x52\x61\x72\x21\x1A\x07',  # Rar!
            'footer': None,
            'max_size': 100 * 1024 * 1024,
        },
    }
    
    def __init__(self, image_path: str, output_dir: str):
        self.image_path = Path(image_path)
        self.output_dir = Path(output_dir)
        self.logger = logging.getLogger(__name__)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.metadata_extractor = MetadataExtractor()
        
    def carve(self, file_types: Optional[List[str]] = None) -> List[Dict]:
        """
        Perform carving.
        
        Args:
            file_types: List of extensions to look for (e.g. ['jpg', 'png']). 
                        If None, look for all supported.
        """
        self.logger.info(f"Starting carving on {self.image_path}")
        carved_files = []
        
        # Filter signatures
        active_sigs = {}
        if file_types:
            for ft in file_types:
                ft = ft.lower().strip('.')
                if ft in self.SIGNATURES:
                    active_sigs[ft] = self.SIGNATURES[ft]
        else:
            active_sigs = self.SIGNATURES
            
        if not active_sigs:
            self.logger.warning("No valid file signatures selected for carving.")
            return []
            
        try:
            with open(self.image_path, 'rb') as f:
                # Naive implementation: Read buffer, search for headers.
                # To be robust, we should handle cross-boundary headers.
                # We'll use a sliding window or overlap approach.
                
                chunk_size = 10 * 1024 * 1024 # 10MB
                overlap = 1024 # 1KB overlap
                offset = 0
                
                # Setup output counters
                counts = {ext: 0 for ext in active_sigs}
                
                f.seek(0, 2)
                total_size = f.tell()
                f.seek(0)
                
                # Progress tracking
                last_progress = 0
                
                while offset < total_size:
                    # Log progress every 10%
                    progress = int((offset / total_size) * 100)
                    if progress >= last_progress + 10:
                        self.logger.info(f"Carving progress: {progress}% ({sum(counts.values())} files found so far)")
                        last_progress = progress
                    
                    f.seek(offset)
                    data = f.read(chunk_size + overlap)
                    if not data:
                        break
                        
                    # Scan for headers in this chunk
                    for ext, sig in active_sigs.items():
                        header = sig['header']
                        # Find all occurrences of header in data
                        # Note: This is computationally expensive for 'FF' headers if not careful.
                        # Jpeg FF D8 FF is specific enough.
                        
                        start_idx = 0
                        while True:
                            idx = data.find(header, start_idx)
                            if idx == -1:
                                break
                                
                            # If we found a header, try to extract file
                            # Don't re-process if it's in the overlap region from PREVIOUS chunk (idx < 0)
                            # But here idx is relative to current read.
                            # We only care if idx < chunk_size (start address is in main block)
                            # or if we are at end of file.
                            
                            if idx >= chunk_size and (offset + idx < total_size):
                                # It's in the overlap for the NEXT chunk loop. Skip.
                                break
                                
                            abs_start = offset + idx
                            
                            # Attempt extraction
                            recovered_data = self._extract_file(f, abs_start, sig['footer'], sig['max_size'])
                            
                            if recovered_data:
                                counts[ext] += 1
                                filename = f"carved_{counts[ext]:04d}.{ext}"
                                out_file = self.output_dir / filename
                                
                                with open(out_file, 'wb') as out:
                                    out.write(recovered_data)
                                    
                                # Compute hash for deduplication (first 64KB)
                                file_hash = hashlib.sha256(recovered_data[:65536]).hexdigest()
                                
                                # Metadata extraction is done lazily (on-demand) to keep carving fast
                                # Call extract_metadata() on results to get EXIF/PDF info
                                
                                carved_files.append({
                                    'name': filename,
                                    'size': len(recovered_data),
                                    'type': ext,
                                    'path': str(out_file),
                                    'offset': abs_start,
                                    'hash': file_hash,
                                    'source': 'carved',
                                    'status': 'unknown',  # Will be determined by deduplication
                                    'is_duplicate': False,
                                    'metadata': None,  # Lazy: use extract_metadata() to populate
                                })
                                
                            start_idx = idx + 1
                    
                    offset += chunk_size
                    
        except Exception as e:
            self.logger.error(f"Carving failed: {e}")
            
        self.logger.info(f"Carving complete. Found {len(carved_files)} files.")
        return carved_files

    def _extract_file(self, f, start_offset: int, footer: Optional[bytes], max_size: int) -> Optional[bytes]:
        """Extract file data from offsets."""
        try:
            f.seek(start_offset)
            
            # If footer known, look for it
            if footer:
                # Read max_size to find footer
                # NOTE: This reads into memory. For huge max_size, buffered approach needed.
                # Assuming max_size ~20-50MB is fine for RAM.
                chunk = f.read(max_size)
                
                footer_idx = chunk.find(footer)
                if footer_idx != -1:
                    # Found footer. Include it.
                    end_idx = footer_idx + len(footer)
                    return chunk[:end_idx]
                else:
                    # Footer not found. 
                    # Options: Return max_size (might be garbage), or fail.
                    # Usually better to be conservative to avoid huge garbage files?
                    # Or aggressive? Let's verify header matches exactly first.
                    return None # Conservative: footer required
            else:
                # No footer (e.g. ZIP). We could use internal structure parsing (hard).
                # Simple carve: Read reasonable amount or look for next header?
                # For ZIP, finding End of Central Directory record is strictly required for validity.
                # Simplification: Read default size.
                return f.read(min(max_size, 1024*1024)) # 1MB default for footer-less
                
        except Exception:
            return None

    def extract_metadata(self, file_info: Dict) -> Dict:
        """
        Extract embedded metadata from a carved file.
        
        Call this on-demand for files the user wants to inspect.
        
        Args:
            file_info: A carved file dict with 'path' key
            
        Returns:
            Updated file_info with 'metadata' populated
        """
        if file_info.get('metadata') is None:
            path = file_info.get('path', '')
            if path:
                file_info['metadata'] = self.metadata_extractor.extract(path)
        return file_info
