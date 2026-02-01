import sys
import os
import struct
from pathlib import Path

# Add src to path to import local modules
sys.path.insert(0, os.path.join(os.getcwd(), 'src'))

from core.btrfs_parser import BtrfsParser, BTRFS_INODE_ITEM_KEY # We need to ensure constants are exported or redefine them

# Redefine constants if not available in import
BTRFS_ROOT_TREE_OBJECTID = 1
BTRFS_EXTENT_TREE_OBJECTID = 2
BTRFS_CHUNK_TREE_OBJECTID = 3
BTRFS_DEV_TREE_OBJECTID = 4
BTRFS_FS_TREE_OBJECTID = 5

def debug_scan(image_path, offset=0):
    print(f"--- Debugging Btrfs Scan on {image_path} (offset {offset}) ---")
    
    parser = BtrfsParser(image_path, offset=offset)
    
    try:
        if not parser.detect_filesystem():
            print("❌ NOT detected as Btrfs.")
            return

        sb = parser.parse_superblock()
        print(f"✅ Superblock parsed. Label: '{sb.label}', Nodesize: {sb.nodesize}, Total: {sb.total_bytes}")
        
        # Scan
        print("Scanning for leaves...")
        current_offset = 0
        total_size = sb.total_bytes
        nodesize = sb.nodesize
        sectorsize = sb.sectorsize # usually 4096
        scan_step = sectorsize 
        chunk_size = 100 * 1024 * 1024 # 100MB chunks
        
        stats = {
            'leaves_found': 0,
            'by_owner': {},
            'inodes_found': 0,
            'inodes_deleted': 0,
            'inodes_existing': 0,
            'extents_found': 0,
            'chunks_found': 0
        }
        
        parser.open()
        parser.file_handle.seek(parser.offset)
        
        # Limit scan for debug speed (first 2GB or full if small)
        scan_limit = min(total_size, 2 * 1024 * 1024 * 1024) 
        
        while current_offset < scan_limit:
            if current_offset % chunk_size == 0:
                print(f"  Scanning offset {current_offset}...")
                
            chunk = parser.file_handle.read(min(chunk_size, scan_limit - current_offset))
            if not chunk:
                break
                
            for i in range(0, len(chunk), scan_step):
                block = chunk[i:i+nodesize] # Read full node size
                if len(block) < nodesize: continue
                
                # FSID Check
                if block[32:48] != sb.fsid:
                    continue
                    
                try:
                    header = parser.parse_header(block)
                    if header.level == 0:
                        stats['leaves_found'] += 1
                        owner = header.owner
                        stats['by_owner'][owner] = stats['by_owner'].get(owner, 0) + 1
                        
                        # Process items in leaf
                        offset = 101
                        for _ in range(header.nritems):
                             if offset + 25 > len(block): break
                             key = parser.parse_btrfs_key(block, offset)
                             
                             # Get item size
                             item_offset = struct.unpack('<I', block[offset+17:offset+21])[0]
                             item_size = struct.unpack('<I', block[offset+21:offset+25])[0]
                             offset += 25
                             
                             if key.type == 1: # INODE_ITEM
                                stats['inodes_found'] += 1
                                # Parse inode to check nlink
                                data_start = 101
                                abs_off = data_start + item_offset
                                if abs_off + item_size <= len(block):
                                    idata = block[abs_off : abs_off + item_size]
                                    inode = parser.parse_inode_item(idata)
                                    is_reg = (inode.mode & 0o170000) == 0o100000
                                    print(f"  Inode {key.objectid}: size={inode.size}, nlink={inode.nlink}, mode={oct(inode.mode)} (REG={is_reg})")
                                    
                                    if inode.nlink == 0:
                                        stats['inodes_deleted'] += 1
                                    else:
                                        stats['inodes_existing'] += 1
                                        
                             elif key.type == 108: # EXTENT_DATA
                                 stats['extents_found'] += 1
                                 print(f"  Inode {key.objectid}: Found EXTENT_DATA")

                             elif key.type == 228: # CHUNK_ITEM
                                 stats['chunks_found'] += 1
                                 
                except Exception:
                    pass
                    
            current_offset += len(chunk)

        print("\n--- Scan Results ---")
        print(f"Leaves Found: {stats['leaves_found']}")
        print(f"Chunks Found: {stats['chunks_found']}")
        print("Leaves by Tree ID:")
        for owner, count in stats['by_owner'].items():
            name = "UNKNOWN"
            if owner == 1: name = "ROOT_TREE"
            elif owner == 2: name = "EXTENT_TREE"
            elif owner == 3: name = "CHUNK_TREE"
            elif owner == 5: name = "FS_TREE"
            print(f"  ID {owner} ({name}): {count}")
            
        print(f"\nInodes Found: {stats['inodes_found']}")
        print(f"  Existing (nlink>0): {stats['inodes_existing']}")
        print(f"  Deleted  (nlink=0): {stats['inodes_deleted']}")
        
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: sudo python3 debug_btrfs.py <image_path>")
    else:
        debug_scan(sys.argv[1])
