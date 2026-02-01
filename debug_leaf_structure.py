#!/usr/bin/env python3
"""
Debug script to examine Btrfs leaf structure and verify offset calculation.
"""
import sys
import struct
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

# Btrfs constants
BTRFS_MAGIC = b'_BHRfS_M'
BTRFS_SUPERBLOCK_OFFSET = 65536  # 64KB

def hexdump(data, prefix=""):
    """Print hex dump of data"""
    for i in range(0, len(data), 16):
        hex_part = ' '.join(f'{b:02x}' for b in data[i:i+16])
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[i:i+16])
        print(f"{prefix}{i:04x}: {hex_part:<48} {ascii_part}")

def read_superblock(f):
    """Read and parse superblock"""
    f.seek(BTRFS_SUPERBLOCK_OFFSET)
    data = f.read(4096)
    
    # Check magic at offset 64
    magic = data[64:72]
    if magic != BTRFS_MAGIC:
        return None
    
    # Parse relevant fields
    fsid = data[32:48]
    nodesize = struct.unpack('<I', data[96:100])[0]
    sectorsize = struct.unpack('<I', data[100:104])[0]
    total_bytes = struct.unpack('<Q', data[104:112])[0]
    
    return {
        'fsid': fsid,
        'nodesize': nodesize,
        'sectorsize': sectorsize,
        'total_bytes': total_bytes
    }

def find_and_parse_leaf(f, fsid, nodesize, max_scan=10*1024*1024):
    """Find a leaf node and parse its structure"""
    print(f"\nScanning for leaf nodes (up to {max_scan//1024//1024}MB)...")
    
    f.seek(0)
    offset = 0
    leaves_found = 0
    
    while offset < max_scan:
        f.seek(offset)
        block = f.read(nodesize)
        if len(block) < nodesize:
            break
        
        # Check FSID at offset 32
        if block[32:48] == fsid:
            # Parse header
            # nritems at offset 96, level at offset 100
            nritems = struct.unpack('<I', block[96:100])[0]
            level = block[100]
            
            if level == 0 and nritems > 0 and nritems < 200:  # Leaf node
                leaves_found += 1
                print(f"\n=== Found leaf at offset {offset} ===")
                print(f"nritems: {nritems}, level: {level}")
                
                # Parse first few items
                item_offset = 101  # After header
                
                print("\nItem headers:")
                for i in range(min(5, nritems)):
                    if item_offset + 25 > len(block):
                        break
                    
                    # Parse key (17 bytes)
                    objectid = struct.unpack('<Q', block[item_offset:item_offset+8])[0]
                    item_type = block[item_offset+8]
                    key_offset = struct.unpack('<Q', block[item_offset+9:item_offset+17])[0]
                    
                    # Parse item info (8 bytes)
                    data_offset = struct.unpack('<I', block[item_offset+17:item_offset+21])[0]
                    data_size = struct.unpack('<I', block[item_offset+21:item_offset+25])[0]
                    
                    print(f"  Item {i}: key=({objectid}, {item_type}, {key_offset})")
                    print(f"          data_offset={data_offset}, data_size={data_size}")
                    
                    # Show raw bytes at data_offset
                    if data_offset < nodesize and data_offset + data_size <= nodesize and data_size > 0:
                        data = block[data_offset:data_offset + min(32, data_size)]
                        print(f"          data at offset {data_offset}: {data[:16].hex()}")
                        
                        # If it's an INODE_ITEM (type 1), parse it
                        if item_type == 1 and data_size >= 160:
                            generation = struct.unpack('<Q', data[0:8])[0]
                            transid = struct.unpack('<Q', data[8:16])[0]
                            size = struct.unpack('<Q', data[16:24])[0]
                            nbytes = struct.unpack('<Q', data[24:32])[0]
                            nlink = struct.unpack('<I', block[data_offset+32:data_offset+36])[0]
                            print(f"          INODE: size={size}, nlink={nlink}, gen={generation}")
                    
                    item_offset += 25
                
                if leaves_found >= 3:
                    break
        
        offset += 4096  # Scan in sector-sized steps
    
    print(f"\nFound {leaves_found} leaf nodes")

def main():
    if len(sys.argv) < 2:
        print("Usage: python debug_leaf_structure.py <btrfs_image_or_device>")
        sys.exit(1)
    
    path = sys.argv[1]
    print(f"Examining: {path}")
    
    with open(path, 'rb') as f:
        sb = read_superblock(f)
        if not sb:
            print("Not a valid Btrfs filesystem")
            sys.exit(1)
        
        print(f"Superblock found:")
        print(f"  FSID: {sb['fsid'].hex()}")
        print(f"  Nodesize: {sb['nodesize']}")
        print(f"  Sectorsize: {sb['sectorsize']}")
        print(f"  Total bytes: {sb['total_bytes']}")
        
        find_and_parse_leaf(f, sb['fsid'], sb['nodesize'])

if __name__ == "__main__":
    main()
