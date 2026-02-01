import os
import subprocess
import time
from pathlib import Path

def create_btrfs_test_image(filename="test_btrfs.img", size_mb=200):
    """Create a Btrfs test image with some deleted files."""
    print(f"Creating {filename} ({size_mb}MB)...")
    
    # 1. Create file
    subprocess.run(["dd", "if=/dev/zero", f"of={filename}", "bs=1M", f"count={size_mb}", "status=none"], check=True)
    
    # 2. Format as Btrfs
    subprocess.run(["mkfs.btrfs", "-f", filename], check=True, stdout=subprocess.DEVNULL)
    
    # 3. Mount (requires sudo)
    mount_point = Path("mnt_test")
    mount_point.mkdir(exist_ok=True)
    
    try:
        print("Mounting image (requires sudo)...")
        subprocess.run(["sudo", "mount", filename, str(mount_point)], check=True)
        
        # 4. Create files
        print("Creating files...")
        (mount_point / "existing_file.txt").write_text("This is an existing file.")
        
        # Create files to delete
        for i in range(5):
            p = mount_point / f"deleted_file_{i}.txt"
            p.write_text(f"This is the content of deleted file {i}. " * 50)
            
        # Sync to disk
        subprocess.run(["sync"], check=True)
        
        # 5. Delete files
        print("Deleting files...")
        for i in range(5):
            (mount_point / f"deleted_file_{i}.txt").unlink()
            
        # Sync again
        subprocess.run(["sync"], check=True)
        
    finally:
        # 6. Unmount
        if os.path.ismount(mount_point):
            print("Unmounting...")
            subprocess.run(["sudo", "umount", str(mount_point)], check=True)
        mount_point.rmdir()
        
    print(f"\nDone! Created {filename} with 5 deleted files.")
    print(f"You can now load {os.path.abspath(filename)} in Unearth.")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Note: This script requires sudo to mount/unmount the test image.")
        print("Relaunching with sudo...")
        subprocess.run(["sudo", "python3", __file__])
    else:
        create_btrfs_test_image()
