import sys
import os
import logging

# Add src to path
sys.path.insert(0, os.path.join(os.getcwd(), 'src'))

from core.file_carver import FileCarver

def debug_carve(image_path):
    print(f"--- Debugging File Carver on {image_path} ---")
    
    # Enable verbose logging to stdout
    logging.basicConfig(level=logging.INFO, format='%(message)s')
    
    try:
        # Check size first
        with open(image_path, 'rb') as f:
            f.seek(0, 2)
            size = f.tell()
            print(f"Device size detected: {size / (1024*1024):.2f} MB")
            
        print("Initializing carver...")
        carver = FileCarver(image_path, "debug_output")
        
        print("Starting carve...")
        # Only look for JPG/PNG for speed/test
        files = carver.carve(['jpg', 'png'])
        
        print(f"\n--- Results ---")
        print(f"Files found: {len(files)}")
        for f in files:
            print(f"  {f['name']} ({f['size']} bytes) at offset {f['offset']}")
            
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: sudo python3 debug_carver.py <image_path>")
    else:
        debug_carve(sys.argv[1])
