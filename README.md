# 🔍 Unearth - Advanced Forensic Data Recovery Tool

![Python Version](https://img.shields.io/badge/python-3.11+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-active-success.svg)

**Unearth** is a professional-grade forensic data recovery and analysis tool designed for digital forensics investigators, incident responders, and cybersecurity professionals. It specializes in recovering deleted files from **XFS** and **Btrfs** file systems with advanced AI-powered analysis capabilities.

## Features

### A. Core Recovery Engine (Technical Foundation)

These features ensure maximum data retrieval and maintain the forensic integrity of all recovered files.

- **Deleted File Recovery:** Employs a **dual-pronged approach** combining metadata analysis (parsing XFS/Btrfs B-trees for unlinked data) and signature-based **file carving** to guarantee the highest recovery rates, even when file system structures are lost.
- **Multi-Format Support:** Leverages a robust database to identify and reconstruct **over 30 diverse file types** (documents, media, executables, etc.), maximizing the scope of recoverable evidence.
- **Metadata Extraction:** Meticulously extracts and preserves critical file data (timestamps, inode numbers, permissions) and embedded information (author, camera data) essential for building a **forensic timeline**.
- **File Integrity Verification:** Computes a unique **SHA256 hash** for every recovered file. This digital fingerprint serves to verify authenticity and maintain the crucial **chain of custody**.
- **File Type Detection (Magic Numbers):** Performs rapid classification using file header signatures to ensure accurate identification, even if file extensions are lost or tampered with.

### B. Usability and Forensics Suite (Analysis and Workflow)

These features streamline the investigation process, making the final evidence review professional and auditable.

- **Interactive Timeline:** Aggregates all recovered file timestamps into an **interactive, chronological visualization**. This allows investigators to quickly identify patterns of activity and reconstruct the sequence of events.
- **Keyword Search:** Provides a powerful investigative capability to perform **targeted searches** for terms (e.g., "password," "confidential") within the content of all recovered text files.
- **Forensic Report Generator:** Automatically compiles all key findings—file lists, metadata, integrity hashes, and search results—into a professional, exportable **PDF or CSV report**, creating a complete and auditable legal record.

### User Interfaces
- **Command-Line Interface (CLI)**: Rich terminal interface with progress bars
- **Graphical User Interface (GUI)**: PyQt5-based desktop application
- **Python API**: Programmatic access for automation

## Architecture

```
unearth/
├── run.py                      # Main launcher (CLI/GUI interactive entrypoint)
│
├── src/
│   ├── core/                    # Core recovery engines
│   │   ├── xfs_parser.py       # XFS filesystem parser
│   │   ├── btrfs_parser.py     # Btrfs filesystem parser
│   │   └── file_carver.py      # File carving engine
│   │
│   ├── analysis/                # AI analysis modules
│   │   ├── ai_classifier.py    # ML-based file classifier
│   │   ├── anomaly_detector.py # Anomaly detection engine
│   │   └── keyword_search.py   # NLP keyword search
│   │
│   ├── ui/                      # User interfaces
│   │   ├── cli.py              # Command-line interface
│   │   ├── gui.py              # Desktop GUI (PyQt5)
│   │   └── report_generator.py # Report generation
│   │
│   ├── app.py                   # Main application controller
│   └── utils.py                 # Utility functions
│
├── data/
│   ├── test_images/             # Test disk images
│   └── recovered_output/        # Recovery output directory
│
├── docs/                        # Documentation
│   ├── api.md
│   ├── user_guide.md
│   └── forensic_procedures.md
│
├── tests/                       # Test suite
│   ├── test_core.py
│   ├── test_analysis.py
│   └── test_e2e.py
│
├── config/                      # Configuration files
│   ├── config.json
│   └── signatures.yaml
│
├── logs/                        # Application logs
├── .gitignore
├── README.md
├── requirements.txt
├── setup.py
└── LICENSE
```

## Installation

### Prerequisites

- **Python**: 3.11 or higher
- **Operating System**: Linux
- **RAM**: Minimum 4GB (16GB recommended for large images)
- **Disk Space**: 10GB+ for disk images and recovered files
- **Permissions**: Root/Administrator access for raw disk access

### System Dependencies

#### Ubuntu / Debian based Linux distributions
```bash
sudo apt-get update
sudo apt-get install -y \
    python3.11 \
    python3-pip \
    python3-dev \
    libmagic-dev \
    build-essential \
    git
```

#### Arch Linux based Linux distributions
```bash
sudo pacman -Syu --noconfirm
sudo pacman -S --noconfirm \
    python \
    python-pip \
    python-setuptools \
    libmagic \
    base-devel \
    git
```

#### Fedora
```bash
sudo dnf update -y
sudo dnf install -y \
    python3.11 \
    python3-pip \
    python3-devel \
    file-devel \
    gcc \
    gcc-c++ \
    make \
    git
```

### Install Unearth

```bash
# Clone repository
git clone https://github.com/bhargavgajare1479/unearth.git
cd unearth

# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Launch Unearth
python run.py
```

### Optional: GPU Support

For faster AI analysis with TensorFlow GPU:

```bash
# Install CUDA Toolkit (NVIDIA GPUs only)
# Follow: https://developer.nvidia.com/cuda-downloads

# Install GPU-enabled TensorFlow
pip install tensorflow-gpu

# Verify GPU detection
python -c "import tensorflow as tf; print(tf.config.list_physical_devices('GPU'))"
```

## File System Support

### XFS (Extended File System)

**Support Level:** Full

**Capabilities:**
- Superblock parsing
- AG (Allocation Group) analysis
- Inode recovery (deleted and active)
- B+tree directory traversal
- Extended attributes extraction
- Journal analysis (for timeline reconstruction)

**Known Limitations:**
- Large filesystem support (>16TB) may require additional memory
- Heavily fragmented files may have partial recovery

**Recovery Success Rate:** ~85-95% (depending on overwrite)

### Btrfs (B-Tree File System)

**Support Level:** Full

**Capabilities:**
- Superblock and tree root parsing
- COW (Copy-On-Write) tree traversal
- Subvolume navigation
- Snapshot analysis
- Extent-based recovery
- Checksum verification

**Known Limitations:**
- Compressed extents require decompression (zlib, lzo, zstd)
- RAID configurations may need special handling

**Recovery Success Rate:** ~80-90% (COW helps recovery)

### Project Structure Guidelines

- **Modularity**: Each module should have a single responsibility
- **Documentation**: All functions must have docstrings
- **Type Hints**: Use type annotations for all function signatures
- **Error Handling**: Use specific exceptions, avoid bare `except:`
- **Logging**: Use structured logging, not print statements

### Creating Test Disk Images

```bash
# Create XFS test image
dd if=/dev/zero of=test_xfs.img bs=1M count=100
mkfs.xfs test_xfs.img
mkdir /mnt/test
mount -o loop test_xfs.img /mnt/test
# Add test files
umount /mnt/test

# Create Btrfs test image
dd if=/dev/zero of=test_btrfs.img bs=1M count=100
mkfs.btrfs test_btrfs.img
mount -o loop test_btrfs.img /mnt/test
# Add test files
umount /mnt/test
```

## Legal & Ethics

### Legal Disclaimer

**IMPORTANT:** This tool is designed for **legitimate forensic investigations** only.

**Authorized Uses:**
- Law enforcement investigations (with proper warrant)
- Corporate incident response (on company-owned systems)
- Personal data recovery (on your own devices)
- Security research (with proper authorization)
- Educational purposes (on test systems)

**Unauthorized Uses:**
- Accessing systems without permission
- Violating privacy laws
- Bypassing encryption without authorization
- Tampering with evidence
- Any illegal activity

### Ethical Guidelines

1. **Authorization**: Always obtain proper authorization before analysis
2. **Chain of Custody**: Maintain proper evidence handling procedures
3. **Privacy**: Respect data privacy laws (GDPR, CCPA, etc.)
4. **Documentation**: Keep detailed logs of all actions
5. **Integrity**: Never modify original evidence
6. **Transparency**: Clearly document methodology in reports

### Compliance

Unearth is designed to comply with:
- **ACPO Guidelines** (UK)
- **NIJ Guidelines** (USA)
- **ISO/IEC 27037:2012** (Digital Evidence)
- **GDPR** (Data Protection)

### Liability

The developers and contributors of Unearth:
- Provide this software "AS IS" without warranty
- Are not responsible for misuse
- Are not liable for data loss or damages
- Recommend professional forensic training

## Acknowledgments

- **XFS Development Team** - For filesystem documentation
- **Btrfs Developers** - For COW filesystem design
- **Sleuth Kit Team** - For forensic tool inspiration
- **TensorFlow/PyTorch Teams** - For ML frameworks
- **Open Source Community** - For amazing tools and libraries

## Notes for cross-platform support

### Currently we have selected Linux as the default platform due to following advantages

- Native XFS/Btrfs support
- Raw disk access with proper permissions
- Better performance for I/O operations
- Most forensic tools available

**Setup:**
```bash
# Install kernel headers (for some dependencies)
sudo apt-get install linux-headers-$(uname -r)

# Grant user access to disk devices (use carefully!)
sudo usermod -aG disk $USER
```

## Support the Project

Unearth is free and open-source. If you find it useful:

- **Star** the repository
- **Report bugs** and suggest features
- **Contribute** code or documentation
- **Share** with your network
- **Teach** others how to use it

## Final Words

Thank you for choosing **Unearth** for your forensic investigations! 

We've built this tool with a passion for digital forensics and a commitment to the open-source community. Whether you're investigating cybercrime, recovering lost data, or conducting security research, we hope Unearth serves you well.

**Remember**: With great power comes great responsibility. Always use this tool ethically and legally.

**Happy Investigating!**

*Made with ❤️ by the Unearth Development Team*

*Last Updated: October 3, 2025*