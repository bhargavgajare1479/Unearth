# 🔍 Unearth - Advanced Forensic Data Recovery Tool

![Python Version](https://img.shields.io/badge/python-3.11+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-active-success.svg)

**Unearth** is a professional-grade forensic data recovery and analysis tool designed for digital forensics investigators, incident responders, and cybersecurity professionals. It specializes in recovering deleted files from **Btrfs** and **XFS** file systems using a combination of metadata analysis and file carving techniques.

## Features

### A. Core Recovery Engine (Technical Foundation)

These features ensure maximum data retrieval and maintain the forensic integrity of all recovered files.

- **Deleted File Recovery:** Employs a **dual-pronged approach** combining metadata analysis (parsing Btrfs/XFS B-trees for unlinked data) and signature-based **file carving** to guarantee the highest recovery rates, even when file system structures are lost.
- **Multi-Format Support:** Leverages a robust signature database to identify and reconstruct **16+ diverse file types** (documents, images, audio, video, archives), maximizing the scope of recoverable evidence.
- **Metadata Extraction:** Meticulously extracts and preserves critical file data (timestamps, inode numbers, permissions) and embedded information (EXIF camera data, PDF author info, Office document properties) essential for building a **forensic timeline**.
- **File Integrity Verification:** Computes a unique **SHA256 hash** for every recovered file. This digital fingerprint serves to verify authenticity and maintain the crucial **chain of custody**.
- **File Type Detection (Magic Numbers):** Performs rapid classification using file header signatures to ensure accurate identification, even if file extensions are lost or tampered with.

### B. Usability and Forensics Suite (Analysis and Workflow)

These features streamline the investigation process, making the final evidence review professional and auditable.

- **Interactive Timeline:** Aggregates all recovered file timestamps into an **interactive, chronological visualization**. This allows investigators to quickly identify patterns of activity and reconstruct the sequence of events.
- **Keyword Search:** Provides a powerful investigative capability to perform **targeted searches** for terms (e.g., "password," "confidential") within the content of all recovered text files.
- **Forensic Report Generator:** Automatically compiles all key findings—file lists, metadata, integrity hashes, and search results—into a professional, exportable **PDF or CSV report**, creating a complete and auditable legal record.

### User Interfaces
- **Command-Line Interface (CLI)**: Rich terminal interface with progress bars
- **Graphical User Interface (GUI)**: PyQt6-based desktop application
- **Python API**: Programmatic access for automation

## Architecture

```
unearth/
├── run.py                      # Main launcher (CLI/GUI interactive entrypoint)
│
├── src/
│   ├── core/                    # Core recovery engines
│   │   ├── btrfs_parser.py     # Btrfs filesystem parser
│   │   ├── xfs_parser.py       # XFS filesystem parser
│   │   ├── file_carver.py      # File carving engine
│   │   ├── metadata_extractor.py  # EXIF/PDF/Office metadata extraction
│   │   └── partition_parser.py # Partition detection
│   │
│   ├── ui/                      # User interfaces
│   │   ├── cli.py              # Command-line interface
│   │   ├── gui.py              # Desktop GUI (PyQt6)
│   │   └── report_generator.py # Report generation
│   │
│   ├── app.py                   # Main application controller
│   └── utils.py                 # Utility functions
│
├── data/
│   ├── test_images/             # Test disk images
│   └── recovered_output/        # Recovery output directory
│
├── logs/                        # Application logs
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
    file \
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

## File System Support

### Btrfs (B-Tree File System)

**Support Level:** Full

**Capabilities:**
- Superblock and tree root parsing
- COW (Copy-On-Write) tree traversal
- FSID-based leaf node validation
- Extent-based file data recovery
- CRC32C checksum verification
- File carving for deleted content

**Known Limitations:**
- Compressed extents (zlib, lzo, zstd) not yet decompressed
- RAID configurations may need special handling
- Deleted file metadata has narrow recovery window due to COW architecture

**Recovery Approach:** File carving (primary), metadata parsing (secondary)

### XFS (Extended File System)

**Support Level:** Planned

**Capabilities:**
- Superblock parsing
- AG (Allocation Group) analysis
- Inode recovery

**Note:** XFS support is currently under development.

## Creating Test Disk Images

```bash
# Create Btrfs test image
dd if=/dev/zero of=test_btrfs.img bs=1M count=100
mkfs.btrfs test_btrfs.img
mkdir /mnt/test
mount -o loop test_btrfs.img /mnt/test
# Add test files, then delete some
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

- **Btrfs Developers** - For COW filesystem design and documentation
- **XFS Development Team** - For filesystem documentation
- **Sleuth Kit Team** - For forensic tool inspiration
- **Open Source Community** - For amazing tools and libraries

## Platform Support

### Linux (Primary Platform)

- Native Btrfs/XFS support
- Raw disk access with proper permissions
- Better performance for I/O operations
- Most forensic tools available

**Setup:**
```bash
# Grant user access to disk devices (use carefully!)
sudo usermod -aG disk $USER
```

## Support the Project

Unearth is free and open-source. If you find it useful:

- **Star** the repository
- **Report bugs** and suggest features
- **Contribute** code or documentation
- **Share** with your network

## Final Words

Thank you for choosing **Unearth** for your forensic investigations! 

We've built this tool with a passion for digital forensics and a commitment to the open-source community. Whether you're investigating cybercrime, recovering lost data, or conducting security research, we hope Unearth serves you well.

**Remember**: With great power comes great responsibility. Always use this tool ethically and legally.

**Happy Investigating!**

*Made with ❤️ by the Unearth Development Team*

*Last Updated: February 2026*