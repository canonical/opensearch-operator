#!/usr/bin/env python3
"""
Download and install US-only Hunspell dictionary for Vale spell checking.

This script downloads the SCOWL-based en_US dictionary from wordlist.sourceforge.net,
which contains only US English spellings (no UK variants like "colour", "centre", etc.).

Source: SCOWL (Spell Checker Oriented Word Lists) - https://wordlist.sourceforge.net/
License: Multiple licenses (mostly MIT-like and public domain)
"""

import os
import shutil
import subprocess
import tempfile
import sys
import logging
import argparse
import zipfile
from urllib.request import urlretrieve

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

SPHINX_DIR = os.path.join(os.getcwd(), ".sphinx")
DICT_DIR = os.path.join(SPHINX_DIR, "styles/config/dictionaries")

# SCOWL-based US-only dictionary from wordlist.sourceforge.net
DICT_VERSION = "2020.12.07"
DICT_URL = f"https://sourceforge.net/projects/wordlist/files/speller/{DICT_VERSION}/hunspell-en_US-{DICT_VERSION}.zip/download"
DICT_FILES = ["en_US.dic", "en_US.aff"]


def download_and_install_dict(overwrite=False):
    """
    Download US-only Hunspell dictionary and install it to the dictionaries directory.
    
    Args:
        overwrite: boolean flag to overwrite existing dictionary files
    
    Returns:
        bool: True if successful, False otherwise
    """
    
    # Create dictionaries directory if it doesn't exist
    os.makedirs(DICT_DIR, exist_ok=True)
    
    # Check if dictionary already exists
    dict_file = os.path.join(DICT_DIR, "en_US.dic")
    aff_file = os.path.join(DICT_DIR, "en_US.aff")
    
    if os.path.exists(dict_file) and os.path.exists(aff_file) and not overwrite:
        logging.info("Dictionary files already exist. Use --overwrite to replace them.")
        return True
    
    # Create temporary directory for download
    temp_dir = tempfile.mkdtemp()
    zip_path = os.path.join(temp_dir, "hunspell-en_US.zip")
    
    try:
        # Download the dictionary zip file
        logging.info("Downloading US-only dictionary from: %s", DICT_URL)
        urlretrieve(DICT_URL, zip_path)
        logging.info("Download complete")
        
        # Extract the zip file
        logging.info("Extracting dictionary files...")
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(temp_dir)
        
        # Copy dictionary files to destination
        for dict_file_name in DICT_FILES:
            source_path = os.path.join(temp_dir, dict_file_name)
            dest_path = os.path.join(DICT_DIR, dict_file_name)
            
            if not os.path.exists(source_path):
                logging.error("Expected file not found in archive: %s", dict_file_name)
                return False
            
            logging.info("Installing %s to %s", dict_file_name, dest_path)
            shutil.copy2(source_path, dest_path)
        
        logging.info("Dictionary installation complete")
        logging.info("Location: %s", DICT_DIR)
        
        # Verify the dictionary is US-only
        verify_us_only_dict(dict_file)
        
        return True
        
    except Exception as e:
        logging.error("Failed to download/install dictionary: %s", e)
        return False
        
    finally:
        # Clean up temporary directory
        if os.path.exists(temp_dir):
            logging.debug("Cleaning up temporary directory: %s", temp_dir)
            shutil.rmtree(temp_dir)


def verify_us_only_dict(dict_path):
    """
    Verify that the dictionary contains US spellings but not UK spellings.
    
    Args:
        dict_path: Path to the dictionary file
    """
    uk_spellings = ['colour', 'centre', 'organise', 'analyse/', 'behaviour']
    us_spellings = ['color', 'center', 'organize', 'analyze', 'behavior']
    
    logging.info("Verifying dictionary is US-only...")
    
    try:
        with open(dict_path, 'r', encoding='utf-8') as f:
            content = f.read()
            
            # Check for UK spellings (should not be present)
            # Use word boundaries to avoid false positives like 'analyses'
            uk_found = [word for word in uk_spellings if f'\n{word}' in content or content.startswith(word)]
            if uk_found:
                logging.warning("Warning: Found UK spellings in dictionary: %s", uk_found)
            else:
                logging.info("✓ No UK spellings found (as expected)")
            
            # Check for US spellings (should be present)
            us_found = [word for word in us_spellings if f'\n{word}' in content or content.startswith(word)]
            if us_found:
                logging.info("✓ US spellings verified: %s", us_found[:3])
            else:
                logging.warning("Warning: US spellings not found in dictionary")
                
    except Exception as e:
        logging.error("Failed to verify dictionary: %s", e)


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Download and install US-only Hunspell dictionary for Vale"
    )
    parser.add_argument(
        "--overwrite", 
        action="store_true", 
        help="Overwrite existing dictionary files"
    )
    return parser.parse_args()


def main():
    args = parse_arguments()
    
    if not download_and_install_dict(overwrite=args.overwrite):
        logging.error("Failed to install US-only dictionary")
        return 1
    
    logging.info("Success! Vale will now use US-only spelling dictionary.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
