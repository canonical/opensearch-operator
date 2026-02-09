# US-Only Spelling Dictionary Configuration

## Overview

This repository uses a **US-only spelling dictionary** for Vale spell checking to ensure consistent American English spelling throughout the documentation. UK spellings (such as "colour", "centre", "organise") will be flagged as errors.

## Dictionary Source

**Dictionary**: SCOWL-based Hunspell en_US dictionary  
**Source**: [wordlist.sourceforge.net](https://wordlist.sourceforge.net/)  
**Version**: 2020.12.07  
**License**: Multiple FOSS licenses (MIT-like and public domain)

This dictionary is based on SCOWL (Spell Checker Oriented Word Lists), a well-maintained and widely-used open-source project that provides high-quality spelling dictionaries.

## How It Works

The spelling check is performed by Vale using the Hunspell dictionary format:
- **Dictionary file**: `.sphinx/styles/config/dictionaries/en_US.dic` (word list)
- **Affix file**: `.sphinx/styles/config/dictionaries/en_US.aff` (rules for word forms)

The US-only dictionary is automatically downloaded and installed by the `vale-install` target in the Makefile.

## Running Spell Check

```bash
# Run spell check on all files
make spelling

# Run spell check on specific files
make spelling TARGET=docs/tutorial/*.md
```

## Custom Wordlist

Project-specific terms and proper nouns can be added to `.custom_wordlist.txt` at the root of the docs directory. These words will be accepted in addition to the US dictionary.

## Verification

The dictionary installation script verifies that:
- ✓ US spellings are present (color, center, organize, analyze, behavior)
- ✗ UK spellings are NOT present (colour, centre, organise, analyse, behaviour)

## Manual Dictionary Update

To manually update or reinstall the dictionary:

```bash
cd docs
python3 .sphinx/get_us_only_dict.py --overwrite
```

## Difference from Previous Setup

**Previous**: The dictionary came from the Canonical documentation style guide and contained **both US and UK spellings**, meaning UK variants were not flagged as errors.

**Current**: The dictionary is sourced from SCOWL and contains **only US spellings**, ensuring consistent American English usage and flagging any UK spelling variants.

## Examples of What Will Be Caught

| UK Spelling (ERROR) | US Spelling (CORRECT) |
|---------------------|----------------------|
| colour              | color                |
| centre              | center               |
| organise            | organize             |
| analyse             | analyze              |
| behaviour           | behavior             |
| licence (noun)      | license              |
| defence             | defense              |
| programme           | program              |
