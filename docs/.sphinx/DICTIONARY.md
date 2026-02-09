# US-Only Spelling Dictionary Configuration

## Overview

This repository uses a **US-only spelling dictionary** for Vale spell checking to ensure consistent American English spelling throughout the documentation. UK spellings (such as "colour", "centre", "organise") will be flagged as errors.

## Dictionary Source

**Dictionary**: SCOWL-based Hunspell en_US dictionary  
**Source**: [wordlist.sourceforge.net](https://wordlist.sourceforge.net/)  
**Version**: 2020.12.07  
**License**: Multiple FOSS licenses (MIT-like and public domain)  
**Location in repo**: `.sphinx/dictionaries/`

This dictionary is based on SCOWL (Spell Checker Oriented Word Lists), a well-maintained and widely-used open-source project that provides high-quality spelling dictionaries.

## How It Works

The spelling check is performed by Vale using the Hunspell dictionary format:
- **Source files**: `.sphinx/dictionaries/en_US.dic` and `.sphinx/dictionaries/en_US.aff` (stored in repository)
- **Deployed to**: `.sphinx/styles/config/dictionaries/` (copied during vale-install)

The US-only dictionary files are stored in the repository and copied to the Vale configuration directory when running `make spelling` or any target that depends on `vale-install`.

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

The dictionary has been verified to contain:
- ✓ US spellings: color, center, organize, analyze, behavior, license, defense
- ✗ UK spellings NOT present: colour, centre, organise, analyse, behaviour, licence, defence

## Difference from Previous Setup

**Previous**: The dictionary came from the Canonical documentation style guide and contained **both US and UK spellings**, meaning UK variants were not flagged as errors.

**Current**: The dictionary is sourced from SCOWL and contains **only US spellings** (49,569 entries vs 81,536 in the mixed dictionary), ensuring consistent American English usage and flagging any UK spelling variants.

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

## Updating the Dictionary

The dictionary files are stored in the repository at `.sphinx/dictionaries/`. To update to a newer version:

1. Download the latest en_US dictionary from https://wordlist.sourceforge.net/
2. Replace the files in `.sphinx/dictionaries/`
3. Commit the updated dictionary files
