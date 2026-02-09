# US-Only Spelling Dictionary

This directory contains the US-only spelling dictionary files used by Vale for spell checking to ensure consistent American English spelling throughout the documentation.

## Dictionary Information

**Source**: SCOWL-based Hunspell en_US dictionary  
**Origin**: https://wordlist.sourceforge.net/  
**Version**: 2020.12.07  
**License**: Multiple FOSS licenses (MIT-like and public domain)  

## Files

- `en_US.dic` - Word list (49,569 entries)
- `en_US.aff` - Affix rules for word forms

## How It Works

The spelling check is performed by Vale using the Hunspell dictionary format. These source files are copied to `.sphinx/styles/config/dictionaries/` when running `make spelling` or any target that depends on `vale-install`.

## Running Spell Check

```bash
# Run spell check on all files
make spelling

# Run spell check on specific files
make spelling TARGET=docs/tutorial/*.md
```

## Custom Wordlist

Project-specific terms and proper nouns can be added to `.custom_wordlist.txt` at the root of the docs directory. These words will be accepted in addition to the US dictionary.

## Why US-Only?

This dictionary contains **only US English spellings**. UK variants (colour, centre, organise, analyse, behaviour) are NOT included and will be flagged as spelling errors by Vale.

## Verification

The dictionary has been verified to contain:
- ✓ US spellings: color, center, organize, analyze, behavior, license, defense
- ✗ UK spellings NOT present: colour, centre, organise, analyse, behaviour, licence, defence

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

## Difference from Previous Setup

**Previous**: The dictionary came from the Canonical documentation style guide and contained **both US and UK spellings** (81,536 entries), meaning UK variants were not flagged as errors.

**Current**: The dictionary is sourced from SCOWL and contains **only US spellings** (49,569 entries), ensuring consistent American English usage and flagging any UK spelling variants.

## Updating the Dictionary

To update to a newer version:

1. Download the latest en_US dictionary from https://wordlist.sourceforge.net/
2. Extract `en_US.dic` and `en_US.aff` from the archive
3. Replace the files in this directory
4. Commit the updated dictionary files

## Source Details

The SCOWL (Spell Checker Oriented Word Lists) project provides high-quality, well-maintained spelling dictionaries. This en_US variant was specifically chosen because it excludes British English spellings.

Downloaded from: https://sourceforge.net/projects/wordlist/files/speller/2020.12.07/hunspell-en_US-2020.12.07.zip
