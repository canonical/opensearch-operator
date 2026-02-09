# US-Only Spelling Dictionary

This directory contains the US-only spelling dictionary files used by Vale for spell checking.

## Dictionary Information

**Source**: SCOWL-based Hunspell en_US dictionary  
**Origin**: https://wordlist.sourceforge.net/  
**Version**: 2020.12.07  
**License**: Multiple FOSS licenses (MIT-like and public domain)  

## Files

- `en_US.dic` - Word list (49,569 entries)
- `en_US.aff` - Affix rules for word forms

## Why US-Only?

This dictionary contains **only US English spellings**. UK variants (colour, centre, organise, analyse, behaviour) are NOT included and will be flagged as spelling errors by Vale.

## Verification

Tested UK spellings (not in dictionary):
- colour, centre, organise, analyse, behaviour, licence, defence

Tested US spellings (in dictionary):
- color, center, organize, analyze, behavior, license, defense

## Source Details

The SCOWL (Spell Checker Oriented Word Lists) project provides high-quality, well-maintained spelling dictionaries. This en_US variant was specifically chosen because it excludes British English spellings.

Downloaded from: https://sourceforge.net/projects/wordlist/files/speller/2020.12.07/hunspell-en_US-2020.12.07.zip
