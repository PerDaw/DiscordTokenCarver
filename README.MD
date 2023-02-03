# DTC - Discord token carver

Carves tokens for discord.\
Since the tokens are carved. You can set the `--validate` argument to validate the token.\
These tokens can be used to authenticate on Discord's backend.\
This project is used for educational purposes only and is not meant to be used for illegal things!

## Usage
`pip install -r requirements.txt`

### Carving from host computer (Roaming directory)
Without validation: `python discord_token_stealer.py`\

With validation: `python discord_token_stealer.py --validate`

### Stealing from given directory
Without validation: `python discord_token_stealer.py --directory <dir-path>\`

With validation: `python discord_token_stealer.py --directory <dir-path> --validate`

## Use Cases
May be used to create a backup of discord messages.

## Info
Carving works well for multiple browsers including Chrome, Opera, etc.\
Also works with multiple Discord clients like Discord, Lightcord, Discord Canary, Discord Portable.\
May not work with Firefox. Firefox does not store the token clearly.\
False positives are normal, be sure to validate!

Enjoy!
