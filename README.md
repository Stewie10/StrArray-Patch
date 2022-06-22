# StrArray-Patch
Adds more entries to the str_array files to add more text for button sounds, slide sounds, chainsliders sounds, slidertouch sounds, and modules

Slide sounds, chainsliders sounds, slidertouch sounds are all moved to just before the module text (the button text can't be moved cuz its the only one that uses a single byte for the entry start ID). So button sounds can only have a max of 63.
Modules can now add up to ID 2030. If there's a point where someone adds up to this much modules, I'll change it to allow more.
