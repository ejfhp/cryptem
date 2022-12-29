# cryptem
A little tool to simply encrypt files.

I need a simple, short, easy command to encrypt all the content of a folder.  
Few options:
- password 
- delete clear files when encrypting, encrypted files when decrypting
- scan subfolders
- decrypt

___Note: password must be long exactly 16 chars.___
___Note: cryptem ignores files and folders that start with a dot (.).___

Prerequisites: 
- go
- git

To install, clone the git repo, cd into cmd/cryptem folder and run go install.

```
# EXAMPLES

# Encrypt all the files inside the folder 
> cryptem -folder . -password "1234567890123456" 

# Encrypt all the files inside the folder 
# delete the originals unencrypted
> cryptem -folder . -password "1234567890123456" -delete

# Encrypt all the files inside the folder
# delete the originals unencrypted
# do the same recursively inside all the subfolders
> cryptem -folder . -password "1234567890123456" -delete -recursive

# Encrypt all the files inside the folder
# overwrite existing .cryptem files
# delete the originals unencrypted
# do the same recursively inside all the subfolders
> cryptem -folder . -password "1234567890123456" -delete -recursive -overwrite

# Adding -decrypt the previous commands perform unencryption

```