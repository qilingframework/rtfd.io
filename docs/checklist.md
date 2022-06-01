---
title: List of Checklists
---

## Release TAG

- Checkout rootfs
```
    - cd examples/rootfs
    - git pull origin master
```

- Make sure version development status in setup.py is correct
```
    - __version__ = "1.[x].[x]"
    - 'Development Status :: 5 - Production/Stable'
```

- Update ChangeLog    
- commit and push into dev
- merge dev into master, via github and make sure pass CI test

- Tag now
```bash
git checkout master
git pull
git tag 1.[x].[x]
git push origin --tags
```

- Check for new Pypi package @ https://pypi.org/project/qiling
- Check pip3 update command
```bash
pip3 install qiling --upgrade
```

- Sync dev with latest master
```
git checkout dev
git merge master
```

-  Change development status in setup.py to 
```
'Development Status :: 3 - Beta'
```

- Update version and add in dev 
```
__version__ = "X.X.X" + "-dev"
```

- Update changelog and add section for next Update
- commit and push
- Done

## Adding New Arch (WIP)
- Instrumentation

## Adding New OS (WIP)
- Test for hello asm, dynamic and static 
- set_api() test


