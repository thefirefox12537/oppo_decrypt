# oppo_decrypt
Oppo .ofp and Oneplus .ops Firmware decrypter
------------------------------------

<img alt="Preview UI" src="preview.png" width="75%"/>

* ofp_decrypt.pyw  : Decrypts oppo qc and mtk chipset based firmware with .ofp extension (oppo)
* opscrypto.py     : Decrypts and re-encrypts based firmware with .ops extension (oneplus)
* backdoor.py      : Enables hidden "readback" functionality


Installation:
-------------
- Install >= python 3.8 and pip3

In the console, run
```bash
pip3 install -r requirements.txt
```

Both Linux and Windows now supported, folks !

Usage:
-------- 
* Run UI and extract oppo ofp file:

Click ```ofp_decrypt.pyw``` file, or
```
python3 ofp_decrypt.pyw
```

* Extract oneplus ops file:

```
python3 opscrypto.py decrypt [myops.ops]
```
File will be in the extract subdirectory

* Repack oneplus ops file:

```
python3 opscrypto.py encrypt [path to extracted firmware]
```


* Enable readback mode (use admin command prompt under windoze):

```
python3 backdoor.py "MsmDownloadTool V4.0.exe"'
```

* Merge super images:

The .ofp may contain super firmware from multiple carriers, check the super_map.csv.txt outside .ofp first.

```
sudo apt install simg2img # If you have already installed, skip this step.
simg2img [super.0.xxxxxxxx.img] [super.1.xxxxxxxx.img] [super.1.xxxxxxxx.img] [filename to merge] # All split super imgs must be the same carrier
```

License:
-------- 
Share, modify and use as you like, but refer the original author !
And if you like my work, please donate :)
