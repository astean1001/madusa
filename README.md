
# MADUSA

Android Demo Application Generator based on usage scenario.]
## Installation

### Prerequisites

- [ACVTool](https://github.com/pilgun/acvtool)
- [APKTool](https://ibotpeaches.github.io/Apktool/)
- Python 2.7

### Installation

```bash
  pip install -e .
```
    
## Usage

  1. Instrument and get code coverage (pickle file and ec_file) with ACVTool ([ACVTool Guide](https://github.com/pilgun/acvtool#workflow))
  2. Provice code coverage info into madusa (`python madusa.py <apk file> <ec_files> <pickle file>`)

  ```bash
   python madusa.py <path_to_target_apk>/target.apk ~/acvtool/acvtool_working_dir/report/com.target.app/ec_files/ ~/acvtool/acvtool_working_dir/metadata/target.pickle
  ```

  3. Madusa will provide demo application.


## License

Copyright © 2022 - Present Programming System Laboratory (PSL), Hanyang University. All rights reserved.    
This software is distributed under the term of the BSD license.

## Reference

Experimental Artifact : https://drive.google.com/drive/folders/1CWIwmQVJWqlYqVNkJdDatp3y33ExS_7u?usp=sharing

