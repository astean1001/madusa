
# MADUSA

Android Demo Application Generator based on usage scenario.
## Installation

### Prerequisites

- [ACVTool](https://github.com/pilgun/acvtool)
- [APKTool](https://ibotpeaches.github.io/Apktool/)
- Python 2.7
- Android Debug Bridge
- Android Emulator

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

## Options

  - `-o` : Set output apk path
  - `--purge_res` : Purge unused resources
  - `--merge` : Merge drawables/mipmaps into medium resolution
  - `-p <float between 1.0 to 0>` : Set APK size limit in percent
  - `-b` : Set APK size limit in byte
  - `--clean` : Clean up temporary generated files
  - `--no_ilp` : Generate APK without code ILP (Cov version)


## To Reproduce the Paper Results

  1. Get dataset from [zenodo](https://zenodo.org/record/7272254)
  2. Turn on Virtual Device Manager, create a device. API level of virtual device should be below 29. 
  3. Instrument original applications in `/original_apps` directory of dataset with [ACVTool](https://github.com/pilgun/acvtool).
     - `acv instrument <apk_path>`
     - The instrumented app appears in the same directory of original app.
  4. Install the instrumented app in emulator
     - `acv install <instrumented_app_path>`
  5. Start installed app to measure code coverage.
     - `acv start <package.name>`
  6. Interact with installed app refer to video in `/scenario` directory of dataset.
     - If video shows terminal with some command, type the same command in the video at first.
     - If you want to reproduce the result as similar as possible, you should follow just as video doing.
  7. Finalize testing by pressing Ctrl+C. 
  8. Generate the code coverage report after tesing an app
     - `acv report <package.name> -p <path>` 
  9. At `~/acvtool/acvtool_working_dir/report/<package.name>`, you can get ec_files and at `~/acvtool/acvtool_working_dir/metadata/<package.name>.pickle`, you can get pickle file
  10. Run MADUSA to generate reduced demo application
      - MADUSA will generate reduced apk at `~/madusa`

## License

Copyright © 2022 - Present Programming System Laboratory (PSL), Hanyang University. All rights reserved.    
This software is distributed under the term of the BSD license.

## Reference

Lee, Jaehyung, Cho, Hangyeol, & Lee, Woosuk. (2022). Artifact of MADUSA: Mobile Application Demo Generation based on Usage Scenarios (v1.0.0) [Data set]. Zenodo. https://doi.org/10.5281/zenodo.7272254

