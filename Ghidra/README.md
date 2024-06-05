# Ghidra Opcode Extraction Scripts

This repository contains two scripts that work together to extract opcodes from binary files using the Ghidra headless analyzer.

## Scripts

1. `get_opcode.sh`: This Bash script automates the process of running the Ghidra headless analyzer with the `ghidra_opcode_script.py` script. It takes the path to the Ghidra headless analyzer and the directory containing the program samples as input parameters. The script sets up the necessary directories, splits the input program samples into multiple subfolders based on the number of available CPUs, runs the Ghidra headless analyzer with the specified parameters for each subfolder in parallel using GNU Parallel, and measures the total execution time.

2. `ghidra_opcode_script.py`: This Python script is designed to be run within the Ghidra headless analyzer. It extracts the opcodes and corresponding addresses from the disassembled code of the input binary files. The script writes the extracted information to a CSV file in the specified output directory.

## Prerequisites

- Ghidra: Make sure you have Ghidra installed on your system. The `ghidra_headless_path` parameter in the `get_opcode.sh` script should point to the path of the Ghidra headless analyzer executable.
- GNU Parallel: The script uses GNU Parallel to process the subfolders in parallel. Make sure you have GNU Parallel installed on your system.

## Usage

1. Clone this repository to your local machine.

2. Open a terminal and navigate to the directory where the scripts are located.

3. Run the `get_opcode.sh` script with the following command:

   ```bash
   ./get_opcode.sh <ghidra_headless_path> <program_folder>
   ```

   Replace `<ghidra_headless_path>` with the path to the Ghidra headless analyzer executable and `<program_folder>` with the path to the directory containing the program samples you want to analyze.

4. The script will create an output directory named `<program_folder>_disassemble` in the current directory. Inside this directory, you will find the following:
   - `ghidra_projects`: Contains the Ghidra project files for each analyzed program sample.
   - `results`: Contains the CSV files with the extracted opcodes and addresses for each analyzed program sample.
   - `split_folders`: Contains the subfolders created by splitting the input program samples based on the number of available CPUs.
   - `<program_folder>_disassemble_time.txt`: A text file containing the total execution time of the analysis.

## Notes

- The `ghidra_opcode_script.py` script is designed to be run within the Ghidra headless analyzer and should not be executed directly.
- The script uses the `logging` module to log any errors that occur during the execution. The log file is saved in the output directory with the name `extract_operation_code.log`.
- The script measures the execution time for each analyzed program sample and appends it to the `execution_times.log` file in the output directory.

## License

This project is licensed under the [MIT License](https://github.com/louiskyee/OpCodeReverseTool/blob/main/LICENSE).

Feel free to contribute to this project by creating issues or submitting pull requests.
