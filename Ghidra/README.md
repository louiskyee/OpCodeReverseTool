# Ghidra Opcode Extraction Scripts

This repository contains two scripts that work together to extract opcodes from binary files using the Ghidra headless analyzer.

## Scripts

1. `get_opcode.sh`: This Bash script automates the process of running the Ghidra headless analyzer with the `ghidra_opcode_script.py` script. It takes the path to the Ghidra headless analyzer and the directory containing the program samples as input parameters. The script sets up the necessary directories, runs the Ghidra headless analyzer with the specified parameters for each file in parallel using GNU Parallel, and measures the total execution time for each file.

2. `ghidra_opcode_script.py`: This Python script is designed to be run within the Ghidra headless analyzer. It extracts the opcodes, corresponding addresses, and section names from the disassembled code of the input binary files. The script writes the extracted information to a CSV file in the specified output directory.

## Prerequisites

- Ghidra: Make sure you have Ghidra installed on your system. The `ghidra_headless_path` parameter in the `get_opcode.sh` script should point to the path of the Ghidra headless analyzer executable.
- GNU Parallel: The script uses GNU Parallel to process the files in parallel. Make sure you have GNU Parallel installed on your system.

## Usage

1. Clone this repository to your local machine.

2. Open a terminal and navigate to the directory where the scripts are located.

3. Run the `get_opcode.sh` script with the following command:

   ```bash
   ./get_opcode.sh <ghidra_headless_path> <program_folder> [<output_dir>] [<timeout>]
   ```

   - `<ghidra_headless_path>`: Path to the Ghidra headless analyzer executable.
   - `<program_folder>`: Path to the directory containing the program samples you want to analyze.
   - `<output_dir>` (optional): Path to the output directory. Defaults to "./output" if not specified.
   - `<timeout>` (optional): Timeout in seconds for processing each file. Defaults to 600 seconds (10 minutes) if not specified.

4. The script will create an output directory (default or specified) containing the following:
   - `ghidra_projects`: Contains the temporary Ghidra project files for each analyzed program sample (removed after processing).
   - `results`: Contains subdirectories for each analyzed program sample, named after the program name. Each subdirectory contains a CSV file with the extracted opcodes, addresses, and section names.
   - `extraction.log`: A log file containing information about the extraction process, including execution times for each file and any errors encountered.
   - `timed_out_files.txt`: A list of files that timed out during processing.

## Output Format

The CSV file for each analyzed program will contain the following columns:
- `addr`: The address of the instruction.
- `opcode`: The opcode of the instruction.
- `section_name`: The name of the section containing the instruction.

## Logging

- The `extraction.log` file contains detailed information about the processing of each file, including:
  - Successful extractions with execution times
  - Error messages for files that failed to process or timed out
- The `timed_out_files.txt` file lists the names of any files that exceeded the specified timeout duration during processing.

## Notes

- The `ghidra_opcode_script.py` script is designed to be run within the Ghidra headless analyzer and should not be executed directly.
- Execution time for each file is measured in the `get_opcode.sh` script and includes the time taken for Ghidra's reverse analysis as well as the opcode extraction.
- After the analysis is complete, the temporary Ghidra project files are removed to clean up the output directory.

## License

This project is licensed under the MIT License. See the [LICENSE](https://github.com/louiskyee/OpCodeReverseTool/blob/main/LICENSE) file for details.

Feel free to contribute to this project by creating issues or submitting pull requests.