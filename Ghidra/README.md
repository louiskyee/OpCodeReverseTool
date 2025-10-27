# Opcode Extraction Tool

[English](README.md) | [繁體中文](README.zh-TW.md)

This Python tool is designed to extract address and opcode information from binary files using Ghidra and save the results as CSV files. Here's a detailed explanation of each part of the tool:

## Installation Requirements

Before using this tool, ensure that you have the following installed:

- **Ghidra**: A software reverse engineering framework developed by the NSA. Download from [Ghidra's official website](https://ghidra-sre.org/).
- **Python 3.x** with the following packages:
  - `pandas`: Used for processing and manipulating the extracted data.
  - `tqdm`: Used for displaying progress bars to track the processing progress.

You can install the required Python packages using the following command:

```bash
pip install pandas tqdm
```

## Usage

To use this tool, follow these steps:

1. Download the Python file `get_opcode.py` and `ghidra_opcode_script.py` to your local machine.

2. Ensure Ghidra is installed and note the path to the `analyzeHeadless` script (typically located in `<ghidra_install_dir>/support/analyzeHeadless`).

3. Open a terminal or command prompt and navigate to the directory where the tool is located.

4. Run the following command to use the tool:

   ```bash
   python get_opcode.py -d /path/to/binary/directory -g /path/to/ghidra/analyzeHeadless
   ```

   Replace `/path/to/binary/directory` with the path to the directory containing the binary files you want to process, and `/path/to/ghidra/analyzeHeadless` with the path to Ghidra's headless analyzer.

### Command-Line Arguments

- `-d, --directory` (required): Path to the binary directory containing the files to process.
- `-g, --ghidra` (required): Path to Ghidra headless analyzer (analyzeHeadless).
- `-o, --output` (optional): Path to the output directory. If not specified, defaults to `<binary_directory>_disassemble`.
- `-t, --timeout` (optional): Timeout duration in seconds for each file analysis (default: 600 seconds).

### Usage Examples

```bash
# Basic usage with default settings
python get_opcode.py -d /path/to/binary/directory -g ~/ghidra/support/analyzeHeadless

# Specify custom output directory
python get_opcode.py -d /path/to/binary/directory -g ~/ghidra/support/analyzeHeadless -o /path/to/output

# Set custom timeout (1200 seconds)
python get_opcode.py -d /path/to/binary/directory -g ~/ghidra/support/analyzeHeadless -t 1200

# Combine all options
python get_opcode.py -d /path/to/binary/directory -g ~/ghidra/support/analyzeHeadless -o /path/to/output -t 1200
```

4. The tool will start processing the binary files and save the extracted address and opcode information as CSV files. The progress will be displayed in the terminal.

5. Once the processing is complete, the extracted CSV files will be saved in the output directory. The output directory will contain the following:
   - `results` subdirectory: Contains the extracted CSV files for each binary file, organized into subdirectories based on the first two characters of the filename.
   - `extraction.log`: Log file recording the extraction process and any errors or warnings.
   - `timing.log`: Log file recording the execution time for each file processing.

## Features

- **Parallel Processing**: Utilizes multi-core CPUs (2x CPU count) to process multiple binary files simultaneously for faster extraction.
- **Ghidra Integration**: Leverages Ghidra's powerful disassembly capabilities with headless mode for automated processing.
- **No Auto-Analysis**: Uses `-noanalysis` flag to skip Ghidra's automatic analysis phase, focusing only on disassembly for faster processing.
- **Manual Disassembly**: Implements manual disassembly using `DisassembleCommand` for precise control over the extraction process.
- **Timeout Protection**: Built-in timeout mechanism using Linux `timeout` command to prevent hanging on problematic binaries.
- **Comprehensive Logging**: Separate logs for extraction process and timing information for analysis and debugging.
- **Error Handling**: Robust error handling for various edge cases including packed, damaged, or incomplete binaries.
- **Progress Tracking**: Real-time progress bar to monitor the extraction process.
- **Flexible Output**: Customizable output directory location.
- **Resource Cleanup**: Automatic cleanup of temporary Ghidra project files after processing each file.

## Code Explanation

Here's a detailed explanation of each part of the tool:

### `configure_logging` Function

This function is used to configure the logging settings. It takes the output directory path as a parameter and returns the `extraction_logger` object.

- `extraction_logger` is used to log errors during the extraction process.

The log file will be saved in the output directory. The function also clears existing handlers to prevent duplicate logging entries. Note that timing information is logged directly by `ghidra_opcode_script.py` during the Ghidra analysis phase.

### `extract_features` Function

This function extracts opcode information from binary files using Ghidra headless analyzer. It:
- Creates a temporary project folder for the current file
- Runs Ghidra headless analyzer with `-noanalysis` flag for faster processing
- Executes the `ghidra_opcode_script.py` post-script to extract opcodes
- Verifies that the CSV output file was generated successfully
- Cleans up the temporary project folder after processing

The function uses Linux `timeout` command to prevent hanging on problematic binaries, with a configurable timeout duration.

### `extraction` Function

This function is responsible for extracting address and opcode information from the specified binary file and saving the results as a CSV file. It takes the following parameters:

- `input_file_path`: The path to the target file.
- `output_csv_path`: The path for the output CSV file.
- `file_name`: The name of the target file.
- `extraction_logger`: The logger object for recording the extraction process.
- `output_dir`: Output directory path.
- `ghidra_headless_path`: Path to Ghidra headless analyzer.
- `timeout_seconds`: Maximum time allowed for file analysis.

The function performs the following steps:
1. Checks if the output file already exists (skips if it does)
2. Calls `extract_features` to run Ghidra and extract opcodes
3. Validates that extraction succeeded
4. Returns the execution time

If any errors occur during the extraction process, the error information will be logged using the `extraction_logger`. Errors are logged only once to avoid duplicate messages (e.g., timeout errors won't also log "no valid disassembly" messages).

### `ghidra_opcode_script.py`

This Ghidra Python script runs inside Ghidra's headless environment and performs the actual opcode extraction:

1. **Memory Block Analysis**: Iterates through all memory blocks in the program
2. **Manual Disassembly**: Uses `DisassembleCommand` to disassemble each memory block (required because of `-noanalysis` flag)
3. **Opcode Extraction**: Extracts address (as integer), opcode, and section name for each instruction
4. **Data Collection**: Collects all opcodes before creating the CSV file to ensure data validity
5. **CSV Generation**: Only creates the CSV file if valid opcodes were extracted
6. **Timing**: Records the execution time for performance analysis

The script handles errors such as missing memory blocks (potentially indicating packed, damaged, or incomplete binaries).

### `get_args` Function

This function is used to generate a list of arguments for parallel processing. It takes the following parameters:

- `binary_path`: The path to the directory containing the binary files.
- `output_path`: The path to the directory where the output CSV files will be saved.
- `extraction_logger`: The logger object for recording the extraction process.
- `ghidra_headless_path`: Path to Ghidra headless analyzer.
- `timeout_seconds`: Timeout duration in seconds.

The function iterates over all the files in the binary directory (files without extensions) and generates a tuple for each file, containing the input file path, output file path, file name, and other processing parameters. These tuples will be used as arguments for parallel processing.

### `parallel_process` Function

This function is used to process the extraction tasks in parallel. It takes a list of arguments, where each argument is a tuple containing the file information and processing parameters.

The function uses `ProcessPoolExecutor` with a maximum of 2x CPU count workers to create a process pool and submits the extraction tasks to the pool for parallel processing. The higher worker count (2x) is used because Ghidra spends most time waiting for I/O operations. The progress is displayed in the terminal using the `tqdm` package.

### `setup_output_directory` Function

This function is used to set up the output directory for storing the extracted files. It takes the input directory path and an optional custom output directory path as parameters and returns the path to the output directory.

If a custom output directory is specified, it will be used. Otherwise, the output directory will be named `<binary_directory>_disassemble` and located at the same level as the input directory. The function creates the output directory if it doesn't exist and also creates `results` and `ghidra_projects` subdirectories within it. The `ghidra_projects` directory is used for temporary Ghidra project files and is cleaned up automatically.

### `parse_arguments` Function

This function is used to parse the command-line arguments. It uses the `argparse` module to define and parse the arguments.

The tool accepts the following arguments:
- `-d` or `--directory` (required): Specifies the path to the directory containing the binary files.
- `-g` or `--ghidra` (required): Specifies the path to Ghidra headless analyzer.
- `-o` or `--output` (optional): Specifies the custom output directory path.
- `-t` or `--timeout` (optional): Specifies the timeout duration in seconds for file analysis (default: 600).

### `main` Function

This function is the main entry point of the tool and coordinates the entire extraction process. It performs the following steps:

1. Parse the command-line arguments to obtain the input directory path and Ghidra path.
2. Verify that the Ghidra headless analyzer exists at the specified path.
3. Set up the output directory for storing the extracted files.
4. Configure the logging settings.
5. Generate the list of arguments for parallel processing.
6. Perform parallel processing to extract address and opcode information and save the results as CSV files.
7. Clean up the temporary `ghidra_projects` directory.

## Conclusion

This Python tool provides a convenient way to extract address and opcode information from binary files using Ghidra's powerful disassembly engine and save the results as CSV files. It leverages Ghidra's headless mode for automated processing and uses parallel processing to speed up the extraction.

The tool requires Ghidra installation and Python packages `pandas` and `tqdm`, and can be used via the command-line interface. The extracted CSV files will be saved in a directory named `<binary_directory>_disassemble` located at the same level as the input directory. The output directory will contain the extracted CSV files organized into subdirectories, along with the extraction and timing log files.

By using this tool, you can easily analyze binary files and obtain valuable address and opcode information for further research and analysis.

## Reference

This tool utilizes Ghidra and several Python libraries compatible with Python 3.x. Below are the references and additional resources:

1. **Ghidra**: A software reverse engineering framework developed by the NSA. Official website and documentation: [Ghidra](https://ghidra-sre.org/).

2. **os, time, and shutil**: Built-in Python libraries for operating system interactions, time-related functions, and file operations. More details can be found in the official Python documentation: [Python Standard Library](https://docs.python.org/3/library/).

3. **subprocess**: Standard Python library for spawning new processes and interacting with external programs. Documentation available at: [Subprocess](https://docs.python.org/3/library/subprocess.html).

4. **logging and argparse**: Standard Python libraries for logging and parsing command-line arguments. Documentation available at: [Logging](https://docs.python.org/3/library/logging.html) and [Argparse](https://docs.python.org/3/library/argparse.html).

5. **pandas**: A powerful data manipulation and analysis library for Python. Official documentation and user guide: [Pandas Documentation](https://pandas.pydata.org/).

6. **tqdm**: A library for adding progress meters to Python loops. Repository and documentation: [tqdm GitHub](https://github.com/tqdm/tqdm).

7. **concurrent.futures**: Python library for parallel execution. Documentation available at: [Concurrent.futures](https://docs.python.org/3/library/concurrent.futures.html).

8. **Ghidra Python API**: Documentation for Ghidra's Python scripting capabilities, including `DisassembleCommand` and other APIs used in this tool: [Ghidra API](https://ghidra.re/ghidra_docs/api/).

These references provide a foundation for understanding the tools and libraries used in the development of this opcode extraction tool.
