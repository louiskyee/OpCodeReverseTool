# Opcode Extraction Tool

This Python tool is designed to extract address and opcode information from binary files and save the results as CSV files. Here's a detailed explanation of each part of the tool:

## Installation Requirements

Before using this tool, ensure that you have the following Python packages installed:

- `r2pipe`: Used for interacting with Radare2 to perform disassembly.
- `pandas`: Used for processing and manipulating the extracted data.
- `tqdm`: Used for displaying progress bars to track the processing progress.

You can install these packages using the following command:

```
pip install -r requirements.txt
```
or
```
pip install r2pipe pandas tqdm
```

## Usage

To use this tool, follow these steps:

1. Download the Python file `get_opcode.py` to your local machine.

2. Open a terminal or command prompt and navigate to the directory where the tool is located.

3. Run the following command to use the tool:

   ```
   python get_opcode.py -d /path/to/binary/directory
   ```

   Replace `/path/to/binary/directory` with the path to the directory containing the binary files you want to process.

4. The tool will start processing the binary files and save the extracted address and opcode information as CSV files. The progress will be displayed in the terminal.

5. Once the processing is complete, the extracted CSV files will be saved in a directory named `<binary_directory>_disassemble` located at the same level as the input directory, where `<binary_directory>` is the name of the input directory. The `<binary_directory>_disassemble` directory will contain the following:
   - `results` subdirectory: Contains the extracted CSV files for each binary file, maintaining the same relative path structure as the input directory.
   - `extraction.log`: Log file recording the extraction process and any errors or warnings.
   - `timing.log`: Log file recording the execution time for each file processing.

## Code Explanation

Here's a detailed explanation of each part of the tool:

### `configure_logging` Function

This function is used to configure the logging settings. It takes the output directory path as a parameter and returns two logger objects: `extraction_logger` and `timing_logger`.

- `extraction_logger` is used to log errors during the extraction process.
- `timing_logger` is used to log the execution time for each file processing.

The log files will be saved in the `<binary_directory>_disassemble` directory.

### `extraction` Function

This function is responsible for extracting address and opcode information from the specified binary file and saving the results as a CSV file. It takes the following parameters:

- `input_file_path`: The path to the target file.
- `output_csv_path`: The path for the output CSV file.
- `file_name`: The name of the target file.
- `extraction_logger`: The logger object for recording the extraction process.
- `timing_logger`: The logger object for recording the execution time.

The function uses Radare2 to perform disassembly and extracts the address and opcode information from the disassembly results. The extracted data is then saved as a CSV file.

If any errors occur during the extraction process, such as file not found or invalid disassembly results, the error information will be logged using the `extraction_logger`.

### `get_args` Function

This function is used to generate a list of arguments for parallel processing. It takes the following parameters:

- `binary_path`: The path to the directory containing the binary files.
- `output_path`: The path to the directory where the output CSV files will be saved.
- `extraction_logger`: The logger object for recording the extraction process.
- `timing_logger`: The logger object for recording the execution time.

The function iterates over all the files in the binary directory and generates a tuple for each file, containing the input file path, output file path, file name, and logger objects. These tuples will be used as arguments for parallel processing.

### `parallel_process` Function

This function is used to process the extraction tasks in parallel. It takes a list of arguments, where each argument is a tuple containing the input file path, output file path, file name, and logger objects.

The function uses `ProcessPoolExecutor` to create a process pool and submits the extraction tasks to the pool for parallel processing. The progress is displayed in the terminal using the `tqdm` package.

### `setup_output_directory` Function

This function is used to set up the output directory for storing the extracted files. It takes the input directory path as a parameter and returns the path to the output directory.

The output directory will be named `<binary_directory>_disassemble` and located at the same level as the input directory, where `<binary_directory>` is the name of the input directory. The function creates the `<binary_directory>_disassemble` directory if it doesn't exist and also creates a `results` subdirectory within it.

### `parse_arguments` Function

This function is used to parse the command-line arguments. It uses the `argparse` module to define and parse the arguments.

The tool accepts one required argument, `-d` or `--directory`, which specifies the path to the directory containing the binary files.

### `main` Function

This function is the main entry point of the tool and coordinates the entire extraction process. It performs the following steps:

1. Parse the command-line arguments to obtain the input directory path.
2. Set up the output directory for storing the extracted files.
3. Configure the logging settings, including the extraction log and timing log.
4. Generate the list of arguments for parallel processing.
5. Perform parallel processing to extract address and opcode information and save the results as CSV files.

## Conclusion

This Python tool provides a convenient way to extract address and opcode information from binary files and save the results as CSV files. It leverages Radare2 for disassembly and uses parallel processing to speed up the processing.

The tool requires the installation of the `r2pipe`, `pandas`, and `tqdm` packages and can be used via the command-line interface. The extracted CSV files will be saved in a directory named `<binary_directory>_disassemble` located at the same level as the input directory, where `<binary_directory>` is the name of the input directory. The `<binary_directory>_disassemble` directory will contain the extracted CSV files for each binary file, maintaining the same relative path structure as the input directory, along with the extraction and timing log files.

By using this tool, you can easily analyze binary files and obtain valuable address and opcode information for further research and analysis.

## Reference

This tool utilizes several Python libraries and tools compatible with Python 3.11.4. Below are the references and additional resources for each:

1. **os and time**: Built-in Python libraries for operating system interactions and time-related functions. More details can be found in the official Python documentation specific to Python 3.11.4: [Python Standard Library](https://docs.python.org/3.11/library/).

2. **r2pipe**: A Python library for scripting with Radare2, which is used for binary analysis. Official repository and documentation available at: [Radare2 GitHub](https://github.com/radareorg/radare2).

3. **logging and argparse**: Standard Python libraries for logging and parsing command-line arguments. Documentation for Python 3.11.4 available at: [Logging](https://docs.python.org/3.11/library/logging.html) and [Argparse](https://docs.python.org/3.11/library/argparse.html).

4. **pandas**: A powerful data manipulation and analysis library for Python. Official documentation and user guide: [Pandas Documentation](https://pandas.pydata.org/pandas-docs/version/1.4.4/).

5. **tqdm**: A library for adding progress meters to Python loops. Repository and documentation: [tqdm GitHub](https://github.com/tqdm/tqdm).

6. **multiprocessing and concurrent.futures**: Python libraries for parallel execution and asynchronous programming. Documentation specific to Python 3.11.4 available at: [Multiprocessing](https://docs.python.org/3.11/library/multiprocessing.html) and [Concurrent.futures](https://docs.python.org/3.11/library/concurrent.futures.html).

These references provide a foundation for understanding the tools and libraries used in the development of this opcode extraction tool.