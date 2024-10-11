import os
import time
import r2pipe
import logging
import argparse
import subprocess
import pandas as pd

from tqdm import tqdm
from elftools.elf.elffile import ELFFile
from concurrent.futures import ProcessPoolExecutor, as_completed

def configure_logging(output_dir: str) -> tuple:
    """
    Configure logging settings.

    Args:
        output_dir (str): Path to the output directory.

    Returns:
        tuple: A tuple containing the extraction_logger and timing_logger objects.
    """
    extraction_log_file = os.path.join(output_dir, f'extraction.log')
    print(f"Logging to: {extraction_log_file}")
    extraction_logger = logging.getLogger('extraction_logger')
    extraction_logger.setLevel(logging.INFO)
    extraction_handler = logging.FileHandler(extraction_log_file)
    extraction_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    extraction_logger.addHandler(extraction_handler)

    timing_log_file = os.path.join(output_dir, f'timing.log')
    print(f"Timing log file: {timing_log_file}")
    timing_logger = logging.getLogger('timing_logger')
    timing_logger.setLevel(logging.INFO)
    timing_handler = logging.FileHandler(timing_log_file)
    timing_handler.setFormatter(logging.Formatter('%(asctime)s,%(message)s'))
    timing_logger.addHandler(timing_handler)

    return extraction_logger, timing_logger

def check_timeout(input_file_path: str, timeout_seconds: int, bash_script_path: str) -> bool:
    """
    Check if the file analysis will timeout.

    Args:
        input_file_path (str): Path to the input file.
        timeout_seconds (int): Timeout duration in seconds.
        bash_script_path (str): Path to the bash script for timeout check.

    Returns:
        bool: True if the analysis won't timeout, False otherwise.
    """
    try:
        result = subprocess.run(
            [bash_script_path, input_file_path, str(timeout_seconds)],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip() == "true"
    except subprocess.CalledProcessError:
        return False

def get_entry_point(file_path: str) -> int:
    """
    Get the entry point of an ELF file.

    Args:
        file_path (str): Path to the ELF file.

    Returns:
        int: Entry point address, or None if not found.
    """
    try:
        with open(file_path, 'rb') as f:
            elf = ELFFile(f)
            return elf.header.e_entry
    except Exception as e:
        logging.error(f"Error getting entry point for {file_path}: {str(e)}")
        return None

def extract_features(input_file_path: str) -> list:
    """
    Extract features from the input file.

    Args:
        input_file_path (str): Path to the input file.

    Returns:
        list: List of dictionaries containing extracted features.
    """
    r2 = r2pipe.open(input_file_path, flags=['-2'])
    r2.cmd("aaa")
    
    sections = r2.cmdj('iSj')
    all_opcodes = []

    if sections:
        for section in sections:
            if section['size'] > 0:
                instructions = r2.cmdj(f"pDj {section['size']} @{section['vaddr']}")
                if instructions:
                    for instr in instructions:
                        all_opcodes.append({
                            'addr': instr['offset'],
                            'opcode': instr['opcode'].split()[0] if 'opcode' in instr else '',
                            'section_name': section['name']
                        })
    else:
        elf_position = r2.cmdj("/j ELF")[0]['offset']
        entry_point = get_entry_point(input_file_path)
        if entry_point is None:
            logging.error(f"Unable to retrieve entry point for {input_file_path}")
            return []
        r2.cmd(f"s {elf_position} - 1")
        instructions = r2.cmdj("pdj $s")
        invalid_count = 0
        invalid_threshold = 500
        if instructions:
            for instr in instructions:
                opcode = instr['opcode'].split()[0] if 'opcode' in instr else ''
                if opcode == 'invalid':
                    invalid_count += 1
                else:
                    invalid_count = 0

                if invalid_count > invalid_threshold:
                    all_opcodes = all_opcodes[:-invalid_count+1]
                    break
                
                if entry_point and instr['offset'] < entry_point:
                    section_name = '.compressed_data'
                else:
                    section_name = '.loader'
                
                all_opcodes.append({
                    'addr': instr['offset'],
                    'opcode': opcode,
                    'section_name': section_name
                })

    r2.quit()
    return all_opcodes

def extraction(input_file_path: str, output_csv_path: str, file_name: str, extraction_logger: logging.Logger, timing_logger: logging.Logger, timeout_seconds: int, bash_script_path: str) -> float:
    """
    Extract address and opcode information from each section of the specified file and save it to a CSV file, categorized by sections.

    Args:
        input_file_path (str): File path of the target file.
        output_csv_path (str): File path for the output CSV file.
        file_name (str): Name of the target file.
        extraction_logger (logging.Logger): Logger object for recording the extraction process.
        timing_logger (logging.Logger): Logger object for recording execution time.
        timeout_seconds (int): Timeout duration in seconds.
        bash_script_path (str): Path to the bash script for timeout check.

    Returns:
        float: Execution time of the extraction process.
    """
    if os.path.exists(output_csv_path):
        extraction_logger.info(f"File already exists: {output_csv_path}")
        return 0

    start_time = time.time()

    try:
        if not check_timeout(input_file_path, timeout_seconds, bash_script_path):
            extraction_logger.error(f"{file_name}: File analysis timed out after {timeout_seconds} seconds")
            return 0

        all_opcodes = extract_features(input_file_path)

        df = pd.DataFrame(all_opcodes)
        if df.empty:
            extraction_logger.info(f"{file_name}: No valid disassembly found")
            raise ValueError(f"No valid disassembly found: {input_file_path}")

        df.to_csv(output_csv_path, index=False)

        execution_time = time.time() - start_time
        timing_logger.info(f"{file_name},{execution_time:.2f} seconds")
        return execution_time

    except FileNotFoundError:
        extraction_logger.error(f"{file_name}: File not found")
    except ValueError as ve:
        extraction_logger.error(str(ve))
    except Exception as e:
        extraction_logger.exception(f"An unexpected error occurred: {e}")
    
    return 0

def get_args(binary_path: str, output_path: str, extraction_logger: logging.Logger, timing_logger: logging.Logger, timeout_seconds: int, bash_script_path: str) -> list:
    """
    Generate a list of arguments for parallel processing.

    Args:
        binary_path (str): Path to the binary directory.
        output_path (str): Path to the output directory.
        extraction_logger (logging.Logger): Logger object for recording the extraction process.
        timing_logger (logging.Logger): Logger object for recording execution time.
        timeout_seconds (int): Timeout duration in seconds.
        bash_script_path (str): Path to the bash script for timeout check.

    Returns:
        list: A list of tuples containing the binary file path, output file path, file name, loggers, and timeout information.
    """
    args = []
    for root, _, files in os.walk(binary_path):
        for file in files:
            if '.' not in file:
                binary_file_path = os.path.join(root, file)
                relative_path = os.path.relpath(root, binary_path)
                output_dir_path = os.path.normpath(os.path.join(output_path, "results", relative_path))
                os.makedirs(output_dir_path, exist_ok=True)
                output_file_path = os.path.join(output_dir_path, f"{file}.csv")
                args.append((binary_file_path, output_file_path, file, extraction_logger, timing_logger, timeout_seconds, bash_script_path))
    return args

def parallel_process(args: list) -> None:
    """
    Process the extraction tasks in parallel.

    Args:
        args (list): A list of tuples containing the binary file path, output file path, file name, loggers, and timeout information.
    """
    with ProcessPoolExecutor(max_workers=os.cpu_count()) as executor:
        futures = [executor.submit(extraction, *arg) for arg in args]
        for _ in tqdm(as_completed(futures), total=len(futures), desc="Processing files", unit="file"):
            pass

def setup_output_directory(input_dir: str) -> str:
    """
    Set up the output directory for storing the extracted files.

    Args:
        input_dir (str): Path to the input directory.

    Returns:
        str: Path to the output directory.
    """
    output_dir = os.path.join(os.path.dirname(input_dir), f"{os.path.basename(input_dir)}_disassemble")
    print(f"Output directory: {output_dir}")
    os.makedirs(output_dir, exist_ok=True)
    results_dir = os.path.join(output_dir, "results")
    os.makedirs(results_dir, exist_ok=True)
    return output_dir

def parse_arguments() -> argparse.Namespace:
    """
    Parse command-line arguments.

    Returns:
        argparse.Namespace: Parsed arguments.
    """
    parser = argparse.ArgumentParser(description='Extract address and opcode information from binary files.')
    parser.add_argument('-d', '--directory', type=str, required=True, help='Path to the binary directory')
    parser.add_argument('-t', '--timeout', type=int, default=300, help='Timeout duration in seconds')
    args = parser.parse_args()
    args.directory = os.path.normpath(os.path.expanduser(args.directory))
    return args

def main() -> None:
    """
    Main function to orchestrate the extraction process.
    """
    args = parse_arguments()

    input_dir = args.directory
    output_dir = setup_output_directory(input_dir)
    extraction_logger, timing_logger = configure_logging(output_dir)

    # Get the path of the current script
    current_script_path = os.path.abspath(__file__)
    script_directory = os.path.dirname(current_script_path)
    bash_script_path = os.path.join(script_directory, "r2_timeout_check.sh")

    # Check if r2_timeout_check.sh exists and is executable
    if not os.path.exists(bash_script_path):
        extraction_logger.error(f"r2_timeout_check.sh not found in the same directory as get_opcode.py")
        print(f"Error: r2_timeout_check.sh not found in {script_directory}")
        return
    elif not os.access(bash_script_path, os.X_OK):
        extraction_logger.error(f"r2_timeout_check.sh is not executable")
        print(f"Error: r2_timeout_check.sh in {script_directory} is not executable")
        return

    parallel_process(get_args(input_dir, output_dir, extraction_logger, timing_logger, args.timeout, bash_script_path))

if __name__ == "__main__":
    main()