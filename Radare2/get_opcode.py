import os
import time
import r2pipe
import logging
import argparse
import subprocess
import pandas as pd

from tqdm import tqdm
from typing import List, Dict, Any, Tuple
from contextlib import contextmanager
from concurrent.futures import ProcessPoolExecutor, as_completed

# Constants
RESULTS_SUBDIR = "results"
DEFAULT_TIMEOUT_SECONDS = 300
R2_TIMEOUT_SCRIPT = "r2_timeout_check.sh"

def configure_logging(output_dir: str) -> Tuple[logging.Logger, logging.Logger]:
    """
    Configure logging settings.

    Args:
        output_dir (str): Path to the output directory.

    Returns:
        Tuple[logging.Logger, logging.Logger]: A tuple containing the extraction_logger and timing_logger objects.
    """
    extraction_log_file = os.path.join(output_dir, 'extraction.log')
    print(f"Logging to: {extraction_log_file}")
    extraction_logger = logging.getLogger('extraction_logger')
    extraction_logger.setLevel(logging.INFO)
    # Clear existing handlers to avoid duplication
    extraction_logger.handlers.clear()
    extraction_handler = logging.FileHandler(extraction_log_file)
    extraction_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    extraction_logger.addHandler(extraction_handler)

    timing_log_file = os.path.join(output_dir, 'timing.log')
    print(f"Timing log file: {timing_log_file}")
    timing_logger = logging.getLogger('timing_logger')
    timing_logger.setLevel(logging.INFO)
    # Clear existing handlers to avoid duplication
    timing_logger.handlers.clear()
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

@contextmanager
def open_r2pipe(file_path: str):
    """
    Context manager for r2pipe to ensure proper cleanup.

    Args:
        file_path (str): Path to the file to analyze.

    Yields:
        r2pipe object
    """
    r2 = None
    try:
        r2 = r2pipe.open(file_path, flags=['-2'])
        yield r2
    finally:
        if r2:
            r2.quit()

def extract_features(input_file_path: str, extraction_logger: logging.Logger) -> List[Dict[str, Any]]:
    """
    Extract features from the input file.

    Args:
        input_file_path (str): Path to the input file.
        extraction_logger (logging.Logger): Logger object for recording errors.

    Returns:
        List[Dict[str, Any]]: List of dictionaries containing extracted features.
    """
    with open_r2pipe(input_file_path) as r2:
        r2.cmd("e asm.flags.middle=0")
        sections = r2.cmdj('iSj')

        if not sections:
            # No sections found - file may be packed, damaged, or incomplete
            extraction_logger.error(f"No sections found in {input_file_path} - file may be packed, damaged, or incomplete")
            return []

        # Use list comprehension for better performance
        all_opcodes = [
            {
                'addr': instr['offset'],
                'opcode': instr['opcode'].split()[0] if 'opcode' in instr else '',
                'section_name': section['name']
            }
            for section in sections
            if section['size'] > 0
            for instr in (r2.cmdj(f"pDj {section['size']} @{section['vaddr']}") or [])
        ]

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
        float: Execution time of the extraction process, or 0 if failed.
    """
    if os.path.exists(output_csv_path):
        extraction_logger.info(f"File already exists: {output_csv_path}")
        return 0


    try:
        if not check_timeout(input_file_path, timeout_seconds, bash_script_path):
            extraction_logger.error(f"{file_name}: File analysis timed out after {timeout_seconds} seconds")
            return 0

        start_time = time.process_time()
        
        all_opcodes = extract_features(input_file_path, extraction_logger)

        execution_time = time.process_time() - start_time
        timing_logger.info(f"{file_name},{execution_time:.2f}")

        if not all_opcodes:
            extraction_logger.error(f"{file_name}: No valid disassembly found")
            return 0

        # Create output directory only when needed
        output_dir = os.path.dirname(output_csv_path)
        os.makedirs(output_dir, exist_ok=True)

        df = pd.DataFrame(all_opcodes)
        df.to_csv(output_csv_path, index=False)

        return execution_time

    except FileNotFoundError:
        extraction_logger.error(f"{file_name}: File not found - {input_file_path}")
    except Exception as e:
        extraction_logger.exception(f"{file_name}: Unexpected error - {e}")

    return 0

def get_args(binary_path: str, output_path: str, extraction_logger: logging.Logger, timing_logger: logging.Logger, timeout_seconds: int, bash_script_path: str) -> List[Tuple]:
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
        List[Tuple]: A list of tuples containing the binary file path, output file path, file name, loggers, and timeout information.
    """
    args = []
    for root, _, files in os.walk(binary_path):
        for file in files:
            if '.' not in file:
                binary_file_path = os.path.join(root, file)
                relative_path = os.path.relpath(root, binary_path)
                output_dir_path = os.path.normpath(os.path.join(output_path, RESULTS_SUBDIR, relative_path))
                # Don't create directory here - will be created when needed
                output_file_path = os.path.join(output_dir_path, f"{file}.csv")
                args.append((binary_file_path, output_file_path, file, extraction_logger, timing_logger, timeout_seconds, bash_script_path))
    return args

def parallel_process(args: List[Tuple]) -> None:
    """
    Process the extraction tasks in parallel.

    Args:
        args (List[Tuple]): A list of tuples containing the binary file path, output file path, file name, loggers, and timeout information.
    """
    with ProcessPoolExecutor(max_workers=os.cpu_count()) as executor:
        futures = [executor.submit(extraction, *arg) for arg in args]
        with tqdm(total=len(futures), desc="Processing files", unit="file") as pbar:
            for _ in as_completed(futures):
                pbar.update(1)

def setup_output_directory(input_dir: str, custom_output_dir: str = None) -> str:
    """
    Set up the output directory for storing the extracted files.

    Args:
        input_dir (str): Path to the input directory.
        custom_output_dir (str, optional): Custom output directory path. If None, uses default naming.

    Returns:
        str: Path to the output directory.
    """
    if custom_output_dir:
        output_dir = custom_output_dir
    else:
        output_dir = os.path.join(os.path.dirname(input_dir), f"{os.path.basename(input_dir)}_disassemble")

    print(f"Output directory: {output_dir}")
    os.makedirs(output_dir, exist_ok=True)
    results_dir = os.path.join(output_dir, RESULTS_SUBDIR)
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
    parser.add_argument('-o', '--output', type=str, help='Path to the output directory (default: <input_dir>_disassemble)')
    parser.add_argument('-t', '--timeout', type=int, default=DEFAULT_TIMEOUT_SECONDS, help=f'Timeout duration in seconds (default: {DEFAULT_TIMEOUT_SECONDS})')
    args = parser.parse_args()
    args.directory = os.path.normpath(os.path.expanduser(args.directory))
    if args.output:
        args.output = os.path.normpath(os.path.expanduser(args.output))
    return args

def main() -> None:
    """
    Main function to orchestrate the extraction process.
    """
    args = parse_arguments()

    input_dir = args.directory
    output_dir = setup_output_directory(input_dir, args.output)
    extraction_logger, timing_logger = configure_logging(output_dir)

    # Get the path of the current script
    script_directory = os.path.dirname(os.path.abspath(__file__))
    bash_script_path = os.path.join(script_directory, R2_TIMEOUT_SCRIPT)

    # Check if r2_timeout_check.sh exists and is executable
    if not os.path.exists(bash_script_path):
        error_msg = f"{R2_TIMEOUT_SCRIPT} not found in {script_directory}"
        extraction_logger.error(error_msg)
        print(f"Error: {error_msg}")
        return

    if not os.access(bash_script_path, os.X_OK):
        error_msg = f"{R2_TIMEOUT_SCRIPT} in {script_directory} is not executable"
        extraction_logger.error(error_msg)
        print(f"Error: {error_msg}")
        return

    parallel_process(get_args(input_dir, output_dir, extraction_logger, timing_logger, args.timeout, bash_script_path))

if __name__ == "__main__":
    main()