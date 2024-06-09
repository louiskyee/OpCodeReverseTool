import os
import time
import r2pipe
import logging
import argparse
import pandas as pd

from tqdm import tqdm
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

def extraction(input_file_path: str, output_csv_path: str, file_name: str, extraction_logger: logging.Logger, timing_logger: logging.Logger) -> float:
    """
    Extract address and opcode information from each section of the specified file and save it to a CSV file, categorized by sections.

    Args:
        input_file_path (str): File path of the target file.
        output_csv_path (str): File path for the output CSV file.
        file_name (str): Name of the target file.
        extraction_logger (logging.Logger): Logger object for recording the extraction process.
        timing_logger (logging.Logger): Logger object for recording execution time.

    Returns:
        float: Execution time of the extraction process.

    Raises:
        FileNotFoundError: If the target file is not found.
        ValueError: If no valid disassembly is found for the target file.
        Exception: If any other unexpected error occurs.
    """
    start_time = time.time()
    r2 = None

    try:
        r2 = r2pipe.open(input_file_path, flags=["-2"])
        r2.cmd("aaa")  # Enhanced analysis

        sections = r2.cmdj('iSj')  # Get sections as JSON
        all_opcodes = []

        if sections:
            for section in sections:
                if section['size'] > 0:  # Only process sections with size
                    opcodes = r2.cmdj(f"pDj {section['size']} @{section['vaddr']}")
                    if opcodes:
                        for opcode in opcodes:
                            all_opcodes.append({
                                'addr': opcode['offset'],
                                'opcode': opcode['opcode'].split()[0] if 'opcode' in opcode else '',
                                'section_name': section['name']
                            })
        else:
            # No sections found, use 'pdj $s' to disassemble the entire file
            opcodes = r2.cmdj("pdj $s")
            if opcodes:
                for opcode in opcodes:
                    all_opcodes.append({
                        'addr': opcode['offset'],
                        'opcode': opcode['opcode'].split()[0] if 'opcode' in opcode else '',
                        'section_name': '.no_section'
                    })

        df = pd.DataFrame(all_opcodes)
        if df.empty:
            raise ValueError(f"No valid disassembly found for file: {input_file_path}")

        df.to_csv(output_csv_path, index=False)

    except FileNotFoundError:
        extraction_logger.error(f"File not found: {input_file_path}")
    except ValueError as ve:
        extraction_logger.error(str(ve))
    except Exception as e:
        extraction_logger.exception(f"An unexpected error occurred: {e}")
    finally:
        if r2:
            r2.quit()

    end_time = time.time()
    execution_time = end_time - start_time
    timing_logger.info(f"{file_name},{execution_time:.2f} seconds")

def get_args(binary_path: str, output_path: str, extraction_logger: logging.Logger, timing_logger: logging.Logger) -> list:
    """
    Generate a list of arguments for parallel processing.

    Args:
        binary_path (str): Path to the binary directory.
        output_path (str): Path to the output directory.
        extraction_logger (logging.Logger): Logger object for recording the extraction process.
        timing_logger (logging.Logger): Logger object for recording execution time.

    Returns:
        list: A list of tuples containing the binary file path, output file path, file name, and loggers.
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
                args.append((binary_file_path, output_file_path, file, extraction_logger, timing_logger))
    return args

def parallel_process(args: list) -> None:
    """
    Process the extraction tasks in parallel.

    Args:
        args (list): A list of tuples containing the binary file path, output file path, file name, and loggers.
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

    parallel_process(get_args(input_dir, output_dir, extraction_logger, timing_logger))

if __name__ == "__main__":
    main()