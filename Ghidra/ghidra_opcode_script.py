import os
import csv
import time
import logging
from ghidra.program.model.address import AddressSet
from ghidra.app.cmd.disassemble import DisassembleCommand

# Get script arguments
argv = getScriptArgs()

# Configure extraction logger
def configure_extraction_logger(output_folder):
    """Configure extraction logger with proper handler management."""
    log_file_path = os.path.join(output_folder, 'extraction.log')
    extraction_logger = logging.getLogger('ghidra_extraction_logger')
    extraction_logger.setLevel(logging.INFO)
    # Clear existing handlers to avoid duplication
    extraction_logger.handlers = []
    extraction_handler = logging.FileHandler(log_file_path)
    extraction_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    extraction_logger.addHandler(extraction_handler)
    return extraction_logger

try:
    # Set save folder
    if len(argv) == 2:
        output_folder = argv[0]
        results_folder = argv[1]
    elif len(argv) == 1:
        output_folder = argv[0]
        results_folder = os.path.join(output_folder, 'results')
    elif len(argv) == 0:
        output_folder = os.getcwd()
        results_folder = os.path.join(os.getcwd(), 'results')
    else:
        raise ValueError("Invalid number of arguments")
except Exception as e:
    # Use basic logging for parameter setup errors
    error_message = "An error occurred while setting parameters: {}".format(e)
    print("ERROR: " + error_message)
    raise

file_name = currentProgram().getName()

# Use first two characters as subdirectory (aligned with Radare2 structure)
subdir = file_name[:2]
output_dir_path = os.path.join(results_folder, subdir)

# Create the subdirectory
if not os.path.exists(output_dir_path):
    os.makedirs(output_dir_path)

# Set up logging with dedicated logger
extraction_logger = configure_extraction_logger(output_folder)

# Determine file path for CSV file
csv_file_path = os.path.join(output_dir_path, file_name + '.csv')

try:
    # Record start time (CPU time)
    start_time = time.process_time()
    
    memory_blocks = currentProgram().getMemory().getBlocks()

    if not memory_blocks:
        # No memory blocks found - file may be packed, damaged, or incomplete
        extraction_logger.error("{}: No memory blocks found - file may be packed, damaged, or incomplete".format(file_name))
        raise Exception("No memory blocks found")

    # Collect all opcodes first
    all_opcodes = []
    for block in memory_blocks:
        section_name = block.getName()
        address_set = AddressSet(block.getStart(), block.getEnd())

        # Manually disassemble the block since we use -noanalysis
        disassembleCommand = DisassembleCommand(address_set, address_set, True)
        disassembleCommand.applyTo(currentProgram())

        instructions = currentProgram().getListing().getInstructions(address_set, True)
        for instr in instructions:
            addr = int(instr.getAddress().getOffset())
            opcode = str(instr).split(' ')[0]
            all_opcodes.append([addr, opcode, section_name])

    # Calculate execution time
    execution_time = time.process_time() - start_time

    # Only create CSV file if we have extracted opcodes
    if not all_opcodes:
        extraction_logger.error("{}: No instructions found in any memory block".format(file_name))
        raise Exception("No instructions found")

    # Write all collected opcodes to CSV
    with open(csv_file_path, 'w', newline='', encoding='utf-8') as csvfile:
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow(['addr', 'opcode', 'section_name'])
        csvwriter.writerows(all_opcodes)

    # Log success with timing information
    extraction_logger.info("{}: Successfully extracted opcode information".format(file_name))

    # Write timing information to timing.log
    timing_log_path = os.path.join(output_folder, 'timing.log')
    with open(timing_log_path, 'a') as timing_file:
        timing_file.write("{},{:.2f}\n".format(file_name, execution_time))

except Exception as e:
    error_message = "{}: An error occurred while extracting opcodes - {}".format(file_name, str(e))
    extraction_logger.error(error_message, exc_info=True)
