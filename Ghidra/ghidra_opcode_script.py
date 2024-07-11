import os
import csv
import logging
from ghidra.app.util.headless import HeadlessScript
from ghidra.program.model.address import AddressSet

# Get script arguments and determine the save folder
argv = getScriptArgs()

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
    error_message = "An error occurred while setting parameters: {}".format(e)
    logging.error(error_message, exc_info=True)

program_name = currentProgram.getName()
program_folder = os.path.join(results_folder, program_name)

# Create the program-specific directory
if not os.path.exists(program_folder):
    os.makedirs(program_folder)

# Set up logging
log_file_path = os.path.join(output_folder, 'extraction.log')
logging.basicConfig(filename=log_file_path, level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Determine file path for CSV file
csv_file_path = os.path.join(program_folder, program_name + '.csv')

try:
    with open(csv_file_path, 'w', newline='', encoding='utf-8') as csvfile:
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow(['addr', 'opcode', 'section_name'])

        memory_blocks = currentProgram.getMemory().getBlocks()

        if memory_blocks:
            for block in memory_blocks:
                block_name = block.getName()
                address_set = AddressSet(block.getStart(), block.getEnd())
                instructions = currentProgram.getListing().getInstructions(address_set, True)
                for instr in instructions:
                    addr = instr.getAddress().toString()
                    opcode = str(instr).split(' ')[0]
                    csvwriter.writerow([addr, opcode, block_name])
        else:
            instructions = currentProgram.getListing().getInstructions(True)
            for instr in instructions:
                addr = instr.getAddress().toString()
                opcode = str(instr).split(' ')[0]
                csvwriter.writerow([addr, opcode, '.no_section'])

except Exception as e:
    error_message = "An error occurred while writing the files: {}".format(e)
    logging.error(error_message, exc_info=True)