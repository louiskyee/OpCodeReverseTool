import os
import csv
import time
import logging
from ghidra.app.util.headless import HeadlessScript
from ghidra.program.model.address import AddressSet

# Get command line arguments
argv = getScriptArgs()
program_name = currentProgram.getName()
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

# Set up logging
log_file_path = os.path.join(output_folder, 'extraction.log')
logging.basicConfig(filename=log_file_path, level=logging.ERROR,
                    format='%(asctime)s:%(levelname)s:%(message)s')

try:
    start_time = time.time()

    output_path = os.path.join(results_folder, program_name + '.csv')

    with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
        # Create a CSV writer
        csvwriter = csv.writer(csvfile)

        # Write the header
        csvwriter.writerow(['addr', 'opcode', 'section_name'])

        # Get the list of MemoryBlocks
        memory_blocks = currentProgram.getMemory().getBlocks()

        if len(memory_blocks) > 0:
            for block in memory_blocks:
                # Get each MemoryBlock's name
                block_name = block.getName()

                # Get the start and end addresses of the MemoryBlock
                start_address = block.getStart()
                end_address = block.getEnd()

                # Create an AddressSet for the block
                address_set = AddressSet(start_address, end_address)

                # Get instructions in the MemoryBlock using the AddressSet
                instructions = currentProgram.getListing().getInstructions(address_set, True)
                for instr in instructions:
                    addr = instr.getAddress().toString()
                    opcode = str(instr).split(' ')[0]

                    # Write the instruction to the CSV file
                    csvwriter.writerow([addr, opcode, block_name])
        else:
            # If no MemoryBlocks found, get all instructions
            instructions = currentProgram.getListing().getInstructions(True)
            for instr in instructions:
                addr = instr.getAddress().toString()
                opcode = str(instr).split(' ')[0]

                # Write the instruction to the CSV file with section_name as .no_section
                csvwriter.writerow([addr, opcode, '.no_section'])

    end_time = time.time()
    execution_time = end_time - start_time
    with open(os.path.join(output_folder, 'timing.log'), 'a', newline='', encoding='utf-8') as f:
        f.write("{},{:.2f}\n".format(program_name, execution_time))

except Exception as e:
    error_message = "An error occurred while writing the files: {}".format(e)
    logging.error(error_message, exc_info=True)
