#!/bin/bash

# Input parameters
ghidra_headless_path=$1
program_folder=$2

# Get the directory of the currently executing script
current_dir=$(pwd)
python_script_path="${current_dir}/ghidra_opcode_script.py"
project_name="$(basename "${program_folder}")"
output_dir="${current_dir}/${project_name}_disassemble"

# Set directory path variables based on input parameters
project_folder="${output_dir}/ghidra_projects"
result_folder="${output_dir}/results"

max_cpu=$(nproc)

if [ -d "${output_dir}" ]; then
    rm -rf "${output_dir}"
fi
mkdir -p "${output_dir}"

# Check if project_folder exists, if exist, remove then create it
if [ -d "${project_folder}" ]; then
    rm -rf "${project_folder}"
fi
mkdir -p "${project_folder}"

# Check if result_folder exists, if exist, remove then create it
if [ -d "${result_folder}" ]; then
    rm -rf "${result_folder}"
fi
mkdir -p "${result_folder}"

# Make sure time.txt file does not exist before execution to avoid retaining old results
time_file_name="${output_dir}/${project_name}_disassemble_time.txt"
rm -f "${time_file_name}"

start_time=$(date +%s)

"${ghidra_headless_path}" "${project_folder}" "${project_name}" -import "${program_folder}/" -scriptPath "$(dirname "${python_script_path}")" -postScript "$(basename "${python_script_path}")" "${output_dir}" "${result_folder}" -max-cpu "${max_cpu}"

end_time=$(date +%s)
execution_time=$((end_time - start_time))  # Calculate the total execution time in seconds
# Append the total execution time to the time.txt file
echo "Total Execution Time: ${execution_time} seconds" >> "${time_file_name}"