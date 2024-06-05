# Use an official base image
FROM ubuntu:latest

# Install base utilities
RUN apt-get update && apt-get install -y git make sudo

# Copy the installation script into the container
COPY install_ghidra.sh /install_ghidra.sh

# Grant execution permissions to the script
RUN chmod +x /install_ghidra.sh

# Run the script when the container starts
CMD ["/install_ghidra.sh"]
