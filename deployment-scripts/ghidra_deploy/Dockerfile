# Use an official base image
FROM ubuntu:latest

# Install base utilities
RUN apt-get update && apt-get install -y sudo adduser

# Create a new user and add to sudo group
RUN useradd -m ghidrauser && echo "ghidrauser:ghidrauser" | chpasswd && adduser ghidrauser sudo

# Switch to the new user
USER ghidrauser

# Set working directory
WORKDIR /home/ghidrauser

# Copy the installation script into the container
COPY --chown=ghidrauser:ghidrauser install_ghidra.sh /home/ghidrauser/install_ghidra.sh

# Grant execution permissions to the script
RUN chmod +x /home/ghidrauser/install_ghidra.sh

# Run the script when the container starts
CMD ["/home/ghidrauser/install_ghidra.sh"]