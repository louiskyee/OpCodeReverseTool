#!/bin/bash

# Set non-interactive installation mode
export DEBIAN_FRONTEND=noninteractive

# Update and install required tools including python3-venv
apt-get update && apt-get install -y wget unzip python3 python3-pip gcc g++ make git openjdk-17-jdk python3-venv python-is-python3

# Check if JDK 17 is installed and install if not
if ! javac -version 2>&1 | grep -q '17'; then
    echo "JDK 17 is not installed. Installing JDK 17..."
    apt-get install -y openjdk-17-jdk
fi

# Set JAVA_HOME to the path of JDK 17
export JAVA_HOME=$(dirname $(dirname $(readlink -f $(which javac))))

if [[ "$JAVA_HOME" =~ .*jdk-17.* ]]; then
    echo "JAVA_HOME is correctly set to JDK 17."
else
    echo "JAVA_HOME was not set correctly. Attempting to set JAVA_HOME..."
    JAVA_HOME=$(update-alternatives --list javac | grep java-17 | sed 's:/bin/javac::' | head -n 1)
    export JAVA_HOME
fi

echo "JAVA_HOME set to $JAVA_HOME"

# Download and install Gradle
wget https://services.gradle.org/distributions/gradle-7.3-bin.zip -P /tmp
unzip /tmp/gradle-7.3-bin.zip -d /opt
export GRADLE_HOME=/opt/gradle-7.3
export PATH=$PATH:/opt/gradle-7.3/bin

echo "export GRADLE_HOME=$GRADLE_HOME" >> /etc/profile.d/gradle.sh
echo "export PATH=\$GRADLE_HOME/bin:\$PATH" >> /etc/profile.d/gradle.sh
chmod +x /etc/profile.d/gradle.sh
source /etc/profile.d/gradle.sh

# Download the specific release of Ghidra
wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.3.1_build/ghidra_10.3.1_PUBLIC_20230614.zip -P /tmp

# Unzip the downloaded file to the desired installation directory
unzip /tmp/ghidra_10.3.1_PUBLIC_20230614.zip -d /opt

# Set GHIDRA_HOME to the unzipped directory
GHIDRA_HOME=/opt/ghidra_10.3.1_PUBLIC
export GHIDRA_HOME

# Make the ghidraRun script executable
chmod +x $GHIDRA_HOME/ghidraRun

# Check if Ghidra was setup successfully
if [ -f "$GHIDRA_HOME/ghidraRun" ]; then
    echo "Ghidra setup was successful."
else
    echo "Ghidra setup failed."
    exit 1
fi

# Create a virtual environment in the Ghidra directory
python3 -m venv $GHIDRA_HOME/venv

# Check if virtual environment was created successfully
if [ ! -f "$GHIDRA_HOME/venv/bin/activate" ]; then
    echo "Virtual environment was not created successfully."
    exit 1
fi

# Activate the virtual environment
source $GHIDRA_HOME/venv/bin/activate

# Install JEP
pip install jep || { echo "Failed to install JEP"; exit 1; }

# Assuming GHIDRA_INSTALL_DIR is set to Ghidra's installation directory
export GHIDRA_INSTALL_DIR=/opt/ghidra_10.3.1_PUBLIC


cd /tmp
git clone https://github.com/mandiant/Ghidrathon.git

# Navigate to the Ghidrathon directory
cd /tmp/Ghidrathon/lib
wget https://github.com/ninia/jep/releases/download/v4.2.0/jep-4.2.0.jar

cd ../
gradle -PGHIDRA_INSTALL_DIR=$GHIDRA_HOME 

cd dist
zip_file=$(ls *.zip)
cp $zip_file $GHIDRA_HOME/Extensions/Ghidra
echo "source ${SCRIPT_DIR}/venv/bin/activate" >> ./ghidraRun
