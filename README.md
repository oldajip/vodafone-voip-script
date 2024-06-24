# vodafone-voip-script
Vodafone VoIP Registration, Call, and Pre-Recorded Message Script

This repository contains a Python script and a sample WAV file for registering with Vodafone's VoIP service, making a call, and playing a pre-recorded message. The script is intended for testing audio transmission through Vodafone's network and understanding VoIP functionality.

## Files Included

- **git_vodafone_reg_and_call_with_msg_release_1.py**: A Python script that handles the SIP registration, call initiation, and playback of a pre-recorded message using Vodafone's VoIP service.
- **voipTest.wav**: A sample WAV file to be played during the VoIP call.

## Features

- Registers a new SIP binding with Vodafone's VoIP server.
- Authenticates the SIP registration.
- Initiates a VoIP call to a specified phone number.
- Plays a pre-recorded WAV message during the call.
- Handles various SIP responses and maintains the call session.

## Requirements

- **Operating System**: Windows 11
- **Python**: 3.8
- **Additional Packages**: `numpy`, `dnspython`, `pydivert`
- **FFmpeg**: Required for converting WAV files to PCMA format.

## Setup Instructions

1. **Create a Conda Environment**:
    ```sh
    conda create --name voip python=3.8
    conda activate voip
    pip install numpy dnspython pydivert
    ```

2. **Install FFmpeg**:
    - Download FFmpeg from [official site](https://ffmpeg.org/download.html).
    - Follow the instructions to install FFmpeg and add it to your system PATH.

3. **Run the Script as Administrator**:
    - Ensure that your IDE (e.g., Visual Studio Code) is run with administrator privileges to modify packet headers.

4. **Update Configuration**:
    - Edit the script to replace example values with your actual Vodafone SIP credentials and network configuration.

## Usage

- Run the script from your IDE or command line:
    ```sh
    python git_vodafone_reg_and_call_with_msg_release_1.py
    ```

## Notes

- The script includes detailed comments and instructions for configuring and running the VoIP tests.
- Wireshark is recommended for monitoring SIP and RTP traffic.

## Disclaimer

This script is provided for educational and testing purposes only. Use it at your own risk. The authors are not responsible for any misuse or damage caused by this script.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

    
