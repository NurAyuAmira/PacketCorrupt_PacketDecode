# Packet Corruption - Packet Decoding

## Overview

This project involves the development of a tool in C++ designed to intentionally corrupt packet fields within network traffic. The primary goal is to analyze the robustness of network security systems by manipulating various fields in IP packets, such as TTL, protocol, and source/destination addresses. This allows us to test how different operating systems respond to malformed packets.

## Features

- **Packet Corruption:** The tool corrupts packet fields intentionally to simulate different network conditions and analyze responses.
- **Real-time Adjustment:** Variable packet corruption parameters can be adjusted in real-time by the user, enhancing the flexibility and utility of the tool.
- **Network Vulnerability Analysis:** Contributes to the understanding of network vulnerabilities by demonstrating how different OSs handle corrupted packets.

## Technologies Used

- **C++** (CodeBlocks IDE)

## Getting Started

### Prerequisites

- CodeBlocks IDE
- C++ compiler

### Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/NurAyuAmira/PacketCorrupt_PacketDecode.git
    ```
2. Open the project in CodeBlocks IDE.
3. Build and run the project.

### Usage

1. Launch the tool from the CodeBlocks IDE.
2. Configure the packet corruption parameters as needed.
3. Start the packet corruption process and observe the results on different operating systems.

## Contributing

Contributions are welcome! Please fork the repository and use a feature branch. Pull requests are reviewed on a regular basis.
