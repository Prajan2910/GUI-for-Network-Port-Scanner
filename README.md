# Network Port Scanner GUI - Made by Prajan Kannan

A Python-based multi-threaded TCP port scanner with a user-friendly graphical interface built using Tkinter. This tool is designed for efficient network analysis, real-time monitoring, and basic security assessment.

## Features

- Interactive GUI - Clean and structured interface using Tkinter
- Custom Scan Settings - Input target, port range, timeout, and thread count
- Multi-threaded Scanning - Faster performance using concurrent threads (up to 500)
- Real-time Progress Tracking - Live progress bar with scan status updates
- Service Identification - Automatically maps well-known ports (HTTP, FTP, SSH, etc.)
- Treeview Results Table - Structured display of open ports, services, and status
- Live Logging System - Timestamp-based activity logs during scanning
- Graceful Stop Functionality - Stop scan anytime without crashing
- Export Results - Save results in .txt or .csv format
- Cross-platform Support - Works on Windows, macOS, and Linux

## Methodology

1. User provides target (IP/hostname) and port range
2. Input validation ensures correct scanning parameters
3. Target hostname is resolved to IP address
4. Multi-threaded scanning is initiated using TCP sockets
5. Each port is tested using socket.connect_ex()
6. Open ports are identified and mapped to known services
7. Results are sent to GUI using thread-safe queue
8. Real-time updates displayed via progress bar and table
9. Final results can be exported for further analysis

## Technologies & Tools Used

- Python - Core programming language
- Tkinter (ttk) - GUI development
- Socket Module - Network communication and port scanning
- Threading Module - Concurrent execution for faster scanning
- Queue Module - Thread-safe communication with GUI
- Datetime & Time Modules - Logging and elapsed time tracking
- File Handling - Exporting scan results
- Git & GitHub - Version control and project hosting

## Requirements

- Python 3.7 or newer
- Tkinter (pre-installed with Python)

For Linux:
```bash
sudo apt install python3-tk
```

## Installation

```bash
git clone https://github.com/Prajan2910/GUI-for-Network-Port-Scanner.git
cd cybersecurity
python portscannergui.py
```

## Usage

Steps:
1. Enter Target (e.g., 127.0.0.1 or scanme.nmap.org)
2. Enter Start Port and End Port
3. Set optional: Timeout (e.g., 0.5), Thread count (e.g., 200)
4. Click Start Scan
5. View results in real-time table
6. Click Stop to cancel scan
7. Click Save Results to export data

## Detected Services

| Port  | Service    |
|-------|------------|
| 21    | FTP        |
| 22    | SSH        |
| 23    | Telnet     |
| 25    | SMTP       |
| 53    | DNS        |
| 80    | HTTP       |
| 110   | POP3       |
| 143   | IMAP       |
| 443   | HTTPS      |
| 3306  | MySQL      |
| 3389  | RDP        |
| 5900  | VNC        |
| 8080  | HTTP-Alt   |

Ports not listed are shown as Unknown.

## Project Structure
cybersecurity/

│

├── portscanergui.py # Main application (Scanner + GUI)

├── README.md

└── screenshots/ # (Optional) UI images for GitHub


## Disclaimer

This tool is intended for educational and ethical purposes only.

Do NOT scan:
- Unauthorized systems
- Government/private servers
- Any network without permission

Unauthorized port scanning may be illegal.

## Acknowledgment

I sincerely thank everyone who supported and guided me throughout the development of this project. This project helped me strengthen my understanding of networking, multithreading, and cybersecurity concepts.

## License

This project is licensed under the MIT License.
