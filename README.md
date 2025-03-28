# Real-Time Security OS Event Logger

A Python-based security event monitoring tool with a minimalist GUI that tracks system processes and resource usage in real-time. The application provides alerts for suspicious activities and high resource usage, making it useful for system administrators and security professionals.

## Features

- 🔍 Real-time monitoring of system processes
- 📊 System resource usage tracking (CPU & Memory)
- 🚨 Anomaly detection for high CPU usage
- 🌓 Dark-themed minimalist GUI
- 🔍 Event filtering capabilities
- 📁 Export logs to CSV format
- 🔄 Automatic process history tracking

## Requirements

- Python 3.8 or higher
- psutil library
- tkinter (usually comes with Python)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/udayaryan0001/Real-time-Security-OS-event-logger.git
cd Real-time-Security-OS-event-logger
```

2. Create a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install required packages:
```bash
pip install -r requirements.txt
```

## Usage

1. Run the application:
```bash
python security_logger.py
```

2. The application window will appear with the following features:
   - Filter dropdown to view specific types of events
   - Export button to save logs as CSV
   - Clear button to reset the log display
   - Real-time log display area
   - Status bar showing current state

3. The application automatically monitors:
   - Process CPU and memory usage
   - System-wide resource utilization
   - Anomalous process behavior

4. Use the filter dropdown to view:
   - All Events
   - Process Events
   - Resource Usage
   - Security Alerts

5. Export logs to CSV for further analysis

## Security Features

- Monitors CPU and memory usage of all processes
- Detects high CPU usage anomalies (threshold at 80%)
- Tracks system resource usage
- Logs security-relevant events with timestamps
- Process history tracking for pattern recognition

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with Python and tkinter
- Uses psutil for system monitoring
- Dark theme for reduced eye strain
- Detects unusual process behavior
- Logs security-relevant system events
- Provides real-time alerts for suspicious activities

## Note
Some features may require administrative privileges to access system information.
