# BTLE Research

## Setup
0. ensure wireshark is installed
1. Create python env
ex: `python -m venv venv`
2. Activate env
ex: `.\venv\Scripts\activate` 
(windows only)
3. Download dependencies in `requirements.txt`
ex: `pip install -r requirements.txt`
4. Run scripts!
ex: `python main.py path\to\*.pcapng amount_of_packets` 
analyzes given file path and uses amount of packets for progress bar
ex: `python analyze.py` analyzes some test file

