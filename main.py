import argparse
import analyze
import os

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('file_name', type=str, help='Path to the capture')
    parser.add_argument('amount_of_packets', type=int, help='Amount of Packets in the capture')
    args = parser.parse_args()
    file_name = args.file_name
    amount_of_packets = args.amount_of_packets
    if not os.path.isfile(file_name):
        print(f"Error: '{file_name}' does not exist. If giving a relative path ensure it is based from this file's location")
        return
    if not file_name.endswith(".pcapng"):
        print(f"'{file_name}' is not a packet tracer file and cannot be analyzed")
        return
    print(f"Analyzing: {file_name}")
    analyze.do_analyzing(file_name, amount_of_packets)


if __name__ == "__main__":
    main()
