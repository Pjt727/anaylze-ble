import pyshark
import pandas as pd
import os
from tqdm import tqdm
from dataclasses import dataclass
from pyshark.packet.packet import Packet
from pyshark.packet.fields import LayerFieldsContainer
import matplotlib.pyplot as plt
from typing import Any

# packet to store the minimum amount of data
#    needed for analaysis so that memory can be reclaimed
@dataclass
class TruncatedPacket:
    time_stamp: float
    advertising_address: str

def analyze_packets(packets: list[TruncatedPacket]):
    advertising_address_to_packets: dict[str, list[TruncatedPacket]] = {}
    for packet in packets:
        if packet.advertising_address in advertising_address_to_packets:
            advertising_address_to_packets[packet.advertising_address].append(packet)
        else:
            advertising_address_to_packets[packet.advertising_address] = [packet]

    time_of_first_packet = packets[0].time_stamp
    packet_sort = lambda packets: len(packets[1])
    top_ten_set_of_packets = sorted(advertising_address_to_packets.items(), key=packet_sort, reverse=True)[:100]
    for i, (_, packets) in enumerate(top_ten_set_of_packets):
        x_values = list(map(lambda p: p.time_stamp - time_of_first_packet, packets)) 
        y_values = [i + 1] * len(packets)
        plt.plot(x_values, y_values, marker='o', linestyle='None', label=f'Packet set {i + 1}')
    plt.xlabel('Time since first packet')
    plt.ylabel('Packet number')
    plt.title('Packet Analaysis')
    plt.show()


def get_packets_from_pcapng(file_path: str, amount_of_packets: int) -> list[TruncatedPacket]:
    capture = pyshark.FileCapture(file_path)
    truncated_packets: list[TruncatedPacket] = []
    progress_bar = tqdm(total=amount_of_packets, bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt}')
    for packet in capture:
        packet: Packet
        for layer_obj in packet.layers:
            if layer_obj.layer_name == 'btle':
                # layer_obj have a useful attribute called field names which tells
                #   all the attributes of a layer_obj
                time_stamp = float(packet.sniff_timestamp) #pyright: ignore
                # if time_stamp > 100: continue
                field_names = layer_obj.field_names
                if "advertising_address" in field_names:
                    truncated_packet = TruncatedPacket(
                            time_stamp=time_stamp,
                            advertising_address=layer_obj.advertising_address
                            )
                    truncated_packets.append(truncated_packet)
                else:
                    # There are some btle packet which do not have an advertising
                    #    ip... may want to do something with them later
                    pass

        progress_bar.update()
    progress_bar.close()
    capture.close()
    print(len(truncated_packets))
    return truncated_packets

def get_packets_from_csv(file_path: str) -> list[TruncatedPacket]:
    df = pd.read_csv(file_path)
    packets = []
    for _, row in df.iterrows():
        person = TruncatedPacket(
                time_stamp=row['time_stamp'], # pyright: ignore 
                advertising_address=row['advertising_address'] # pyright: ignore 
                )
        packets.append(person)
    return packets

def write_to_csv(file_path: str, packets: list[TruncatedPacket]):
    data = {
            "time_stamp": [packet.time_stamp for packet in packets],
            "advertising_address": [packet.advertising_address for packet in packets],
            }
    df = pd.DataFrame(data)
    df.to_csv(file_path, index=False)

def do_analyzing(file_path: str, amount_of_packets: int = 0):
    base_file_name, _ = os.path.splitext(os.path.basename(file_path))
    
    possibly_cached_csv = os.path.join(os.getcwd(), "cached_captures", base_file_name + ".csv")
    if os.path.exists(possibly_cached_csv):
        print("Using the cached csv")
        packets = get_packets_from_csv(possibly_cached_csv)
    else:
        packets = get_packets_from_pcapng(file_path, amount_of_packets)
        write_to_csv(possibly_cached_csv, packets)

    analyze_packets(packets)


if __name__ == "__main__":
    # just a random test
    test_file = os.path.join(os.getcwd(), "valentineCaptures", "bose2.pcapng")
    do_analyzing(test_file)
