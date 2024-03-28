import pyshark
from statistics import mean
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
    power_level: float

def top_n_packets_by_address(packets: list[TruncatedPacket], n: int=100) -> dict[str, list[TruncatedPacket]]:
    advertising_address_to_packets: dict[str, list[TruncatedPacket]] = {}
    for packet in packets:
        if packet.advertising_address in advertising_address_to_packets:
            advertising_address_to_packets[packet.advertising_address].append(packet)
        else:
            advertising_address_to_packets[packet.advertising_address] = [packet]

    packet_sort = lambda packets: len(packets[1])
    top_packets = sorted(advertising_address_to_packets.items(), key=packet_sort, reverse=True)[:n]
    top_advertising_address_to_packets: dict[str, list[TruncatedPacket]] = {}
    for address, packets in top_packets:
        top_advertising_address_to_packets[address] = packets
    return top_advertising_address_to_packets 

@dataclass
class PacketAggregateInfo:
    advertising_address: str
    average_difference: float
    min: float
    max: float

    def __str__(self) -> str:
        return f"{self.advertising_address}, {self.min}, {self.max}, {self.average_difference}"

# ananlyze 
def analyze_packets_cmd_out(packets: list[TruncatedPacket]):
    advertising_address_to_packets = top_n_packets_by_address(packets, 10)
    advertising_address_to_packet_info: dict[str, PacketAggregateInfo] = {}
    for advertising_address, packets in advertising_address_to_packets.items():
        if 2 > len(packets): continue
        # may need to sort this idkk
        differences = [packets[i+1].time_stamp - packets[i].time_stamp for i in range(len(packets) - 1)]
        advertising_address_to_packet_info[advertising_address] = PacketAggregateInfo(
                advertising_address=advertising_address,
                average_difference=mean(differences),
                min=min(packets, key=lambda p: p.time_stamp).time_stamp,
                max=max(packets, key=lambda p: p.time_stamp).time_stamp,
                )
    for packet_aggregate in advertising_address_to_packet_info.values():
        packet_aggregates = list(advertising_address_to_packet_info.values())
        packets_after = list(filter(lambda p: p.min > packet_aggregate.max, packet_aggregates))
        if len(packets_after) == 0: continue
        min_packet_aggregate = min(packets_after, key=lambda p: p.min)

        # ARBITRARY SCALING TODO MAYBE CHANGE AROUND
        # the idea is that if the average difference between the packets is not close
        #     to the difference between the previous packets of that address then its not
        #     the same device
        if min_packet_aggregate.min - packet_aggregate.max >  \
                packet_aggregate.average_difference * 2:
                    continue

        print(f"Address {packet_aggregate} might map to ->")
        print(f"       {min_packet_aggregate}")







# creates graph using time_stmap advertising address
def analyze_packets_basic2d(packets: list[TruncatedPacket]):
    time_of_first_packet = packets[0].time_stamp
    advertising_address_to_packets = top_n_packets_by_address(packets, 10)
    for i, (advertising_address, packets) in enumerate(advertising_address_to_packets.items()):
        x_values = list(map(lambda p: p.time_stamp - time_of_first_packet, packets)) 
        y_values = [i + 1] * len(packets)
        plt.plot(x_values, y_values, marker='o', linestyle='None', label=f'Packet set {advertising_address}')
    plt.xlabel('Time since first packet')
    plt.ylabel('Packet number')
    plt.legend()
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
                print(field_names)
                if "advertising_address" in field_names  \
                        and "btcommon_eir_ad_entry_power_level" in field_names:
                    truncated_packet = TruncatedPacket(
                            time_stamp=time_stamp,
                            advertising_address=layer_obj.advertising_address,
                            power_level=layer_obj.btcommon_eir_ad_entry_power_level
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
    progress_bar = tqdm(total=len(df) , bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt}')
    packets = []
    for _, row in df.iterrows():
        person = TruncatedPacket(
                time_stamp=float(row['time_stamp']),
                advertising_address=str(row['advertising_address']),
                power_level=float(row['power_level'])
                )
        packets.append(person)
        progress_bar.update()
    progress_bar.close()
    return packets

def write_to_csv(file_path: str, packets: list[TruncatedPacket]):
    data = {
            "time_stamp": [packet.time_stamp for packet in packets],
            "advertising_address": [packet.advertising_address for packet in packets],
            "power_level": [packet.power_level for packet in packets],
            }
    df = pd.DataFrame(data)
    df.to_csv(file_path, index=False)

def do_analyzing(file_path: str, amount_of_packets: int = 0, is_fresh = False):
    base_file_name, _ = os.path.splitext(os.path.basename(file_path))
    
    possibly_cached_csv = os.path.join(os.getcwd(), "cached_captures", base_file_name + ".csv")
    if os.path.exists(possibly_cached_csv) and (not is_fresh):
        print("Using the cached csv")
        packets = get_packets_from_csv(possibly_cached_csv)
    else:
        packets = get_packets_from_pcapng(file_path, amount_of_packets)
        write_to_csv(possibly_cached_csv, packets)

    analyze_packets_cmd_out(packets)
    analyze_packets_basic2d(packets)


if __name__ == "__main__":
    # just a random test
    test_file = os.path.join(os.getcwd(), "valentineCaptures", "bose2.pcapng")
    do_analyzing(test_file)
