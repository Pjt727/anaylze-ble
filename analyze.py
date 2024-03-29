import pyshark
import os
from tqdm import tqdm
from dataclasses import dataclass
from pyshark.packet.packet import Packet
import matplotlib.pyplot as plt
import avro.schema
from avro.datafile import DataFileReader, DataFileWriter
from avro.io import DatumReader, DatumWriter

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
        return f"addr={self.advertising_address}, min={self.min}, max={self.max}, avg_dif{self.average_difference}"

# ananlyze 
def analyze_packets_cmd_out(packets: list[TruncatedPacket]):
    # ARBITRARY SCALING TODO MAYBE CHANGE AROUND
    # the idea is that if the average difference between the packets is not close
    #     to the difference between the previous packets of that address then its not
    #     the same device
    CONFIDANCE_FACTOR = 1.25
    advertising_address_to_packets = top_n_packets_by_address(packets, 10)
    advertising_address_to_packet_info: dict[str, PacketAggregateInfo] = {}
    for advertising_address, packets in advertising_address_to_packets.items():
        if 2 > len(packets): continue
        # may need to sort this idkk
        differences = [packets[i+1].time_stamp - packets[i].time_stamp for i in range(len(packets) - 1)]
        advertising_address_to_packet_info[advertising_address] = PacketAggregateInfo(
                advertising_address=advertising_address,
                average_difference=sum(differences)/ len(differences),
                min=min(packets, key=lambda p: p.time_stamp).time_stamp,
                max=max(packets, key=lambda p: p.time_stamp).time_stamp,
                )

    for packet_aggregate in advertising_address_to_packet_info.values():
        packet_aggregates = list(advertising_address_to_packet_info.values())
        packets_after = list(filter(lambda p: p.min > packet_aggregate.max, packet_aggregates))
        if len(packets_after) == 0: continue
        packets_after.sort(key=lambda p: p.min)

        print(f"Packet addr={packet_aggregate.advertising_address} might map to ->")
        # the average time between all packets should also be similar 
        for after_aggrrgate2 in packets_after:
            max_avg_time =  packet_aggregate.average_difference * CONFIDANCE_FACTOR 
            min_avg_time = packet_aggregate.average_difference * (1/CONFIDANCE_FACTOR) 
            print(f"       addr={after_aggrrgate2.advertising_address}")
            if after_aggrrgate2.average_difference > max_avg_time\
                    or after_aggrrgate2.average_difference < min_avg_time:
                        print("^^^^^^^NOT CONFIDANT^^^^^^^")
                        continue




# creates graph using time_stmap advertising address
def analyze_packets_basic2d(packets: list[TruncatedPacket]):
    time_of_first_packet = packets[0].time_stamp
    advertising_address_to_packets = top_n_packets_by_address(packets, 10)
    for i, (advertising_address, packets) in enumerate(advertising_address_to_packets.items()):
        x_values = list(map(lambda p: p.time_stamp - time_of_first_packet, packets)) 
        y_values = [i + 1] * len(packets)
        plt.plot(x_values, y_values, marker='o', linestyle='None', label=f'Packet set {advertising_address}')
    plt.xlabel('Time since first packet')
    plt.ylabel('Indexed Packet Address')
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
                # TODO look deper into company_id
                #if "btcommon_eir_ad_entry_company_id" in field_names:
                #    print(layer_obj.btcommon_eir_ad_entry_company_id)
                if "advertising_address" in field_names :
                    power_level = 0
                    if "btcommon_eir_ad_entry_power_level" in field_names:
                        power_level = layer_obj.btcommon_eir_ad_entry_power_level

                    truncated_packet = TruncatedPacket(
                            time_stamp=time_stamp,
                            advertising_address=layer_obj.advertising_address,
                            power_level=power_level
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

def get_packets_from_avro(file_path: str, numPackets: int) -> list[TruncatedPacket]:
    reader = DataFileReader(open(file_path, "rb"), DatumReader())
    progress_bar = tqdm(total=numPackets, bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt}')
    packets = []

    # time mac is a dict object
    for time_mac in reader:
        packet = TruncatedPacket(
                time_stamp = time_mac.get("time_stamp"), # pyright: ignore
                advertising_address = time_mac.get("advertising_address"), # pyright: ignore
                power_level = time_mac.get("power_level"), #pyright: ignore
        )
        packets.append(packet)
        progress_bar.update()
    progress_bar.close()
    # displayAvro(file_path)
    return packets


def write_to_avro(file_path: str, packets: list[TruncatedPacket]):
    schema = avro.schema.parse(open("./avro/timeMacPair.avsc", "rb").read()) # pyright: ignore
    writer = DataFileWriter(open(file_path, "wb"), DatumWriter(), schema)
    for packet in packets:
        writer.append({
            "time_stamp": packet.time_stamp,
            "advertising_address": format_mac(packet.advertising_address),
            "power_level": packet.power_level,
            })
        # print(packet.time_stamp)
    writer.close()

def do_analyzing(file_path: str, amount_of_packets: int = 0, is_fresh = False):
    base_file_name, _ = os.path.splitext(os.path.basename(file_path))
    

    possibly_cached_avro = os.path.join(os.getcwd(), "cached_captures", base_file_name + ".avro")
    if os.path.exists(possibly_cached_avro) and not is_fresh:
        print("Using the cached avro")
        packets = get_packets_from_avro(possibly_cached_avro, amount_of_packets)
    else:
        packets = get_packets_from_pcapng(file_path, amount_of_packets)
        write_to_avro(possibly_cached_avro, packets)

    analyze_packets_cmd_out(packets)
    analyze_packets_basic2d(packets)

def format_mac(address: str) -> int:
    mac_address = address.replace(':', '')
    return int(mac_address, 16)

def displayAvro(file_path):
    reader = DataFileReader(open(file_path, "rb"), DatumReader())
    for time_mac in reader:
        packet = TruncatedPacket(
                time_stamp = time_mac.get("time_stamp"), # pyright: ignore
                advertising_address = time_mac.get("advertising_address"), # pyright: ignore
                power_level = time_mac.get("power_level"), #pyright: ignore
        )
        print(packet)

if __name__ == "__main__":
    # just a random test
    test_file = os.path.join(os.getcwd(), "valentineCaptures", "bose2.pcapng")
    do_analyzing(test_file)
