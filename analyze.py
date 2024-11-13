import pyshark
import os
from collections import defaultdict
from tqdm import tqdm
from dataclasses import dataclass
from pyshark.packet.packet import Packet
import matplotlib.pyplot as plt
import avro.schema
from avro.datafile import DataFileReader, DataFileWriter
from avro.io import DatumReader, DatumWriter
from treelib import Node, Tree


# packet to store the minimum amount of data
#    needed for analaysis so that memory can be reclaimed
@dataclass
class TruncatedPacket:
    time_stamp: float
    advertising_address: str
    power_level: float
    company_id: int


def top_n_packets_by_address(
    packets: list[TruncatedPacket], n: int = 100
) -> dict[str, list[TruncatedPacket]]:
    advertising_address_to_packets: dict[str, list[TruncatedPacket]] = {}
    for packet in packets:
        if packet.advertising_address in advertising_address_to_packets:
            advertising_address_to_packets[packet.advertising_address].append(packet)
        else:
            advertising_address_to_packets[packet.advertising_address] = [packet]

    packet_sort = lambda packets: len(packets[1])
    top_packets = sorted(
        advertising_address_to_packets.items(), key=packet_sort, reverse=True
    )[:n]
    top_advertising_address_to_packets: dict[str, list[TruncatedPacket]] = {}
    for address, packets in top_packets:
        top_advertising_address_to_packets[address] = packets
    return top_advertising_address_to_packets


@dataclass
class PacketAggregateInfo:
    advertising_address: str
    average_difference: float
    first_packet: TruncatedPacket
    last_packet: TruncatedPacket
    next_group_candidates: list[tuple[float, "PacketAggregateInfo"]]

    def __hash__(self):
        return hash(self.advertising_address)

    # ensures that the treelib library has a comparible types for finding parents
    def __eq__(self, other: "object"):
        return self.advertising_address == other.advertising_address  # pyright: ignore

    def __str__(self) -> str:
        return str(self.advertising_address)

    def __repr__(self) -> str:
        return f"""
                addr={self.advertising_address}, \
                min={self.first_packet.time_stamp},\
                max={self.first_packet.time_stamp},\
                avg_dif{self.average_difference}"\
                """

    def show_tree(self):
        tree = Tree()
        tree.create_node(
            # tag=f"Mapping for {self}, company_id={self.first_packet.company_id} power_level={self.first_packet.power_level}",
            tag=f"Mapping for {self}",
            identifier=str(self.advertising_address),
        )
        self.branch(tree)
        print(tree.show(stdout=False))

    def branch(self, tree: Tree, path: str = ""):
        for i, (probability, packet_aggregate) in enumerate(self.next_group_candidates):
            new_path = path + str(i)
            tree.create_node(
                # tag=f"{packet_aggregate} company_id={packet_aggregate.first_packet.company_id} power_level={packet_aggregate.first_packet.power_level} {int(probability*100)}%",
                tag=f"{packet_aggregate} {int(probability*100)}%",
                identifier=f"{packet_aggregate.advertising_address}{new_path}",
                parent=f"{self.advertising_address}{path}",
            )
            packet_aggregate.branch(tree, new_path)


BUFFER_TIME_MILLIS = 500


class PacketAnalysisBuffer:
    def __init__(self) -> None:
        self.packets_in_buffer: list[TruncatedPacket] = []
        self.packet_count_in_buffer: dict[str, int] = defaultdict(int)
        self.advertising_address_to_packet_aggregate_info: dict[
            str, PacketAggregateInfo
        ]

    def add_packet(self, packet: TruncatedPacket):
        self.packet_count_in_buffer[packet.advertising_address] += 1
        self.packets_in_buffer.append(packet)

    def resolve_packets_in_buffer(self, current_time: float):
        while len(self.packets_in_buffer) > 0 and self.packets_in_buffer[
            0
        ].time_stamp < (current_time - BUFFER_TIME_MILLIS):
            entry_packet = self.packets_in_buffer.pop(0)
            self.packet_count_in_buffer[entry_packet.advertising_address] -= 1
        pass


# ananlyze
def analyze_packets_cmd_out(packets: list[TruncatedPacket], current_time: float):
    # ARBITRARY SCALING TODO MAYBE CHANGE AROUND
    # the idea is that if the average difference between the packets is not close
    #     to the difference between the previous packets of that address then its not
    #     the same device
    # advertising_address_to_packets = top_n_packets_by_address(packets, 300)
    advertising_address_to_counter: dict[str, int] = defaultdict(int)
    advertising_address_to_max_time_stamp: dict[str, float] = {}
    buffer_advertising_address_to_counter: dict[str, int] = defaultdict(int)
    advertising_address_to_connected_addres: dict[str, str] = {}
    for packet in packets:
        advertising_address_to_counter[packet.advertising_address] += 1
        advertising_address_to_max_time_stamp[packet.advertising_address] = (
            packet.time_stamp
        )
        if packet.time_stamp > current_time - BUFFER_TIME_MILLIS:
            buffer_advertising_address_to_counter[packet.advertising_address] += 1

    return


def get_refined_aggregate_order(
    refined_aggregate_order: list[PacketAggregateInfo],
    packet_aggregate: PacketAggregateInfo,
):
    if packet_aggregate in refined_aggregate_order:
        return
    refined_aggregate_order.append(packet_aggregate)
    for candidate in packet_aggregate.next_group_candidates:
        get_refined_aggregate_order(refined_aggregate_order, candidate[1])


def n_milli_seconds_after(
    p1: PacketAggregateInfo, p2: PacketAggregateInfo, n: float
) -> bool:
    n = n / 100
    milliseconds_after = p2.first_packet.time_stamp - p1.last_packet.time_stamp
    if milliseconds_after < n and milliseconds_after > 0:
        return True
    return False


# creates graph using time_stmap advertising address
def analyze_packets_basic2d(packets: list[TruncatedPacket]):
    start_time = 0  # can change to the first packet's time
    address_to_index: dict[str, int] = {}
    index_to_packets: dict[int, list[TruncatedPacket]] = {}
    last_index = 0
    for packet in packets:
        if packet.advertising_address in address_to_index:
            index = address_to_index[packet.advertising_address]
            index_to_packets[index].append(packet)
            # print(packet.company_id, end=",")
        else:
            # print("\n-----------------------------\n")
            address_to_index[packet.advertising_address] = last_index
            index_to_packets[last_index] = [packet]
            last_index += 1

    for index in address_to_index.values():
        packets = index_to_packets[index]
        x_values = list(map(lambda p: p.time_stamp - start_time, packets))
        y_values = [index] * len(packets)
        plt.plot(x_values, y_values, marker="o", linestyle="None")

    plt.xlabel("Time since first packet")
    plt.ylabel("Indexed Packet Address")
    if len(address_to_index.keys()) <= 50:
        plt.legend()
    plt.title("Packet Analaysis")
    plt.show()


def get_packets_from_pcapng(
    file_path: str, amount_of_packets: int
) -> list[TruncatedPacket]:
    capture = pyshark.FileCapture(file_path)
    truncated_packets: list[TruncatedPacket] = []
    progress_bar = tqdm(
        total=amount_of_packets, bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}"
    )
    for packet in capture:
        packet: Packet
        for layer_obj in packet.layers:
            if layer_obj.layer_name == "btle":
                # layer_obj have a useful attribute called field names which tells
                #   all the attributes of a layer_obj
                time_stamp = float(packet.sniff_timestamp)  # pyright: ignore
                # if time_stamp > 100: continue
                field_names = layer_obj.field_names
                if "advertising_address" in field_names:
                    power_level = 0
                    company_id = "0xFFFF"  # default / special use
                    if "btcommon_eir_ad_entry_power_level" in field_names:
                        try:
                            power_level = int(
                                layer_obj.btcommon_eir_ad_entry_power_level
                            )
                        except ValueError:
                            pass
                    if "btcommon_eir_ad_entry_company_id" in field_names:
                        company_id = layer_obj.btcommon_eir_ad_entry_company_id

                    truncated_packet = TruncatedPacket(
                        time_stamp=time_stamp,
                        advertising_address=layer_obj.advertising_address,
                        power_level=power_level,
                        company_id=int(company_id, 16),  # pyright: ignore
                    )
                    truncated_packets.append(truncated_packet)
                else:
                    # There are some btle packet which do not have an advertising
                    #    ip... may want to do something with them later
                    pass

        progress_bar.update()
    progress_bar.close()
    capture.close()
    return truncated_packets


def get_packets_from_avro(file_path: str, numPackets: int) -> list[TruncatedPacket]:
    reader = DataFileReader(open(file_path, "rb"), DatumReader())
    progress_bar = tqdm(
        total=numPackets, bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}"
    )
    packets = []

    # time mac is a dict object
    for time_mac in reader:
        packet = TruncatedPacket(
            time_stamp=time_mac.get("time_stamp"),  # pyright: ignore
            advertising_address=time_mac.get("advertising_address"),  # pyright: ignore
            power_level=time_mac.get("power_level"),  # pyright: ignore
            company_id=time_mac.get("company_id"),  # pyright: ignore
        )
        packets.append(packet)
        progress_bar.update()
    progress_bar.close()
    # displayAvro(file_path)
    return packets


def write_to_avro(file_path: str, packets: list[TruncatedPacket]):
    schema = avro.schema.parse(open("./avro/timeMacPair.avsc", "rb").read())
    writer = DataFileWriter(open(file_path, "wb"), DatumWriter(), schema)
    for packet in packets:
        writer.append(
            {
                "time_stamp": packet.time_stamp,
                "advertising_address": format_mac(packet.advertising_address),
                "power_level": packet.power_level,
                "company_id": packet.company_id,
            }
        )
        # print(packet.time_stamp)
    writer.close()


def do_analyzing(file_path: str, amount_of_packets: int = 0, is_fresh=False):
    base_file_name, _ = os.path.splitext(os.path.basename(file_path))

    possibly_cached_avro = os.path.join(
        os.getcwd(), "cached_captures", base_file_name + ".avro"
    )
    if os.path.exists(possibly_cached_avro) and not is_fresh:
        print("Using the cached avro")
        packets = get_packets_from_avro(possibly_cached_avro, amount_of_packets)
    else:
        packets = get_packets_from_pcapng(file_path, amount_of_packets)
        write_to_avro(possibly_cached_avro, packets)

    refined_order_packets = analyze_packets_cmd_out(packets)
    print(len(refined_order_packets))
    analyze_packets_basic2d(refined_order_packets)


def format_mac(address: str) -> int:
    mac_address = address.replace(":", "")
    return int(mac_address, 16)


def displayAvro(file_path):
    reader = DataFileReader(open(file_path, "rb"), DatumReader())
    for time_mac in reader:
        packet = TruncatedPacket(
            time_stamp=time_mac.get("time_stamp"),  # pyright: ignore
            advertising_address=time_mac.get("advertising_address"),  # pyright: ignore
            power_level=time_mac.get("power_level"),  # pyright: ignore
        )
        print(packet)


if __name__ == "__main__":
    # just a random test
    test_file = os.path.join(os.getcwd(), "valentineCaptures", "bose2.pcapng")
    do_analyzing(test_file)
