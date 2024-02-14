import pyshark
from pyshark.packet.packet import Packet
from pyshark.packet.fields import LayerFieldsContainer
import matplotlib.pyplot as plt


def analyze_packet(file_path: str):
    capture = pyshark.FileCapture(file_path)
    packet_advertising_address: dict[str, list[Packet]] = {

            }
    for packet in capture:
        packet: Packet
        for layer_obj in packet.layers:
            if layer_obj.layer_name == 'btle':
                # layer_obj have a useful attribute called field names which tells
                #   all the attributes of a layer_obj
                field_names = layer_obj.field_names
                if "advertising_address" in field_names:
                    if layer_obj.advertising_address in packet_advertising_address:
                        packet_advertising_address[layer_obj.advertising_address].append(packet)
                    else: 
                        packet_advertising_address[layer_obj.advertising_address] = [packet]
                else:
                    # There are some btle packet which do not have an advertising
                    #    ip
                    pass
    capture.close()


    time_of_first_packet = capture[0].sniff_time.timestamp()
    packet_sort = lambda packets: len(packets[1])
    top_ten_set_of_packets = sorted(packet_advertising_address.items(), key=packet_sort, reverse=True)[:100]
    for i, (_, packets) in enumerate(top_ten_set_of_packets):
        x_values = list(map(lambda p: p.sniff_time.timestamp() - time_of_first_packet, packets)) 
        y_values = [i + 1] * len(packets)
        plt.plot(x_values, y_values, marker='o', linestyle='None', label=f'Packet set {i + 1}')
    plt.xlabel('Time since first packet')
    plt.ylabel('Packet number')
    plt.title('Packet Analaysis')
    plt.show()


if __name__ == "__main__":
    analyze_packet("./test_captures/10SecondtestFlipperSpoofing.pcapng")
