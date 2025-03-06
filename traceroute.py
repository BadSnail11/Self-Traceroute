import os
import socket
import struct
import time
import argparse

def checksum(source_string):
    """
    Рассчет контрольной суммы для ICMP-пакета.
    """
    sum = 0
    count_to = (len(source_string) // 2) * 2
    count = 0

    while count < count_to:
        this_val = source_string[count + 1] * 256 + source_string[count]
        sum = sum + this_val
        sum = sum & 0xffffffff
        count = count + 2

    if count_to < len(source_string):
        sum = sum + source_string[len(source_string) - 1]
        sum = sum & 0xffffffff

    sum = (sum >> 16) + (sum & 0xffff)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

def create_icmp_packet(id, seq):
    """
    Создание ICMP-пакета.
    """
    icmp_type = 8  # Echo Request
    icmp_code = 0
    icmp_checksum = 0
    icmp_id = id
    icmp_seq = seq
    icmp_data = b"abcdefghijklmnopqrstuvwxyz"

    header = struct.pack("!BBHHH", icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
    packet = header + icmp_data

    icmp_checksum = checksum(packet)
    header = struct.pack("!BBHHH", icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
    packet = header + icmp_data

    return packet

def traceroute(dest_addr, max_hops=30, timeout=1, resolve_names=True):
    """
    Основная функция traceroute.
    """
    dest_addr = socket.gethostbyname(dest_addr)
    port = 33434

    print(f"traceroute to {dest_addr} ({dest_addr}), {max_hops} hops max")

    for ttl in range(1, max_hops + 1):
        send_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        send_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

        recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        recv_socket.bind(("", port))
        recv_socket.settimeout(timeout)

        packet_id = os.getpid() & 0xFFFF
        packet = create_icmp_packet(packet_id, ttl)
        send_socket.sendto(packet, (dest_addr, port))

        start_time = time.time()
        curr_addr = None
        curr_name = None
        finished = False

        try:
            data, curr_addr = recv_socket.recvfrom(1024)
            curr_addr = curr_addr[0]

            icmp_header = data[20:28]
            icmp_type, code, checksum, received_id, seq = struct.unpack("!BBHHH", icmp_header)

            if icmp_type == 0:
                finished = True

            if resolve_names:
                try:
                    curr_name = socket.gethostbyaddr(curr_addr)[0]
                except socket.error:
                    curr_name = curr_addr
            else:
                curr_name = curr_addr
        except:
            curr_addr = None
        finally:
            send_socket.close()
            recv_socket.close()

        if curr_addr is not None:
            print(f"{ttl}\t{curr_name}\t{(time.time() - start_time) * 1000:.2f} ms")
        else:
            print(f"{ttl}\t*\t*\t*")

        if finished:
            break

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple traceroute implementation using ICMP.")
    parser.add_argument("destination", type=str, help="The destination address to trace.")
    parser.add_argument("-n", "--no-resolve", action="store_false", dest="resolve_names",
                        help="Do not resolve IP addresses to hostnames.")
    args = parser.parse_args()

    traceroute(args.destination, resolve_names=args.resolve_names)
