
import scapy.all as scapy
import optparse


def scan(ip):
    arpreq = scapy.ARP(pdst=ip)  # creating an arp request with given ip
    # or ---------------------------------
    # arpreq.pdst = ip   # we are changing the value of the field(pdst) in the packet to the given "ip"
    # print(arpreq.summary())
    # scapy.ls(scapy.ARP(pdst=ip))  # we are showing the default properties of the scapy.ARP class
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")  # creating an ethernet broadcast instance
    # scapy.ls(scapy.Ether())  # we are showing the default properties of the scapy.ARP class
    arp_broad = broadcast / arpreq  # combining the two
    # arp_broad.show()
    answered_list = scapy.srp(arp_broad, timeout=1, verbose=False)[0]  # sending packet and returning a response
    # print((answered_list.summary()))
    connected_list = []
    #  parsing mac addresses
    for i in answered_list:
        connected_dict = {"ip": i[1].psrc, "mac": i[1].hwsrc}
        connected_list.append(connected_dict)  # we create a list of dictionaries of the connected people
        # i[1].show()  #  used tp show us the fields that we need to show the src ip and the src mac address
    return connected_list


def printing_connected(dctio):
    print(
        "|_________________________________________________________________________|\n|IP|\t\t\t|MAC address\n-------------------------------------------------------------------------|")
    for client in dctio:
        print("|" + client["ip"] + "|\t\t|" + client["mac"] +
              "\n-------------------------------------------------------------------------|")


def get_options():
    parser = optparse.OptionParser()
    parser.add_option("-c", '--client', dest='client', help="client IP address/ IP range")
    (option_s, argument) = parser.parse_args()
    return option_s


options = get_options()
dct = scan(options.client)
printing_connected(dct)
