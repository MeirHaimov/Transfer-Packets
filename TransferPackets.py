import re


class Packet:
    # constructor
    def __init__(self, source_address, destination_address, sequence_number,
                 is_ack=False, data=None):
        self.__source_address = source_address
        self.__destination_address = destination_address
        self.__sequence_number = sequence_number
        self.__is_ack = is_ack
        self.__data = data

    # method to print the fields of the packet
    def __repr__(self):
        return f"Packet(Source IP: {self.__source_address}, Dest IP: {self.__destination_address}, #Seq: {self.__sequence_number}, Is ACK: {self.__is_ack}, Data: {self.__data})"

    # get methods
    def get_source_address(self):
        return self.__source_address

    def get_destination_address(self):
        return self.__destination_address

    def get_sequence_number(self):
        return self.__sequence_number

    def get_is_ack(self):
        return self.__is_ack

    def get_data(self):
        return self.__data


class Communicator:
    # constructor
    def __init__(self, address):
        self.__address = address
        self.__current_seq_num = None

    # get and sets methods
    def get_address(self):
        return self.__address

    def get_current_sequence_number(self):
        return self.__current_seq_num

    def set_current_sequence_number(self, seq_num):
        self.__current_seq_num = seq_num

    # method to print when packet sent
    def send_packet(self, packet):
        print("Sender: Packet Seq Num: " + str(packet.get_sequence_number()) + " was sent")
        return packet

    # method to increment the sequence number by 1
    def increment_current_seq_num(self):
        self.set_current_sequence_number(self.get_current_sequence_number() + 1)


class Sender(Communicator):
    # constructor with checking num of letters
    def __init__(self, address, num_letters_in_packet):
        super().__init__(address)
        if num_letters_in_packet <= 0:
            print("The number of letters in the packet needs to be greater than 1")
        self.__num_letters_in_packet = num_letters_in_packet

    # method to prepare packets
    def prepare_packets(self, message, destination_address):
        packets = []
        if not message:     # if it empty
            print("Not sending an empty string ! ")
            exit()

        elif specielch(message):  # Check if message contains only special characters
            print("Message contains only special characters.")
            exit()  # exit the program if the message contains only special characters
        else:
            for i in range(0, len(message), self.__num_letters_in_packet):
                content = message[i:i + self.__num_letters_in_packet].ljust(self.__num_letters_in_packet)
                packet = Packet(self.get_address(), destination_address, i // self.__num_letters_in_packet, data=content)
                packets.append(packet)
            return packets

    # method to check if the acknowledgment packet indicates acknowledgment
    def receive_ack(self, acknowledgment_packet):
        return acknowledgment_packet.get_is_ack()


class Receiver(Communicator):
    # constructor
    def __init__(self, address):
        super().__init__(address)
        self.received_packets = []

    # method to receive packet
    def receive_packet(self, packet):
        self.received_packets.append(packet)
        acknowledgment = Packet(packet.get_destination_address(), packet.get_source_address(),packet.get_sequence_number(), True, "ACK")
        if acknowledgment.get_is_ack():
            print("Receiver: Received packet seq num: " + str(acknowledgment.get_sequence_number()))
        return acknowledgment

    # method to get the message from received packets
    def get_message_by_received_packets(self):
        message = ""
        for packet in self.received_packets:
            message += packet.get_data()
        return message


# function to check if the input string contains only special characters
def specielch(input_string):
    pat = r'^[!~@#$%^&*(){}\'?|\\]*$'
    match = re.match(pat, input_string)
    return match is not None


if __name__ == '__main__':
    source_address = "192.168.1.1"
    destination_address = "192.168.2.2"
    message = "*^&^&^ !@#$%"
    num_letters_in_packet = 4

    sender = Sender(source_address, num_letters_in_packet)
    receiver = Receiver(destination_address)

    packets = sender.prepare_packets(message, receiver.get_address())

    # setting current packet
    start_interval_index = packets[0].get_sequence_number()
    # setting current packet in the sender and receiver
    sender.set_current_sequence_number(start_interval_index)
    receiver.set_current_sequence_number(start_interval_index)

    # setting the last packet
    last_packet_sequence_num = packets[-1].get_sequence_number()
    receiver_current_packet = receiver.get_current_sequence_number()

    while receiver_current_packet <= last_packet_sequence_num:
        current_index = sender.get_current_sequence_number()
        packet = packets[current_index]
        packet = sender.send_packet(packet)

        ack = receiver.receive_packet(packet)

        result = sender.receive_ack(ack)

        if result == True:
            sender.increment_current_seq_num()
            receiver.increment_current_seq_num()

        receiver_current_packet = receiver.get_current_sequence_number()

    full_message = receiver.get_message_by_received_packets()
    print(f"Receiver message: {full_message}")
