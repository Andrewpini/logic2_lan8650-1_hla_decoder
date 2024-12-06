# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting
from TC6lookup import MemoryMapLookup


from enum import Enum


class ChunkType(Enum):
    EMPTY_CHUNK = 1
    ATOMIC_CHUNK = 2
    START_CHUNK = 3
    END_CHUNK = 4
    INTERMEDIATE_CHUNK = 5
    UNKNOWN_CHUNK = 6

    def __str__(self):
        """
        Returns a formatted string representation of the enum value:
        - Capitalizes the first letter.
        - Replaces underscores with spaces.
        """
        return self.name.replace("_", " ").capitalize()


class ChunkBufStatus(Enum):
    SUCCESS = 0
    LAST_BYTE_POPULATED = 1
    NO_ROOM = 2


class NetType:
    def __init__(self, net_type, trans_type=None):
        """
        Initializes the NetType with a mandatory net_type and an optional trans_type.

        :param net_type: The network type (mandatory).
        :param trans_type: The transport type (optional, defaults to None).
        """
        self.net_type = net_type
        self.trans_type = trans_type

    def __str__(self):
        """
        Returns the string representation of the NetType:
        - If only net_type is provided, returns net_type.
        - If both net_type and trans_type are provided, returns "trans_type/net_type".
        """
        if self.trans_type:
            return f"{self.trans_type}/{self.net_type}"
        return self.net_type


class ChunkTrainIdx:
    def __init__(self, major, minor=None):
        """
        Initializes the ChunkTrainIdx with a major ID and an optional minor ID.

        :param major: The major ID (required, typically the frame ID).
        :param minor: The minor ID (optional, typically the chunk ID, defaults to None).
        """
        self.major = major
        self.minor = minor

    def __str__(self):
        """
        Returns the concatenated major and minor ID if both are present,
        otherwise only the major ID.
        """
        return f"{self.major}.{self.minor}" if self.minor else f"{self.major}"


class ChunkBuf:
    def __init__(self, size):
        """
        Initializes the ChunkBuf with a given size.

        :param size: The size of the buffer (bytearray).
        """
        self.length = 0  # Number of bytes currently in the buffer
        self.buf = bytearray(size)  # Buffer initialized with the given size
        self.parsable = False

    def append_byte(self, byte):
        """
        Appends a single byte to the buffer if there's room.

        :param byte: The byte to append (0-255).
        :return: ChunkBufStatus - The status of the append operation.
        """
        if not isinstance(byte, bytes):
            raise ValueError("Input must be a single byte (0-255).")

        if self.length >= len(self.buf):
            return ChunkBufStatus.NO_ROOM

        self.buf[self.length] = byte[0]
        self.length += 1

        if self.length == len(self.buf):
            self.parsable = True
            return ChunkBufStatus.LAST_BYTE_POPULATED

        return ChunkBufStatus.SUCCESS


class ChunkMeta(ChunkBuf):
    def __init__(self):
        """
        Initializes the ChunkMeta with a fixed buffer size of 4 bytes.
        Inherits initialization from ChunkBuf.
        """
        super().__init__(4)  # Initialize ChunkBuf with size 4

    def chunk_type_get(self):
        """
        Determines the type of the chunk based on the metadata in the buffer.
        Assumes the buffer is fully populated (4 bytes).

        :return: A ChunkType enum representing the chunk type.
        """
        if not self.parsable:
            return ChunkType.UNKNOWN_CHUNK

        # Convert the buffer to a 32-bit integer
        metadata = int.from_bytes(self.buf, byteorder="big")

        # Extract relevant flags
        start_valid = (metadata >> 20) & 0x1
        end_valid = (metadata >> 14) & 0x1
        data_valid = (metadata >> 21) & 0x1

        # Determine the chunk type
        if data_valid != 1:
            return ChunkType.EMPTY_CHUNK
        if start_valid == 1 and end_valid == 1:
            return ChunkType.ATOMIC_CHUNK
        if start_valid == 1:
            return ChunkType.START_CHUNK
        if end_valid == 1:
            return ChunkType.END_CHUNK
        return ChunkType.INTERMEDIATE_CHUNK


class ChunkFooter(ChunkMeta):

    def _parse(self):
        """
        Parses the 4-byte footer into its respective fields.
        Assumes the buffer is fully populated (4 bytes).

        :return: A dictionary containing the parsed footer fields.
        """
        if self.length < 4:
            raise ValueError("Footer is incomplete; requires 4 bytes.")

        # Convert the buffer to a 32-bit integer
        footer = int.from_bytes(self.buf, byteorder="big")

        return {
            "EXST": (footer >> 31) & 0x1,
            "HDRB": (footer >> 30) & 0x1,
            "SYNC": (footer >> 29) & 0x1,
            "RCA": (footer >> 24) & 0x1F,
            "VS": (footer >> 22) & 0x3,
            "DV": (footer >> 21) & 0x1,
            "SV": (footer >> 20) & 0x1,
            "SWO": (footer >> 16) & 0xF,
            "FD": (footer >> 15) & 0x1,
            "EV": (footer >> 14) & 0x1,
            "EBO": (footer >> 8) & 0x3F,
            "RTSA": (footer >> 7) & 0x1,
            "RTSP": (footer >> 6) & 0x1,
            "TXC": (footer >> 1) & 0x1F,
            "P": footer & 0x1,
        }

    def __repr__(self):
        """
        Returns a string representation of the ChunkFooter metadata.
        Each field is represented in the format LABEL=0xHEX_VALUE.
        """
        if self.length < 4:
            return "(Incomplete)"

        fields = self._parse()
        metadata = ", ".join(f"{label}=0x{value:X}" for label, value in fields.items())
        return f"({metadata})"


class ChunkHeader(ChunkMeta):

    def _parse(self):
        """
        Parses the 4-byte header into its respective fields.
        Assumes the buffer is fully populated (4 bytes).

        :return: A dictionary containing the parsed header fields.
        """
        if self.length < 4:
            raise ValueError("Header is incomplete; requires 4 bytes.")

        # Convert the buffer to a 32-bit integer
        header = int.from_bytes(self.buf, byteorder="big")

        return {
            "DNC": (header >> 31) & 0x1,
            "SEQ": (header >> 30) & 0x1,
            "NORX": (header >> 29) & 0x1,
            "RSVD_28_24": (header >> 24) & 0x1F,
            "VS": (header >> 22) & 0x3,
            "DV": (header >> 21) & 0x1,
            "SV": (header >> 20) & 0x1,
            "SWO": (header >> 16) & 0xF,
            "RSVD_15": (header >> 15) & 0x1,
            "EV": (header >> 14) & 0x1,
            "EBO": (header >> 8) & 0x3F,
            "TSC": (header >> 6) & 0x3,
            "RSVD_5_1": (header >> 1) & 0x1F,
            "P": header & 0x1,
        }

    def __repr__(self):
        """
        Returns a string representation of the ChunkHeader metadata.
        Each field is represented in the format LABEL=0xHEX_VALUE.
        """
        if self.length < 4:
            return "(Incomplete)"

        fields = self._parse()
        metadata = ", ".join(f"{label}=0x{value:X}" for label, value in fields.items())
        return f"({metadata})"


class ChunkData(ChunkBuf):
    def __init__(self):
        """
        Initializes the ChunkData with a fixed buffer size of 64 bytes.
        """
        super().__init__(64)  # Initialize the base ChunkBuf with size 64
        self._protocol = NetType("Unknown")  # Store protocol after parsing
        self._ether_type = None  # Store EtherType after parsing
        self._dest_mac = None  # Store destination MAC
        self._src_mac = None  # Store source MAC

    def parse(self):
        """
        Parses the chunk to extract protocol and Ethernet header information.
        Called internally to parse data if it hasn't been parsed yet.
        """
        if self.length < 14:
            self._protocol = NetType("Unknown")
            return

        # Parse Ethernet header
        self._dest_mac = ":".join(f"{byte:02x}" for byte in self.buf[0:6])
        self._src_mac = ":".join(f"{byte:02x}" for byte in self.buf[6:12])
        self._ether_type = int.from_bytes(self.buf[12:14], byteorder="big")

        # Parse protocol
        if self._ether_type == 0x0800:  # IPv4
            if self.length >= 34:  # Minimum for Ethernet + IPv4 headers
                protocol = self.buf[14 + 9]  # Protocol field in IPv4 header
                protocol_map = {
                    1: "ICMP",
                    6: "TCP",
                    17: "UDP",
                }
                self._protocol = NetType("IPv4", protocol_map.get(protocol))
            else:
                self._protocol = NetType("IPv4", "Unknown")
        elif self._ether_type == 0x0806:  # ARP
            self._protocol = NetType("ARP")
        elif self._ether_type == 0x86DD:  # IPv6
            self._protocol = NetType("IPv6")
        else:
            self._protocol = NetType("Unknown (0x{self._ether_type:04x})")


    def protocol_get(self):
        """
        Returns the protocol type.

        :return: A string representing the protocol type.
        """

        return str(self._protocol)

    def protocol_not_app_set(self):
        """
        Set protocol type as empty.

        """
        self._protocol = NetType("N/A")
        self._ether_type = None
        self._dest_mac = None
        self._src_mac = None


    def __repr__(self):
        """
        Returns a string representation of the ChunkData, including protocol and raw content.
        - Protocol is parsed and displayed.
        - Data is shown in raw hex format without spaces between bytes.
        """
        protocol = self.protocol_get()
        raw_data = "".join(f"{byte:02X}" for byte in self.buf[:self.length])
        return f"0x{raw_data}"


class ChunkHandler:
    def __init__(self, mode):
        """
        Initializes the ChunkHandler for either 'miso' or 'mosi' mode.

        :param mode: A string, either 'miso' or 'mosi', indicating the mode.
        """
        if mode not in ["miso", "mosi"]:
            raise ValueError("Mode must be either 'miso' or 'mosi'.")

        self.mode = mode
        self.chunk_data = ChunkData()
        self.chunk_meta = ChunkFooter() if mode == "miso" else ChunkHeader()
        self.total_bytes = 68  # Total bytes expected (64 data + 4 footer/header)
        self.received_bytes = 0  # Counter for received bytes
        self.start_time = None
        self.end_time = None

        # New variables for tracking IDs
        self.chunk_id = None
        self.current_frame_id = 0
        self.current_chunk_id = 0
        self.is_new_frame = False  # Tracks if we're in a new frame

    def handle_byte(self, input_event):
        """
        Handles an incoming byte or control event.

        :param input_event: A dictionary containing the event information.
        """
        event_type = input_event.type
        start_time = input_event.start_time
        end_time = input_event.end_time
        data = input_event.data

        if event_type == "disable" or event_type == "enable":
            # Reset internal state on 'disable' or 'enable' events
            self.reset()
            return

        if event_type == "result":
            # Process the byte data
            miso = data.get("miso")
            mosi = data.get("mosi")

            # Determine the byte to append based on the mode
            byte = miso if self.mode == "miso" else mosi
            if byte is None:
                return  # Skip if no relevant byte is present

            # Handle the first byte's start_time
            if self.received_bytes == 0:
                self.start_time = start_time

            # Incrementally append the byte based on mode
            if self.mode == "miso":
                if self.received_bytes < 64:  # First 64 bytes go to ChunkData
                    self.chunk_data.append_byte(byte)
                elif self.received_bytes < self.total_bytes:  # Last 4 bytes go to ChunkFooter
                    self.chunk_meta.append_byte(byte)
            elif self.mode == "mosi":
                if self.received_bytes < 4:  # First 4 bytes go to ChunkHeader
                    self.chunk_meta.append_byte(byte)
                elif self.received_bytes < self.total_bytes:  # Last 64 bytes go to ChunkData
                    self.chunk_data.append_byte(byte)


            # Handle the last byte's end_time
            if self.received_bytes == self.total_bytes - 1:
                self.end_time = end_time

            # Update the received bytes counter
            self.received_bytes += 1

            # If all bytes are received, process the chunks
            if self.received_bytes == self.total_bytes:
                frame = self.process_chunks()
                self.reset()
                return frame

    def process_chunks(self):
        """
        Processes the parsed data from ChunkData and ChunkFooter/ChunkHeader.
        Returns an AnalyzerFrame object with the specified format and structure.
        """

        # Determine chunk type
        chunk_type = self.chunk_meta.chunk_type_get()

        # Unable to parse chunk type
        if chunk_type == ChunkType.UNKNOWN_CHUNK:
            meta = f"{''.join(f'{byte:02x}' for byte in self.chunk_meta.buf[:self.chunk_meta.length])}"
            payload = f"{''.join(f'{byte:02x}' for byte in self.chunk_data.buf[:self.chunk_data.length])}"

            if self.mode == 'miso':
                output = "0x" + payload + meta
            else:
                output = "0x" + meta + payload

            return AnalyzerFrame( 'Unknown Chunk', self.start_time, self.end_time,
                {'Raw_Bytes': output,}
            )

        # Update frame and chunk IDs
        self.update_ids(chunk_type)

        # Parse ethernet header if applicable otherwise overide protocol type
        if chunk_type == ChunkType.EMPTY_CHUNK:
            self.chunk_data.protocol_not_app_set()
        else:
            self.chunk_data.parse()

        # Decide protocol type
        if chunk_type == ChunkType.END_CHUNK or chunk_type == ChunkType.INTERMEDIATE_CHUNK:
            protocol = self.protocol_last
        else:
            protocol = self.chunk_data.protocol_get()

        # Store current protocol for eventual consecutive chunks
        if chunk_type == ChunkType.START_CHUNK:
            self.protocol_last = self.chunk_data.protocol_get()

        # Create and return the AnalyzerFrame
        return AnalyzerFrame(
            'Chunk',
            self.start_time,
            self.end_time,
            {
                'Chunk_Type': str(chunk_type),
                'Chunk_Idx': str(self.chunk_id),
                'Protocol_Type': protocol,
                'Header/Footer': repr(self.chunk_meta),
                'Payload': repr(self.chunk_data),
            }
        )

    def update_ids(self, chunk_type):
        """
        Updates the frame and chunk IDs based on the chunk type,
        using the ChunkTrainIdx class. Assigns specific rules for empty and atomic chunks.

        :param chunk_type: The type of the chunk.
        """
        if chunk_type == ChunkType.EMPTY_CHUNK:
            # Empty chunks get their own ID with only a major version
            self.current_frame_id += 1
            self.current_chunk_id = None  # Reset minor for empty chunks
            self.chunk_id = ChunkTrainIdx(self.current_frame_id)
            return

        if chunk_type == ChunkType.ATOMIC_CHUNK:
            # Atomic chunks get their own ID with only a major version
            self.current_frame_id += 1
            self.current_chunk_id = None  # Reset minor for atomic chunks
            self.chunk_id = ChunkTrainIdx(self.current_frame_id)
            return

        if chunk_type == ChunkType.START_CHUNK:
            # New frame starts
            self.current_frame_id += 1
            self.current_chunk_id = 1
            self.chunk_id = ChunkTrainIdx(self.current_frame_id, self.current_chunk_id)
            self.is_new_frame = True
        elif chunk_type == ChunkType.INTERMEDIATE_CHUNK:
            # Increment chunk ID within the current frame
            self.current_chunk_id += 1
            self.chunk_id = ChunkTrainIdx(self.current_frame_id, self.current_chunk_id)
        elif chunk_type == ChunkType.EMPTY_CHUNK:
            # End chunks close the frame
            self.current_chunk_id += 1
            self.chunk_id = ChunkTrainIdx(self.current_frame_id, self.current_chunk_id)
            self.is_new_frame = False

    def reset(self):
        """
        Resets the internal state of the handler to prepare for a new stream.
        """
        self.chunk_data = ChunkData()
        self.chunk_meta = ChunkFooter() if self.mode == "miso" else ChunkHeader()
        self.received_bytes = 0
        self.start_time = None
        self.end_time = None


class TC6State(Enum):
    """
    Enum to represent the states of the TC6 State Machine.
    """
    STANDBY = 1
    WAITING_FOR_DATA = 2
    HANDLING_CTRL = 3
    HANDLING_DATA = 4
    CTRL_COMPLETE = 5


class TC6StateMachine:
    """
    Class to implement a TC6 state machine based on input events.
    """
    def __init__(self):
        """
        Initialize the state machine. The initial state is STANDBY.
        """
        self.state = TC6State.STANDBY
        self.prev_state = TC6State.STANDBY

    def process_event(self, input_event):
        """
        Processes an input event and updates the state machine's state.

        :param input_event: A dictionary containing the event information.
                            - input_event.type: The event type ("disable", "enable", "result").
                            - input_event.data: A dictionary containing the byte data.
        :return: None
        """
        event_type = input_event.type
        data = input_event.data

        self.prev_state = self.state

        if event_type == "disable":
                self.state = TC6State.STANDBY
        elif event_type == "enable":
            self.state = TC6State.WAITING_FOR_DATA
        elif event_type == "result" and self.state == TC6State.WAITING_FOR_DATA:
            mosi = data.get("mosi")
            if mosi and isinstance(mosi, bytes):
                # Ensure we handle the first byte of the bytes object
                msb = (mosi[0] >> 7) & 0x1  # Extract the MSB from the first byte of the MOSI data
                self.state = TC6State.HANDLING_DATA if msb == 1 else TC6State.HANDLING_CTRL


        return self.state, self.prev_state


    def set_state(self, state):
        self.state = state


class CtrlHeader:
    """
    Class to parse and represent a 4-byte control header.
    """
    def __init__(self, header_bytes):
        """
        Initializes and parses the 4-byte control header.

        :param header_bytes: A 4-byte input as bytes or bytearray.
        """
        if not isinstance(header_bytes, (bytes, bytearray)) or len(header_bytes) != 4:
            raise ValueError("Input must be a 4-byte bytes or bytearray.")

        # Convert the header to a 32-bit integer for bitfield extraction
        header_value = int.from_bytes(header_bytes, byteorder="big")

        # Parse the header fields
        self.write_not_read = (header_value >> 29) & 0x1
        self.memory_map_selector = (header_value >> 24) & 0xF
        self.address = (header_value >> 8) & 0xFFFF
        self.length = (header_value >> 1) & 0x7F
        self.data_not_control = (header_value >> 31) & 0x1
        self.received_header_bad = (header_value >> 30) & 0x1
        self.address_increment_disable = (header_value >> 28) & 0x1
        self.parity_bit = header_value & 0x1

    def __str__(self):
        """
        Returns a single-line readable output of all header variables with full names.
        """
        return (f"Write-Not-Read: 0x{self.write_not_read:X}, "
                f"Memory Map Selector: 0x{self.memory_map_selector:X}, "
                f"Address: 0x{self.address:04X}, "
                f"Length: 0x{self.length:02X}, "
                f"Data-Not-Control: 0x{self.data_not_control:X}, "
                f"Received Header Bad: 0x{self.received_header_bad:X}, "
                f"Address Increment Disable: 0x{self.address_increment_disable:X}, "
                f"Parity Bit: 0x{self.parity_bit:X}")

    def header_flags_get(self):
        """
        Returns a string representation of the header flags.

        :return: A formatted string like (DNC=[VAL] HDRB=[VAL] WNR=[VAL] AID=[VAL] P=[VAL]).
        """
        return (f"(DNC={hex(self.data_not_control)}, "
                f"HDRB={hex(self.received_header_bad)}, "
                f"WNR={hex(self.write_not_read)}, "
                f"AID={hex(self.address_increment_disable)}, "
                f"P={hex(self.parity_bit)})")


class ControlMessage:
    """
    Class to handle a control message stream.
    """
    def __init__(self):
        """
        Initializes the ControlMessage with an empty buffer and initial state.
        """
        self.buffer = bytearray(64)  # Control messages can be up to 64 bytes long
        self.length = 0  # Current number of bytes in the buffer
        self.start_time = None  # Start time of the message
        self.end_time = None  # Continuously updated end time of the message
        self.complete = False  # Indicates if the buffer is full
        self.header = None  # Parsed control header, initialized to None
        self.protected = False

    def append_byte(self, frame):
        """
        Appends a byte from the input frame to the buffer.

        :param frame: A dictionary containing the frame information.
                      - frame.start_time: Start time of the frame.
                      - frame.end_time: End time of the frame.
                      - frame.data: A dictionary containing the byte to append.
                      - 'mosi' or 'miso': The byte data to append.
        :return: None
        """
        if self.complete:
            return  # No further processing if the buffer is already full

        byte = frame.data.get("mosi")  # Always take the byte from 'mosi'
        if byte is None or not isinstance(byte, bytes):
            return  # Skip invalid or missing byte data

        # Save the start time for the first byte
        if self.length == 0:
            self.start_time = frame.start_time

        # Continuously update the end time
        self.end_time = frame.end_time

        # Append the byte to the buffer
        if self.length < len(self.buffer):
            self.buffer[self.length] = byte[0]
            self.length += 1

        # Mark as complete if the buffer is full
        if self.length == len(self.buffer):
            self.complete = True

    def reset(self):
        """
        Resets the internal state of the control message handler.
        """
        self.buffer = bytearray(64)
        self.length = 0
        self.start_time = None
        self.end_time = None
        self.complete = False
        self.protected = False

    def unknown_frame(self):
        return AnalyzerFrame( 'Unknown Control', self.start_time, self.end_time,
            {'Raw_Bytes': f"0x{''.join(f'{byte:02x}' for byte in self.buffer[:self.length])}",}
        )

    def parse(self):
        """
        Parses the control message header (first 4 bytes) and stores it in `self.header`.
        The header is parsed into a dictionary.
        """
        if self.length < 4:
            return self.unknown_frame()

        self.header = CtrlHeader(self.buffer[:4])

        # Determine command type based on the `write_not_read` bit
        if self.header.write_not_read == 1:  # WRITE command
            # Section 7.4.2, Control write, OPEN Alliance 10BASE-T1x MAC-PHY Serial Interface spec
            expected_prot_msg_len = 8 + ((self.header.length + 1) * 4 * 2)
            expected_msg_len = 8 + ((self.header.length + 1) * 4)

            # Validate that the buffer size accounts for header, data, and final 4 bytes
            # Section 7.4.4, Register Data Format and Protection, OPEN Alliance 10BASE-T1x MAC-PHY Serial Interface spec
            if self.length == expected_prot_msg_len:
                self.protected = True
            elif self.length == expected_msg_len:
                self.protected = False
            else:
                return self.unknown_frame()

            # Extract data (bytes between header and last 4 bytes)
            self.data = self.buffer[4:self.length - 4]
        else:  # READ command
            # For READ commands, no data is stored
            self.data = None

        return AnalyzerFrame(
            'Control',
            self.start_time,
            self.end_time,
            {
                'R/W': "Write" if self.header.write_not_read == 1 else "Read",
                'Reg_Name': MemoryMapLookup.get_reg(self.header.memory_map_selector,self.header.address),
                'MMS/Addr': f"{self.header.memory_map_selector}/{hex(self.header.address)}",
                'Length': str(self.header.length),
                'Payload': f"0x{''.join(f'{byte:02x}' for byte in self.data)}" if self.data else "N/A",
                'Protected': "Yes" if self.protected else "No",
                'Header/Footer': self.header.header_flags_get(),
            }
        )

# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):
    # List of settings that a user can set for this High Level Analyzer.
    pin_cfg = ChoicesSetting(choices=('MISO', 'MOSI'))
    # An optional list of types this analyzer produces, providing a way to customize the way frames are displayed in Logic 2.

    def __init__(self):
        '''
        Initialize HLA.

        Settings can be accessed using the same name used above.
        '''
        self.handler = ChunkHandler(self.pin_cfg.lower())
        self.state_m = TC6StateMachine()
        self.ctrl = ControlMessage()

    def decode(self, frame: AnalyzerFrame):
        '''
        Process a frame from the input analyzer, and optionally return a single `AnalyzerFrame` or a list of `AnalyzerFrame`s.

        The type and data values in `frame` will depend on the input analyzer.
        '''

        new_state, prev_state = self.state_m.process_event(frame)

        if new_state == TC6State.STANDBY:
            ret = None

            if prev_state == TC6State.HANDLING_CTRL:
                # TODO:Fix the control message implementation so that it also handles control MISO messages
                if self.pin_cfg == "MOSI":
                    ret = self.ctrl.parse()

            self.handler.reset()
            self.ctrl.reset()
            return ret
        elif new_state == TC6State.WAITING_FOR_DATA:
            pass
        elif new_state == TC6State.HANDLING_CTRL:
            # TODO:Fix the control message implementation so that it also handles control MISO messages
            if self.pin_cfg == "MOSI":
                self.ctrl.append_byte(frame)
        elif new_state == TC6State.HANDLING_DATA:
            return self.handler.handle_byte(frame)

        return None
