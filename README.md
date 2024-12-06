# Microchip LAN8650/1 TC6 10BASE-T1S MAC-PHY Decoder

This repository contains a High-Level Analyzer (HLA) for Saleae Logic 2, designed to parse and analyze control and
data packets transmitted between an SPI host and a LAN8650/1 MAC/PHY (TC6). This HLA supports decoding, protocol identification,
and visualizing packet content in Logic 2's interface.

This High-Level Analyzer (HLA) is designed to enhance the understanding and analysis of SPI communication between an SPI host and the LAN8650/1 MAC-PHY Ethernet Controller, following the OPEN Alliance 10BASE-T1x MAC-PHY Serial Interface specification.

The implementation is based on the **OPEN Alliance 10BASE-T1x MAC-PHY Serial Interface** specification and the **10BASE-T1S MAC-PHY Ethernet Controller with SPI LAN8650/1** datasheet. It is strongly recommended that users familiarize themselves with these documents to fully understand the protocol and the parsed data output provided by this HLA.
Both documents are available in the **docs** folder in this repo.

## Features

### Control Messages
- **Header Parsing**: Fully parses the 4-byte control header on MOSI with detailed field extraction, including:
  - Write-Not-Read
  - Memory Map Selector
  - Address
  - Length
  - Data-Not-Control
  - Received Header Bad
  - Address Increment Disable
  - Parity Bit
- **Validation**: Automatically validates control messages for proper structure based on the header fields.
- **Data Extraction**: Supports extraction and validation of control message data payload based on header length and type.
- **Readable Names**: Converts memory map selectors and addresses to human-readable names for easier interpretation.

### Data Chunks
- **Header Parsing**: Extracts and interprets fields from the **Transmit Data Header** on MOSI, including:
  - Data-Not-Control
  - Data Chunk Sequence
  - No Receive
  - Reserved
  - Vendor Specific
  - Data Valid
  - Start Valid
  - Start Word Offset
  - End Valid
  - End Byte Offset
  - Transmit Frame Timestamp Capture
  - Header Parity Bit
- **Footer Parsing**: Extracts and interprets fields from the **Receive Data Footer** on MISO, including:
  - Extended Status
  - Received Header Bad
  - Configuration Synchronized
  - Receive Chunks Available
  - Vendor Specific
  - Data Valid
  - Start Valid
  - Start Word Offset
  - Frame Drop
  - End Valid
  - End Byte Offset
  - Receive Frame Timestamp Added
  - Receive Frame Timestamp Parity
  - Transmit Credits
  - Footer Parity Bit
- **Chunk Parsing**: Identifies and processes data chunks, extracting:
  - **Chunk Type**: Determines the type of chunk based on metadata flags in the buffer:
    - **Empty Chunk**: Identified when the **DV (Data Valid)** bit is `0`. Indicates that the chunk contains no valid data.
    - **Atomic Chunk**: Identified when both the **SV (Start Valid)** bit and the **EV (End Valid)** bit are `1`. Represents a complete, standalone chunk.
    - **Start Chunk**: Identified when the **SV (Start Valid)** bit is `1` and the **EV (End Valid)** bit is `0`. Marks the beginning of a multi-chunk sequence.
    - **End Chunk**: Identified when the **EV (End Valid)** bit is `1` and the **SV (Start Valid)** bit is `0`. Marks the end of a multi-chunk sequence.
    - **Intermediate Chunk**: Identified when both **SV (Start Valid)** and **EV (End Valid)** bits are `0`, and the **DV (Data Valid)** bit is `1`. Represents a in-the-middle chunk that is part of a multi-chunk sequence.
  - Chunk data payload.
  - Identifies Ethernet protocols such as IPv4, IPv6, ARP, ICMP, TCP, and UDP.
  - Custom indexing of chunks to group multi-chunk sequences.
- **Error Handling**: Flags malformed or incomplete data chunks for easier debugging.


## Installation (Windows)

1. Clone or download this repository.
2. Open the **Logic 2** software.
3. Navigate to the **Extensions** section in the sidebar.
4. Click the triple-dot icon in the upper-right corner and select **Load Existing Extension**.
5. This will open an Explorer view. Navigate to the directory where you cloned or downloaded this repository and select the `extension.json` file located in the root folder.
6. The extension will now be installed and ready for use in Logic 2.

> **Note**: This process has only been tested on Windows. The steps may be similar for Linux, macOS, and other platforms, but specific instructions for those are not provided here.



## Usage

Follow these steps to set up and use the LAN8650/1 High-Level Analyzer in the Logic2 software:

1. **Navigate to the Analyzers Section**

   - Open the Logic2 software and navigate to the **Analyzers** section in the sidebar.

2. **Add the SPI Low-Level Analyzer (LLA)**
   - Click the **+** icon in the Analyzer menu to add an SPI analyzer.
   - Configure the SPI analyzer with the appropriate parameters for your setup.
   - Run your application/setup and ensure the SPI analyzer captures data correctly.

3. **Add Two Instances of the LAN8650/1 Decoder**

   The HLA operates on top of the SPI LLA, and you will need to configure separate instances for the MISO and MOSI lines.

   - **MISO Decoder**
     - Click the **+** icon in the Analyzer menu to add the **LAN8650/1 Decoder**.
     - Under **Input Analyzer**, select your SPI LLA.
     - Under **Pin Cfg**, select **MISO**.
     - Click **Save**.
     - *(Optional)* Rename the analyzer instance to **MISO** and place it over the SPI MISO trace in the trace menu.

   - **MOSI Decoder**
     - Click the **+** icon in the Analyzer menu to add the **LAN8650/1 Decoder**.
     - Under **Input Analyzer**, select your SPI LLA.
     - Under **Pin Cfg**, select **MOSI**.
     - Click **Save**.
     - *(Optional)* Rename the analyzer instance to **MOSI** and place it over the SPI MOSI trace in the trace menu.

4. **Verify the Setup**

   Run your application/setup and verify the following:
   - **Frame Data**: Frame data appears in the trace for control messages and data chunks.
   - **Table Data**: Parsed data appears in the **Data** tab in the Analyzer sidebar section.

Your setup is now complete, and the HLA should decode and display the communication data.



## Output Format

### Table Columns
| Column           | Description                                                                                   | Control Messages | Data Chunks |
|------------------|-----------------------------------------------------------------------------------------------|:----------------:|:-----------:|
| **name**         | The name of the analyzer instance (`LAN8650/1 Decoder`, `MOSI` etc.).                         |       X          |      X      |
| **type**         | The type of the message or chunk (`Control` or `Chunk`).                                      |       X          |      X      |
| **start_time**   | Timestamp of when the message/chunk was captured.                                             |       X          |      X      |
| **duration**     | Duration of the message/chunk transmission.                                                   |       X          |      X      |
| **Header/Footer**| Parsed header/footer information displayed as bitfield values in concise format.              |       X          |      X      |
| **Payload**      | Hexadecimal representation of the transmitted data.                                           |       X          |      X      |
| **R/W**          | Indicates whether the operation is a `Read` or `Write`.                                       |       X          |             |
| **Reg_Name**     | The readable name of the register or memory location being accessed.                          |       X          |             |
| **Length**       | The length of the control message.                                                            |       X          |             |
| **Protected**    | Whether the control operation was marked as protected (`Yes/No`).                             |       X          |             |
| **MMS/Addr**     | The Memory Map Selector and Address in `MMS/0xAddr` format.                                   |       X          |             |
| **Chunk_Idx**    | Custom index of the chunk being processed.                                                    |                  |      X      |
| **Chunk_Type**   | The type of data chunk (`Empty chunk`, `Atomic chunk`, etc.).                                 |                  |      X      |
| **Protocol_Type**| The interpreted protocol of the chunk payload (e.g., `N/A`, `ARP`, `UDP/IPv4`).               |                  |      X      |

### Trace View
The trace view highlights the most critical information closer to the start of each chunk:
- For control messages: Operation type, register name, ...
- For data chunks: Chunk type, protocol, ...
