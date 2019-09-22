## Implements a reader for the pcap file format used by TcpDump/WinDump/Wireshark as described here: https://wiki.wireshark.org/Development/LibpcapFileFormat

import streams, strutils, endians, times

proc newEIO(msg: string): ref IOError =
  new(result)
  result.msg = msg

proc read[T](s: Stream, result: var T) =
  if readData(s, addr(result), sizeof(T)) != sizeof(T):
    raise newEIO("Cannot read from stream")

proc readUint8(s: Stream): uint8 =
  read(s, result)

proc readUint16(s: Stream): uint16 =
  read(s, result)

proc readUint32(s: Stream): uint32 =
  read(s, result)

proc writeUint8(s: Stream, d: uint8) =
  write(s, d)

proc writeUint16(s: Stream, d: uint16) =
  write(s, d)

proc writeUint32(s: Stream, d: uint32) =
  write(s, d)

proc writeInt32(s: Stream, d: int32) =
  write(s, d)


type
  LinkLayerType* = enum
    ## The Link layer type as described here: http://www.tcpdump.org/linktypes.html
    NULL = (0, "NULL"),
    ETHERNET = (1, "ETHERNET"),
    AX25 = (3, "AX25"),
    IEEE802_5 = (6, "IEEE802_5"),
    ARCNET_BSD = (7, "ARCNET_BSD"),
    SLIP = (8, "SLIP"),
    PPP = (9, "PPP"),
    FDDI = (10, "FDDI"),
    PPP_HDLC = (50, "PPP_HDLC"),
    PPP_ETHER = (51, "PPP_ETHER"),
    ATM_RFC1483 = (100, "ATM_RFC1483"),
    RAW = (101, "RAW"),
    C_HDLC = (104, "C_HDLC"),
    IEEE802_11 = (105, "IEEE802_11"),
    FRELAY = (107, "FRELAY"),
    LOOP = (108, "LOOP"),
    LINUX_SLL = (113, "LINUX_SLL"),
    LTALK = (114, "LTALK"),
    PFLOG = (117, "PFLOG"),
    IEEE802_11_PRISM = (119, "IEEE802_11_PRISM"),
    IP_OVER_FC = (122, "IP_OVER_FC"),
    SUNATM = (123, "SUNATM"),
    IEEE802_11_RADIOTAP = (127, "IEEE802_11_RADIOTAP"),
    ARCNET_LINUX = (129, "ARCNET_LINUX"),
    APPLE_IP_OVER_IEEE1394 = (138, "APPLE_IP_OVER_IEEE1394"),
    MTP2_WITH_PHDR = (139, "MTP2_WITH_PHDR"),
    MTP2 = (140, "MTP2"),
    MTP3 = (141, "MTP3"),
    SCCP = (142, "SCCP"),
    DOCSIS = (143, "DOCSIS"),
    LINUX_IRDA = (144, "LINUX_IRDA"),
    USER0 = (147, "USER0"),
    USER1 = (148, "USER1"),
    USER2 = (149, "USER2"),
    USER3 = (150, "USER3"),
    USER4 = (151, "USER4"),
    USER5 = (152, "USER5"),
    USER6 = (153, "USER6"),
    USER7 = (154, "USER7"),
    USER8 = (155, "USER8"),
    USER9 = (156, "USER9"),
    USER10 = (157, "USER10"),
    USER11 = (158, "USER11"),
    USER12 = (159, "USER12"),
    USER13 = (160, "USER13"),
    USER14 = (161, "USER14"),
    USER15 = (162, "USER15"),
    IEEE802_11_AVS = (163, "IEEE802_11_AVS"),
    BACNET_MS_TP = (165, "BACNET_MS_TP"),
    PPP_PPPD = (166, "PPP_PPPD"),
    GPRS_LLC = (169, "GPRS_LLC"),
    GPF_T = (170, "GPF_T"),
    GPF_F = (171, "GPF_F"),
    LINUX_LAPD = (177, "LINUX_LAPD"),
    BLUETOOTH_HCI_H4 = (187, "BLUETOOTH_HCI_H4"),
    USB_LINUX = (189, "USB_LINUX"),
    PPI = (192, "PPI"),
    IEEE802_15_4 = (195, "IEEE802_15_4"),
    SITA = (196, "SITA"),
    ERF = (197, "ERF"),
    BLUETOOTH_HCI_H4_WITH_PHDR = (201, "BLUETOOTH_HCI_H4_WITH_PHDR"),
    AX25_KISS = (202, "AX25_KISS"),
    LAPD = (203, "LAPD"),
    PPP_WITH_DIR = (204, "PPP_WITH_DIR"),
    C_HDLC_WITH_DIR = (205, "C_HDLC_WITH_DIR"),
    FRELAY_WITH_DIR = (206, "FRELAY_WITH_DIR"),
    IPMB_LINUX = (209, "IPMB_LINUX"),
    IEEE802_15_4_NONASK_PHY = (215, "IEEE802_15_4_NONASK_PHY"),
    USB_LINUX_MMAPPED = (220, "USB_LINUX_MMAPPED"),
    FC_2 = (224, "FC_2"),
    FC_2_WITH_FRAME_DELIMS = (225, "FC_2_WITH_FRAME_DELIMS"),
    IPNET = (226, "IPNET"),
    CAN_SOCKETCAN = (227, "CAN_SOCKETCAN"),
    IPV4 = (228, "IPV4"),
    IPV6 = (229, "IPV6"),
    IEEE802_15_4_NOFCS = (230, "IEEE802_15_4_NOFCS"),
    DBUS = (231, "DBUS"),
    DVB_CI = (235, "DVB_CI"),
    MUX27010 = (236, "MUX27010"),
    STANAG_5066_D_PDU = (237, "STANAG_5066_D_PDU"),
    NFLOG = (239, "NFLOG"),
    NETANALYZER = (240, "NETANALYZER"),
    NETANALYZER_TRANSPARENT = (241, "NETANALYZER_TRANSPARENT"),
    IPOIB = (242, "IPOIB"),
    MPEG_2_TS = (243, "MPEG_2_TS"),
    NG40 = (244, "NG40"),
    NFC_LLCP = (245, "NFC_LLCP"),
    INFINIBAND = (247, "INFINIBAND"),
    SCTP = (248, "SCTP"),
    USBPCAP = (249, "USBPCAP"),
    RTAC_SERIAL = (250, "RTAC_SERIAL"),
    BLUETOOTH_LE_LL = (251, "BLUETOOTH_LE_LL"),
    NETLINK = (253, "NETLINK"),
    BLUETOOTH_LINUX_MONITOR = (254, "BLUETOOTH_LINUX_MONITOR"),
    BLUETOOTH_BREDR_BB = (255, "BLUETOOTH_BREDR_BB"),
    BLUETOOTH_LE_LL_WITH_PHDR = (256, "BLUETOOTH_LE_LL_WITH_PHDR"),
    PROFIBUS_DL = (257, "PROFIBUS_DL"),
    PKTAP = (258, "PKTAP"),
    EPON = (259, "EPON"),
    IPMI_HPM_2 = (260, "IPMI_HPM_2"),
    ZWAVE_R1_R2 = (261, "ZWAVE_R1_R2"),
    ZWAVE_R3 = (262, "ZWAVE_R3"),
    WATTSTOPPER_DLM = (263, "WATTSTOPPER_DLM"),
    ISO_14443 = (264, "ISO_14443"),
    RDS = (265, "RDS"),
    USB_DARWIN = (266, "USB_DARWIN"),
    SDLC = (268, "SDLC")

  PcapGlobalHeader* = ref object
    ## This header starts the libpcap file and will be followed by the first packet header
    magicNumber*: uint32
    nanos*: bool
    swapped*: bool
    versionMajor*: uint16
    versionMinor*: uint16
    thiszone*: int32
    sigfigs*: uint32
    snaplen*: uint32
    network*: LinkLayerType

  PcapRecordHeader* = ref object
    ## Each captured packet starts with this header
    globalHeader*: PcapGlobalHeader
    tsSec*: uint32
    tsUsec*: uint32
    inclLen*: uint32
    origLen*: uint32

  PcapRecord* = ref object
    ## A record which contains a pointer to the header and a sequence of data characters.
    header*: PcapRecordHeader
    data*: seq[uint8]

proc `$`*(header: PcapGlobalHeader): string =
  ## Procedure to get the header as a nicely formatted string
  """Pcap Global header:
  Magic number: 0x$1
    Byte order: $2 endian
    Resolution: $3
  Version: $4.$5
  GMT Offset (s): $6
  Timestamp accuracy: $7
  Max snapshot length: $8
  Network: $9""" % [
    header.magicNumber.toHex, 
    if header.swapped: "little" else: "big", 
    if header.nanos: "nanosecond" else: "millisecond",
    $header.versionMajor,
    $header.versionMinor,
    $header.thiszone,
    $header.sigfigs,
    $header.snaplen,
    $header.network]

proc `$`*(header: PcapRecordHeader): string =
  ## Procedure to get the header as a nicely formatted string
  """Pcap Record header:
  Timestamp (s): $1
    Time: $2
  Timestamp extra ($3): $4
  Captured size: $5
  Actual size: $6""" % [
    $header.tsSec,
    $(fromUnix(header.tsSec.int)),
    if header.globalHeader.nanos: "ns" else: "µs",
    $header.tsUsec,
    $header.inclLen,
    $header.origLen]

const Printables = {' ', '!', '"', '#', '$', '%', '&', '\'', '(', ')', '*', '+', ',', '-', '.', '/', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', ':', ';', '<', '=', '>', '?', '@', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '[', '\\', ']', '^', '_', '`', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '{', '|', '}', '~'}
proc dataString*(record: PcapRecord): string =
  ## Procedure to get the data from a record and print all the printables characters replacing the non-printable characters with dots
  result = ""
  var i = 0
  for c in record.data:
    if c.chr in Printables:
      result.add c.chr
    else:
      result.add "."
    i+=1
    if i>15:
      result.add "\n"
      i = 0

proc `$`*(record: PcapRecord): string =
  ## Procedure to get the record as a nicely formatted string
  result = $record.header
  result.add "\n  Data:\n"
  result.add dataString(record).indent(4)

proc readGlobalHeader*(s: Stream): PcapGlobalHeader =
  ## Reads the header from the start of the stream and advanced the pointer to the first record header
  new result
  result.magicNumber = s.readUint32()
  case result.magicNumber:
  of 0xA1B2C3D4.uint32:
    result.swapped = true
    result.nanos = false
  of 0xD4C3B2A1.uint32:
    result.swapped = false
    result.nanos = false
  of 0xA1B23C4D.uint32:
    result.swapped = true
    result.nanos = true
  of 0x4D3CB2A1.uint32:
    result.swapped = false
    result.nanos = true
  else:
    raise new ValueError
  result.versionMajor = s.readUint16()
  result.versionMinor = s.readUint16()
  result.thiszone = s.readInt32()
  result.sigfigs = s.readUint32()
  result.snaplen = s.readUint32()
  var network = s.readUint32()
  if not result.swapped:
    bigEndian32(result.magicNumber.addr, result.magicNumber.addr)
    bigEndian16(result.versionMajor.addr, result.versionMajor.addr)
    bigEndian16(result.versionMinor.addr, result.versionMinor.addr)
    bigEndian32(result.thiszone.addr, result.thiszone.addr)
    bigEndian32(result.sigfigs.addr, result.sigfigs.addr)
    bigEndian32(result.snaplen.addr, result.snaplen.addr)
    bigEndian32(network.addr, network.addr)
  result.network = LinkLayerType(network)

proc writeGlobalHeader*(s: Stream, globalHeader: PcapGlobalHeader) =
  if globalHeader.nanos:
    s.writeUint32(0xA1B23C4D'u32)
  else:
    s.writeUint32(0xA1B2C3D4'u32)
  s.writeUint16(globalHeader.versionMajor)
  s.writeUint16(globalHeader.versionMinor)
  s.writeInt32(globalHeader.thiszone)
  s.writeUint32(globalHeader.sigfigs)
  s.writeUint32(globalHeader.snaplen)
  s.writeUint32(globalHeader.network.ord.uint32)

proc writeRecordHeader*(s: Stream, recordHeader: PcapRecordHeader, maxlen: int = 0) =
  s.writeUint32(recordHeader.tsSec)
  s.writeUint32(recordHeader.tsUsec)
  if maxlen == 0:
    s.writeUint32(recordHeader.inclLen)
  else:
    s.writeUint32(maxlen.uint32)
  s.writeUint32(recordHeader.origLen)

proc writeRecordHeader*(s: Stream, record: PcapRecord, maxlen: int = 0) =
  s.writeRecordHeader(record.header, maxlen)

proc writeRecordData*(s: Stream, record: seq[uint8], maxlen: int = 0) =
  if maxlen != 0 and maxlen < record.len:
    for b in record[0..<maxlen]:
      s.write(b)
  else:
    for b in record:
      s.write(b)

proc writeRecordData*(s: Stream, record: PcapRecord, maxlen: int = 0) =
  s.writeRecordData(record.data, maxlen)

proc writeRecord*(s: Stream, record: PcapRecord, maxlen: int = 0) =
  s.writeRecordHeader(record, maxlen)
  s.writeRecordData(record, maxlen)

proc readRecordHeader*(s: Stream, globalHeader: PcapGlobalHeader): PcapRecordHeader =
  ## Reads a record header and advanced the pointer to the record data
  new result
  result.globalHeader = globalHeader
  result.tsSec = s.readUint32()
  result.tsUsec = s.readUint32()
  result.inclLen = s.readUint32()
  result.origLen = s.readUint32()
  if not globalHeader.swapped:
    bigEndian32(result.tsSec.addr, result.tsSec.addr)
    bigEndian32(result.tsUsec.addr, result.tsUsec.addr)
    bigEndian32(result.inclLen.addr, result.inclLen.addr)
    bigEndian32(result.origLen.addr, result.origLen.addr)

proc readRecord*(s: Stream, recordHeader: PcapRecordHeader): PcapRecord =
  ## Reads the data for a record given the record header containing the length of the record and advanced the pointer to the next record header
  new result
  result.header = recordHeader
  result.data.newSeq(recordHeader.inclLen)
  if not recordHeader.globalHeader.swapped:
    for i in countdown(recordHeader.inclLen.int-1, 0):
      result.data[i] = s.readUint8()
  else:
    for i in 0..<recordHeader.inclLen.int:
      result.data[i] = s.readUint8()

proc readRecord*(s: Stream, globalHeader: PcapGlobalHeader): PcapRecord =
  ## Reads the record header and the record data given the global header and advances the pointer to the next record header
  s.readRecord(s.readRecordHeader(globalHeader))
