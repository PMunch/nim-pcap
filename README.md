#PCAP parser
Tiny pure Nim library to read PCAP files used by TcpDump/WinDump/Wireshark as described here: https://wiki.wireshark.org/Development/LibpcapFileFormat

##Code example
```
import pcap

let
  s = newFileStream("test.pcap", fmRead)
  globalHeader = s.readGlobalHeader()

echo globalHeader

while not s.atEnd:
  let
    record = s.readRecord(globalHeader)
  echo record
```