#include <iostream>
#include <cctype>

typedef unsigned int DWORD;
typedef unsigned short WORD;
typedef unsigned char BYTE;

template<int N>
unsigned int read_n(unsigned char const* buffer)
{
  unsigned int iRet = 0;
  for(int i=0;i < N;++i)
  {
    iRet |= (unsigned int)(buffer[i]) << (i*8);
  }
  return iRet;
}

  // generated from header_gen.cpp:47
class MZ_HEADER
{
public:
  WORD e_magic;
  WORD e_cblp;
  WORD e_cp;
  WORD e_crlc;
  WORD e_cparhdr;
  WORD e_minalloc;
  WORD e_maxalloc;
  WORD e_ss;
  WORD e_sp;
  WORD e_csum;
  WORD e_ip;
  WORD e_cs;
  WORD e_lfarlc;
  WORD e_ovno;
  WORD e_res[4];
  WORD e_oemid;
  WORD e_oeminfo;
  WORD e_res2[10];
  DWORD e_lfanew;

  static unsigned long size()
  {
    return 64;
  }

  // generated from header_gen.cpp:82
  void parse(unsigned char const* pBuffer)
  {
    e_magic = read_n<2>(&pBuffer[0x0]);
    e_cblp = read_n<2>(&pBuffer[0x2]);
    e_cp = read_n<2>(&pBuffer[0x4]);
    e_crlc = read_n<2>(&pBuffer[0x6]);
    e_cparhdr = read_n<2>(&pBuffer[0x8]);
    e_minalloc = read_n<2>(&pBuffer[0xa]);
    e_maxalloc = read_n<2>(&pBuffer[0xc]);
    e_ss = read_n<2>(&pBuffer[0xe]);
    e_sp = read_n<2>(&pBuffer[0x10]);
    e_csum = read_n<2>(&pBuffer[0x12]);
    e_ip = read_n<2>(&pBuffer[0x14]);
    e_cs = read_n<2>(&pBuffer[0x16]);
    e_lfarlc = read_n<2>(&pBuffer[0x18]);
    e_ovno = read_n<2>(&pBuffer[0x1a]);
    e_res[0] = read_n<2>(&pBuffer[0x1c]);
    e_res[1] = read_n<2>(&pBuffer[0x1e]);
    e_res[2] = read_n<2>(&pBuffer[0x20]);
    e_res[3] = read_n<2>(&pBuffer[0x22]);
    e_oemid = read_n<2>(&pBuffer[0x24]);
    e_oeminfo = read_n<2>(&pBuffer[0x26]);
    e_res2[0] = read_n<2>(&pBuffer[0x28]);
    e_res2[1] = read_n<2>(&pBuffer[0x2a]);
    e_res2[2] = read_n<2>(&pBuffer[0x2c]);
    e_res2[3] = read_n<2>(&pBuffer[0x2e]);
    e_res2[4] = read_n<2>(&pBuffer[0x30]);
    e_res2[5] = read_n<2>(&pBuffer[0x32]);
    e_res2[6] = read_n<2>(&pBuffer[0x34]);
    e_res2[7] = read_n<2>(&pBuffer[0x36]);
    e_res2[8] = read_n<2>(&pBuffer[0x38]);
    e_res2[9] = read_n<2>(&pBuffer[0x3a]);
    e_lfanew = read_n<4>(&pBuffer[0x3c]);
  }

  // generated from header_gen.cpp:108
  void print() const
  {
    //std::cout << "MZ_HEADER" << std::endl; 
    //std::cout << "e_magic = 0x" << std::hex << (unsigned int)(e_magic) << std::endl;
    //std::cout << "e_cblp = 0x" << std::hex << (unsigned int)(e_cblp) << std::endl;
    //std::cout << "e_cp = 0x" << std::hex << (unsigned int)(e_cp) << std::endl;
    //std::cout << "e_crlc = 0x" << std::hex << (unsigned int)(e_crlc) << std::endl;
    //std::cout << "e_cparhdr = 0x" << std::hex << (unsigned int)(e_cparhdr) << std::endl;
    //std::cout << "e_minalloc = 0x" << std::hex << (unsigned int)(e_minalloc) << std::endl;
    //std::cout << "e_maxalloc = 0x" << std::hex << (unsigned int)(e_maxalloc) << std::endl;
    //std::cout << "e_ss = 0x" << std::hex << (unsigned int)(e_ss) << std::endl;
    //std::cout << "e_sp = 0x" << std::hex << (unsigned int)(e_sp) << std::endl;
    //std::cout << "e_csum = 0x" << std::hex << (unsigned int)(e_csum) << std::endl;
    //std::cout << "e_ip = 0x" << std::hex << (unsigned int)(e_ip) << std::endl;
    //std::cout << "e_cs = 0x" << std::hex << (unsigned int)(e_cs) << std::endl;
    //std::cout << "e_lfarlc = 0x" << std::hex << (unsigned int)(e_lfarlc) << std::endl;
    //std::cout << "e_ovno = 0x" << std::hex << (unsigned int)(e_ovno) << std::endl;
    //std::cout << "e_res[0] = 0x" << std::hex << (unsigned int)(e_res[0]) << " '" <<  char(isprint(e_res[0]) ? e_res[0] : '.' ) << "'" << std::endl;
    //std::cout << "e_res[1] = 0x" << std::hex << (unsigned int)(e_res[1]) << " '" <<  char(isprint(e_res[1]) ? e_res[1] : '.' ) << "'" << std::endl;
    //std::cout << "e_res[2] = 0x" << std::hex << (unsigned int)(e_res[2]) << " '" <<  char(isprint(e_res[2]) ? e_res[2] : '.' ) << "'" << std::endl;
    //std::cout << "e_res[3] = 0x" << std::hex << (unsigned int)(e_res[3]) << " '" <<  char(isprint(e_res[3]) ? e_res[3] : '.' ) << "'" << std::endl;
    //std::cout << "e_oemid = 0x" << std::hex << (unsigned int)(e_oemid) << std::endl;
    //std::cout << "e_oeminfo = 0x" << std::hex << (unsigned int)(e_oeminfo) << std::endl;
    //std::cout << "e_res2[0] = 0x" << std::hex << (unsigned int)(e_res2[0]) << " '" <<  char(isprint(e_res2[0]) ? e_res2[0] : '.' ) << "'" << std::endl;
    //std::cout << "e_res2[1] = 0x" << std::hex << (unsigned int)(e_res2[1]) << " '" <<  char(isprint(e_res2[1]) ? e_res2[1] : '.' ) << "'" << std::endl;
    //std::cout << "e_res2[2] = 0x" << std::hex << (unsigned int)(e_res2[2]) << " '" <<  char(isprint(e_res2[2]) ? e_res2[2] : '.' ) << "'" << std::endl;
    //std::cout << "e_res2[3] = 0x" << std::hex << (unsigned int)(e_res2[3]) << " '" <<  char(isprint(e_res2[3]) ? e_res2[3] : '.' ) << "'" << std::endl;
    //std::cout << "e_res2[4] = 0x" << std::hex << (unsigned int)(e_res2[4]) << " '" <<  char(isprint(e_res2[4]) ? e_res2[4] : '.' ) << "'" << std::endl;
    //std::cout << "e_res2[5] = 0x" << std::hex << (unsigned int)(e_res2[5]) << " '" <<  char(isprint(e_res2[5]) ? e_res2[5] : '.' ) << "'" << std::endl;
    //std::cout << "e_res2[6] = 0x" << std::hex << (unsigned int)(e_res2[6]) << " '" <<  char(isprint(e_res2[6]) ? e_res2[6] : '.' ) << "'" << std::endl;
    //std::cout << "e_res2[7] = 0x" << std::hex << (unsigned int)(e_res2[7]) << " '" <<  char(isprint(e_res2[7]) ? e_res2[7] : '.' ) << "'" << std::endl;
    //std::cout << "e_res2[8] = 0x" << std::hex << (unsigned int)(e_res2[8]) << " '" <<  char(isprint(e_res2[8]) ? e_res2[8] : '.' ) << "'" << std::endl;
    //std::cout << "e_res2[9] = 0x" << std::hex << (unsigned int)(e_res2[9]) << " '" <<  char(isprint(e_res2[9]) ? e_res2[9] : '.' ) << "'" << std::endl;
    //std::cout << "e_lfanew = 0x" << std::hex << (unsigned int)(e_lfanew) << std::endl;
  }

};

  // generated from header_gen.cpp:47
class PE_HEADER
{
public:
  DWORD Magic;
  WORD Machine;
  WORD NumberOfSections;
  DWORD TimeDateStamp;
  DWORD PointerToSymbolTable;
  DWORD NumberOfSymbols;
  WORD SizeOfOptionalHeader;
  WORD Characteristics;

  static unsigned long size()
  {
    return 24;
  }

  // generated from header_gen.cpp:82
  void parse(unsigned char const* pBuffer)
  {
    Magic = read_n<4>(&pBuffer[0x0]);
    Machine = read_n<2>(&pBuffer[0x4]);
    NumberOfSections = read_n<2>(&pBuffer[0x6]);
    TimeDateStamp = read_n<4>(&pBuffer[0x8]);
    PointerToSymbolTable = read_n<4>(&pBuffer[0xc]);
    NumberOfSymbols = read_n<4>(&pBuffer[0x10]);
    SizeOfOptionalHeader = read_n<2>(&pBuffer[0x14]);
    Characteristics = read_n<2>(&pBuffer[0x16]);
  }

  // generated from header_gen.cpp:108
  void print() const
  {
    //std::cout << "PE_HEADER" << std::endl; 
    //std::cout << "Magic = 0x" << std::hex << (unsigned int)(Magic) << std::endl;
    //std::cout << "Machine = 0x" << std::hex << (unsigned int)(Machine) << std::endl;
    //std::cout << "NumberOfSections = 0x" << std::hex << (unsigned int)(NumberOfSections) << std::endl;
    //std::cout << "TimeDateStamp = 0x" << std::hex << (unsigned int)(TimeDateStamp) << std::endl;
    //std::cout << "PointerToSymbolTable = 0x" << std::hex << (unsigned int)(PointerToSymbolTable) << std::endl;
    //std::cout << "NumberOfSymbols = 0x" << std::hex << (unsigned int)(NumberOfSymbols) << std::endl;
    //std::cout << "SizeOfOptionalHeader = 0x" << std::hex << (unsigned int)(SizeOfOptionalHeader) << std::endl;
    //std::cout << "Characteristics = 0x" << std::hex << (unsigned int)(Characteristics) << std::endl;
  }

};

  // generated from header_gen.cpp:47
class PE_OPT_HEADER
{
public:
  WORD Magic;
  BYTE MajorLinkerVersion;
  BYTE MinorLinkerVersion;
  DWORD SizeOfCode;
  DWORD SizeOfInitializedData;
  DWORD SizeOfUninitializedData;
  DWORD AddressOfEntryPoint;
  DWORD BaseOfCode;
  DWORD BaseOfData;
  DWORD ImageBase;
  DWORD SectionAlignment;
  DWORD FileAlignment;
  WORD MajorOperatingSystemVersion;
  WORD MinorOperatingSystemVersion;
  WORD MajorImageVersion;
  WORD MinorImageVersion;
  WORD MajorSubsystemVersion;
  WORD MinorSubsystemVersion;
  DWORD Win32VersionValue;
  DWORD SizeOfImage;
  DWORD SizeOfHeaders;
  DWORD CheckSum;
  WORD Subsystem;
  WORD DllCharacteristics;
  DWORD SizeOfStackReserve;
  DWORD SizeOfStackCommit;
  DWORD SizeOfHeapReserve;
  DWORD SizeOfHeapCommit;
  DWORD LoaderFlags;
  DWORD NumberOfRvaAndSizes;

  static unsigned long size()
  {
    return 96;
  }

  // generated from header_gen.cpp:82
  void parse(unsigned char const* pBuffer)
  {
    Magic = read_n<2>(&pBuffer[0x0]);
    MajorLinkerVersion = read_n<1>(&pBuffer[0x2]);
    MinorLinkerVersion = read_n<1>(&pBuffer[0x3]);
    SizeOfCode = read_n<4>(&pBuffer[0x4]);
    SizeOfInitializedData = read_n<4>(&pBuffer[0x8]);
    SizeOfUninitializedData = read_n<4>(&pBuffer[0xc]);
    AddressOfEntryPoint = read_n<4>(&pBuffer[0x10]);
    BaseOfCode = read_n<4>(&pBuffer[0x14]);
    BaseOfData = read_n<4>(&pBuffer[0x18]);
    ImageBase = read_n<4>(&pBuffer[0x1c]);
    SectionAlignment = read_n<4>(&pBuffer[0x20]);
    FileAlignment = read_n<4>(&pBuffer[0x24]);
    MajorOperatingSystemVersion = read_n<2>(&pBuffer[0x28]);
    MinorOperatingSystemVersion = read_n<2>(&pBuffer[0x2a]);
    MajorImageVersion = read_n<2>(&pBuffer[0x2c]);
    MinorImageVersion = read_n<2>(&pBuffer[0x2e]);
    MajorSubsystemVersion = read_n<2>(&pBuffer[0x30]);
    MinorSubsystemVersion = read_n<2>(&pBuffer[0x32]);
    Win32VersionValue = read_n<4>(&pBuffer[0x34]);
    SizeOfImage = read_n<4>(&pBuffer[0x38]);
    SizeOfHeaders = read_n<4>(&pBuffer[0x3c]);
    CheckSum = read_n<4>(&pBuffer[0x40]);
    Subsystem = read_n<2>(&pBuffer[0x44]);
    DllCharacteristics = read_n<2>(&pBuffer[0x46]);
    SizeOfStackReserve = read_n<4>(&pBuffer[0x48]);
    SizeOfStackCommit = read_n<4>(&pBuffer[0x4c]);
    SizeOfHeapReserve = read_n<4>(&pBuffer[0x50]);
    SizeOfHeapCommit = read_n<4>(&pBuffer[0x54]);
    LoaderFlags = read_n<4>(&pBuffer[0x58]);
    NumberOfRvaAndSizes = read_n<4>(&pBuffer[0x5c]);
  }

  // generated from header_gen.cpp:108
  void print() const
  {
    //std::cout << "PE_OPT_HEADER" << std::endl; 
    //std::cout << "Magic = 0x" << std::hex << (unsigned int)(Magic) << std::endl;
    //std::cout << "MajorLinkerVersion = 0x" << std::hex << (unsigned int)(MajorLinkerVersion) << std::endl;
    //std::cout << "MinorLinkerVersion = 0x" << std::hex << (unsigned int)(MinorLinkerVersion) << std::endl;
    //std::cout << "SizeOfCode = 0x" << std::hex << (unsigned int)(SizeOfCode) << std::endl;
    //std::cout << "SizeOfInitializedData = 0x" << std::hex << (unsigned int)(SizeOfInitializedData) << std::endl;
    //std::cout << "SizeOfUninitializedData = 0x" << std::hex << (unsigned int)(SizeOfUninitializedData) << std::endl;
    //std::cout << "AddressOfEntryPoint = 0x" << std::hex << (unsigned int)(AddressOfEntryPoint) << std::endl;
    //std::cout << "BaseOfCode = 0x" << std::hex << (unsigned int)(BaseOfCode) << std::endl;
    //std::cout << "BaseOfData = 0x" << std::hex << (unsigned int)(BaseOfData) << std::endl;
    //std::cout << "ImageBase = 0x" << std::hex << (unsigned int)(ImageBase) << std::endl;
    //std::cout << "SectionAlignment = 0x" << std::hex << (unsigned int)(SectionAlignment) << std::endl;
    //std::cout << "FileAlignment = 0x" << std::hex << (unsigned int)(FileAlignment) << std::endl;
    //std::cout << "MajorOperatingSystemVersion = 0x" << std::hex << (unsigned int)(MajorOperatingSystemVersion) << std::endl;
    //std::cout << "MinorOperatingSystemVersion = 0x" << std::hex << (unsigned int)(MinorOperatingSystemVersion) << std::endl;
    //std::cout << "MajorImageVersion = 0x" << std::hex << (unsigned int)(MajorImageVersion) << std::endl;
    //std::cout << "MinorImageVersion = 0x" << std::hex << (unsigned int)(MinorImageVersion) << std::endl;
    //std::cout << "MajorSubsystemVersion = 0x" << std::hex << (unsigned int)(MajorSubsystemVersion) << std::endl;
    //std::cout << "MinorSubsystemVersion = 0x" << std::hex << (unsigned int)(MinorSubsystemVersion) << std::endl;
    //std::cout << "Win32VersionValue = 0x" << std::hex << (unsigned int)(Win32VersionValue) << std::endl;
    //std::cout << "SizeOfImage = 0x" << std::hex << (unsigned int)(SizeOfImage) << std::endl;
    //std::cout << "SizeOfHeaders = 0x" << std::hex << (unsigned int)(SizeOfHeaders) << std::endl;
    //std::cout << "CheckSum = 0x" << std::hex << (unsigned int)(CheckSum) << std::endl;
    //std::cout << "Subsystem = 0x" << std::hex << (unsigned int)(Subsystem) << std::endl;
    //std::cout << "DllCharacteristics = 0x" << std::hex << (unsigned int)(DllCharacteristics) << std::endl;
    //std::cout << "SizeOfStackReserve = 0x" << std::hex << (unsigned int)(SizeOfStackReserve) << std::endl;
    //std::cout << "SizeOfStackCommit = 0x" << std::hex << (unsigned int)(SizeOfStackCommit) << std::endl;
    //std::cout << "SizeOfHeapReserve = 0x" << std::hex << (unsigned int)(SizeOfHeapReserve) << std::endl;
    //std::cout << "SizeOfHeapCommit = 0x" << std::hex << (unsigned int)(SizeOfHeapCommit) << std::endl;
    //std::cout << "LoaderFlags = 0x" << std::hex << (unsigned int)(LoaderFlags) << std::endl;
    //std::cout << "NumberOfRvaAndSizes = 0x" << std::hex << (unsigned int)(NumberOfRvaAndSizes) << std::endl;
  }

};

  // generated from header_gen.cpp:47
class PE_SECTION_HEADER
{
public:
  BYTE Name[8];
  DWORD VirtualSize;
  DWORD VirtualAddress;
  DWORD SizeOfRawData;
  DWORD PointerToRawData;
  DWORD PointerToRelocations;
  DWORD PointerToLinenumbers;
  WORD NumberOfRelocations;
  WORD NumberOfLinenumbers;
  DWORD Characteristics;

  static unsigned long size()
  {
    return 40;
  }

  // generated from header_gen.cpp:82
  void parse(unsigned char const* pBuffer)
  {
    Name[0] = read_n<1>(&pBuffer[0x0]);
    Name[1] = read_n<1>(&pBuffer[0x1]);
    Name[2] = read_n<1>(&pBuffer[0x2]);
    Name[3] = read_n<1>(&pBuffer[0x3]);
    Name[4] = read_n<1>(&pBuffer[0x4]);
    Name[5] = read_n<1>(&pBuffer[0x5]);
    Name[6] = read_n<1>(&pBuffer[0x6]);
    Name[7] = read_n<1>(&pBuffer[0x7]);
    VirtualSize = read_n<4>(&pBuffer[0x8]);
    VirtualAddress = read_n<4>(&pBuffer[0xc]);
    SizeOfRawData = read_n<4>(&pBuffer[0x10]);
    PointerToRawData = read_n<4>(&pBuffer[0x14]);
    PointerToRelocations = read_n<4>(&pBuffer[0x18]);
    PointerToLinenumbers = read_n<4>(&pBuffer[0x1c]);
    NumberOfRelocations = read_n<2>(&pBuffer[0x20]);
    NumberOfLinenumbers = read_n<2>(&pBuffer[0x22]);
    Characteristics = read_n<4>(&pBuffer[0x24]);
  }

  // generated from header_gen.cpp:108
  void print() const
  {
    //std::cout << "PE_SECTION_HEADER" << std::endl; 
    //std::cout << "Name[0] = 0x" << std::hex << (unsigned int)(Name[0]) << " '" <<  char(isprint(Name[0]) ? Name[0] : '.' ) << "'" << std::endl;
    //std::cout << "Name[1] = 0x" << std::hex << (unsigned int)(Name[1]) << " '" <<  char(isprint(Name[1]) ? Name[1] : '.' ) << "'" << std::endl;
    //std::cout << "Name[2] = 0x" << std::hex << (unsigned int)(Name[2]) << " '" <<  char(isprint(Name[2]) ? Name[2] : '.' ) << "'" << std::endl;
    //std::cout << "Name[3] = 0x" << std::hex << (unsigned int)(Name[3]) << " '" <<  char(isprint(Name[3]) ? Name[3] : '.' ) << "'" << std::endl;
    //std::cout << "Name[4] = 0x" << std::hex << (unsigned int)(Name[4]) << " '" <<  char(isprint(Name[4]) ? Name[4] : '.' ) << "'" << std::endl;
    //std::cout << "Name[5] = 0x" << std::hex << (unsigned int)(Name[5]) << " '" <<  char(isprint(Name[5]) ? Name[5] : '.' ) << "'" << std::endl;
    //std::cout << "Name[6] = 0x" << std::hex << (unsigned int)(Name[6]) << " '" <<  char(isprint(Name[6]) ? Name[6] : '.' ) << "'" << std::endl;
    //std::cout << "Name[7] = 0x" << std::hex << (unsigned int)(Name[7]) << " '" <<  char(isprint(Name[7]) ? Name[7] : '.' ) << "'" << std::endl;
    //std::cout << "VirtualSize = 0x" << std::hex << (unsigned int)(VirtualSize) << std::endl;
    //std::cout << "VirtualAddress = 0x" << std::hex << (unsigned int)(VirtualAddress) << std::endl;
    //std::cout << "SizeOfRawData = 0x" << std::hex << (unsigned int)(SizeOfRawData) << std::endl;
    //std::cout << "PointerToRawData = 0x" << std::hex << (unsigned int)(PointerToRawData) << std::endl;
    //std::cout << "PointerToRelocations = 0x" << std::hex << (unsigned int)(PointerToRelocations) << std::endl;
    //std::cout << "PointerToLinenumbers = 0x" << std::hex << (unsigned int)(PointerToLinenumbers) << std::endl;
    //std::cout << "NumberOfRelocations = 0x" << std::hex << (unsigned int)(NumberOfRelocations) << std::endl;
    //std::cout << "NumberOfLinenumbers = 0x" << std::hex << (unsigned int)(NumberOfLinenumbers) << std::endl;
    //std::cout << "Characteristics = 0x" << std::hex << (unsigned int)(Characteristics) << std::endl;
  }

};

  // generated from header_gen.cpp:47
class IMAGE_DATA_DIRECTORY
{
public:
  DWORD VirtualAddress;
  DWORD Size;

  static unsigned long size()
  {
    return 8;
  }

  // generated from header_gen.cpp:82
  void parse(unsigned char const* pBuffer)
  {
    VirtualAddress = read_n<4>(&pBuffer[0x0]);
    Size = read_n<4>(&pBuffer[0x4]);
  }

  // generated from header_gen.cpp:108
  void print() const
  {
    //std::cout << "IMAGE_DATA_DIRECTORY" << std::endl; 
    //std::cout << "VirtualAddress = 0x" << std::hex << (unsigned int)(VirtualAddress) << std::endl;
    //std::cout << "Size = 0x" << std::hex << (unsigned int)(Size) << std::endl;
  }

};

  // generated from header_gen.cpp:47
class IMAGE_EXPORT_DIRECTORY
{
public:
  DWORD Characteristics;
  DWORD TimeDateStamp;
  WORD MajorVersion;
  WORD MinorVersion;
  DWORD Name;
  DWORD Base;
  DWORD NumberOfFunctions;
  DWORD NumberOfNames;
  DWORD AddressOfFunctions;
  DWORD AddressOfNames;
  DWORD AddressOfNameOrdinals;

  static unsigned long size()
  {
    return 40;
  }

  // generated from header_gen.cpp:82
  void parse(unsigned char const* pBuffer)
  {
    Characteristics = read_n<4>(&pBuffer[0x0]);
    TimeDateStamp = read_n<4>(&pBuffer[0x4]);
    MajorVersion = read_n<2>(&pBuffer[0x8]);
    MinorVersion = read_n<2>(&pBuffer[0xa]);
    Name = read_n<4>(&pBuffer[0xc]);
    Base = read_n<4>(&pBuffer[0x10]);
    NumberOfFunctions = read_n<4>(&pBuffer[0x14]);
    NumberOfNames = read_n<4>(&pBuffer[0x18]);
    AddressOfFunctions = read_n<4>(&pBuffer[0x1c]);
    AddressOfNames = read_n<4>(&pBuffer[0x20]);
    AddressOfNameOrdinals = read_n<4>(&pBuffer[0x24]);
  }

  // generated from header_gen.cpp:108
  void print() const
  {
    //std::cout << "IMAGE_EXPORT_DIRECTORY" << std::endl; 
    //std::cout << "Characteristics = 0x" << std::hex << (unsigned int)(Characteristics) << std::endl;
    //std::cout << "TimeDateStamp = 0x" << std::hex << (unsigned int)(TimeDateStamp) << std::endl;
    //std::cout << "MajorVersion = 0x" << std::hex << (unsigned int)(MajorVersion) << std::endl;
    //std::cout << "MinorVersion = 0x" << std::hex << (unsigned int)(MinorVersion) << std::endl;
    //std::cout << "Name = 0x" << std::hex << (unsigned int)(Name) << std::endl;
    //std::cout << "Base = 0x" << std::hex << (unsigned int)(Base) << std::endl;
    //std::cout << "NumberOfFunctions = 0x" << std::hex << (unsigned int)(NumberOfFunctions) << std::endl;
    //std::cout << "NumberOfNames = 0x" << std::hex << (unsigned int)(NumberOfNames) << std::endl;
    //std::cout << "AddressOfFunctions = 0x" << std::hex << (unsigned int)(AddressOfFunctions) << std::endl;
    //std::cout << "AddressOfNames = 0x" << std::hex << (unsigned int)(AddressOfNames) << std::endl;
    //std::cout << "AddressOfNameOrdinals = 0x" << std::hex << (unsigned int)(AddressOfNameOrdinals) << std::endl;
  }

};

