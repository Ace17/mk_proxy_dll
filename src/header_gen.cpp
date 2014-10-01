#include <iostream>
#include <stdio.h>

#define ARRAY_SIZE(a) (sizeof(a)/sizeof(*a))

/*
template<typename T, int N> int ArraySize(int (&t)[N])
{
  return N;
}
*/

struct MemberDescription
{
  int iSizeInBytes;
  char const* sType;
  char const* sName;
  int iArrayLength;
  char const* sComment;
};

std::string gen_indexed(std::string const& sVar, std::string const& sIndex)
{
  return sVar + "[" + sIndex + "]";
}

std::string gen_int(int iVal)
{
  char buffer[256];
  sprintf(buffer, "%d", iVal);
  return buffer;
}

std::string gen_indexed(std::string const& sVar, int iLiteralIndex)
{
  return sVar + "[" + gen_int(iLiteralIndex) + "]";
}

struct HeaderDescription
{
  char const* sName;
  MemberDescription* pMembers;
  int iNumMembers;

  void GenerateCPP()
  {
    std::cout << "  // generated from " << __FILE__ << ":" << std::dec << __LINE__ << std::endl;
    std::cout << "class " << sName << std::endl;
    std::cout << "{" << std::endl;
    std::cout << "public:" << std::endl;

    // Generate members
    for(int i=0;i < iNumMembers;++i)
    {
      std::cout << "  ";
      std::cout << pMembers[i].sType << " ";
      std::cout << pMembers[i].sName;
      if(pMembers[i].iArrayLength > 1)
      {
        std::cout << "[" << pMembers[i].iArrayLength << "]";
      }
      std::cout << ";" << std::endl;
    }
    std::cout << std::endl;

    // Generate "size" function
    {
      int iTotalSize = 0;
      for(int i=0;i < iNumMembers;++i)
      {
        iTotalSize += pMembers[i].iSizeInBytes * pMembers[i].iArrayLength;
      }
      std::cout << "  static unsigned long size()" << std::endl;
      std::cout << "  {" << std::endl;
      std::cout << "    return " << iTotalSize << ";" << std::endl;
      std::cout << "  }" << std::endl;
      std::cout << std::endl;
    }

    // Generate "parse" function
    {
      std::cout << "  // generated from " << __FILE__ << ":" << std::dec << __LINE__ << std::endl;
      std::cout << "  void parse(unsigned char const* pBuffer)" << std::endl;
      std::cout << "  {" << std::endl;
      int iOffset = 0;
      for(int i=0;i < iNumMembers;++i)
      {
        if(pMembers[i].iArrayLength > 1)
        {
          for(int k=0;k < pMembers[i].iArrayLength;++k)
          {
            std::cout << "    " << pMembers[i].sName << "[" << k << "] = read_n<" << pMembers[i].iSizeInBytes << ">(&pBuffer[0x" << std::hex << iOffset << "]);" << std::endl;
            iOffset += pMembers[i].iSizeInBytes;
          }
        }
        else
        {
          std::cout << "    " << pMembers[i].sName << " = read_n<" << pMembers[i].iSizeInBytes << ">(&pBuffer[0x" << std::hex << iOffset << "]);" << std::endl;
          iOffset += pMembers[i].iSizeInBytes;
        }
      }
      std::cout << "  }" << std::endl;
      std::cout << std::endl;
    }

    // Generate "print" function
    {
      std::cout << "  // generated from " << __FILE__ << ":" << std::dec << __LINE__ << std::endl;
      std::cout << "  void print() const" << std::endl;
      std::cout << "  {" << std::endl;
      std::cout << "    //std::cout << \""<< sName << "\" << std::endl; " << std::endl;
      int iOffset = 0;
      for(int i=0;i < iNumMembers;++i)
      {
        MemberDescription& mbr = pMembers[i];
        if(mbr.iArrayLength > 1)
        {
          for(int k=0;k < mbr.iArrayLength;++k)
          {
            std::string sIndexed = gen_indexed(mbr.sName, k);
            std::cout << "    //std::cout << \"" << sIndexed << " = 0x\" << std::hex << (unsigned int)(" << sIndexed << ") << \" '\" <<  char(isprint(" << sIndexed << ") ? " << sIndexed << " : '.' ) << \"'\" << std::endl;" << std::endl;
          }
        }
        else
        {
          std::cout << "    //std::cout << \"" << pMembers[i].sName << " = 0x\" << std::hex << (unsigned int)(" << pMembers[i].sName << ") << std::endl;" << std::endl;
        }
        iOffset += pMembers[i].iSizeInBytes;
      }
      std::cout << "  }" << std::endl;
      std::cout << std::endl;
    }

    std::cout << "};" << std::endl;
  }
};

//------------------------------------------------------------------------------
// MZ header description
//------------------------------------------------------------------------------
MemberDescription mz_members[] = 
{
  {2, "WORD", "e_magic"   ,  1,  "Magic number"},
  {2, "WORD", "e_cblp"    ,  1,  "Bytes on last page of file"},
  {2, "WORD", "e_cp"      ,  1,  "Pages in file"},
  {2, "WORD", "e_crlc"    ,  1,  "Relocations"},
  {2, "WORD", "e_cparhdr" ,  1,  "Size of header in paragraphs"},
  {2, "WORD", "e_minalloc",  1,  "Minimum extra paragraphs needed"},
  {2, "WORD", "e_maxalloc",  1,  "Maximum extra paragraphs needed"},
  {2, "WORD", "e_ss"      ,  1,  "Initial (relative) SS value"},
  {2, "WORD", "e_sp"      ,  1,  "Initial SP value"},
  {2, "WORD", "e_csum"    ,  1,  "Checksum"},
  {2, "WORD", "e_ip"      ,  1,  "Initial IP value"},
  {2, "WORD", "e_cs"      ,  1,  "Initial (relative) CS value"},
  {2, "WORD", "e_lfarlc"  ,  1,  "File address of relocation table"},
  {2, "WORD", "e_ovno"    ,  1,  "Overlay number"},
  {2, "WORD", "e_res"     ,  4,  "Reserved words"},
  {2, "WORD", "e_oemid"   ,  1,  "OEM identifier (for e_oeminfo)"},
  {2, "WORD", "e_oeminfo" ,  1,  "OEM information; e_oemid specific"},
  {2, "WORD", "e_res2"    , 10,  "Reserved words"},
  {4, "DWORD"  , "e_lfanew"  ,  1,  "File address of new exe header"},
};

HeaderDescription mz_header = 
{
  "MZ_HEADER",
  mz_members,
  ARRAY_SIZE(mz_members)
};

//------------------------------------------------------------------------------
// PE header description
//------------------------------------------------------------------------------
MemberDescription pe_header_members[] = 
{
  {4, "DWORD", "Magic",                1, ""},
  {2, "WORD",  "Machine",              1, ""},
  {2, "WORD",  "NumberOfSections",     1, ""},
  {4, "DWORD", "TimeDateStamp",        1, ""},
  {4, "DWORD", "PointerToSymbolTable", 1, ""},
  {4, "DWORD", "NumberOfSymbols",      1, ""},
  {2, "WORD",  "SizeOfOptionalHeader", 1, ""},
  {2, "WORD",  "Characteristics",      1, ""},
};

HeaderDescription pe_header = 
{
  "PE_HEADER",
  pe_header_members,
  ARRAY_SIZE(pe_header_members)
};

//------------------------------------------------------------------------------
// PE optional header description
//------------------------------------------------------------------------------
MemberDescription pe_opt_header_members[] = 
{
  {2, "WORD",  "Magic", 1, ""},
  {1, "BYTE",  "MajorLinkerVersion", 1, ""},
  {1, "BYTE",  "MinorLinkerVersion", 1, ""},
  {4, "DWORD", "SizeOfCode", 1, ""},
  {4, "DWORD", "SizeOfInitializedData", 1, ""},
  {4, "DWORD", "SizeOfUninitializedData", 1, ""},
  {4, "DWORD", "AddressOfEntryPoint", 1, ""},
  {4, "DWORD", "BaseOfCode", 1, ""},
  {4, "DWORD", "BaseOfData", 1, ""},
  {4, "DWORD", "ImageBase", 1, ""},
  {4, "DWORD", "SectionAlignment", 1, ""},
  {4, "DWORD", "FileAlignment", 1, ""},
  {2, "WORD",  "MajorOperatingSystemVersion", 1, ""},
  {2, "WORD",  "MinorOperatingSystemVersion", 1, ""},
  {2, "WORD",  "MajorImageVersion", 1, ""},
  {2, "WORD",  "MinorImageVersion", 1, ""},
  {2, "WORD",  "MajorSubsystemVersion", 1, ""},
  {2, "WORD",  "MinorSubsystemVersion", 1, ""},
  {4, "DWORD", "Win32VersionValue", 1, ""},
  {4, "DWORD", "SizeOfImage", 1, ""},
  {4, "DWORD", "SizeOfHeaders", 1, ""},
  {4, "DWORD", "CheckSum", 1, ""},
  {2, "WORD",  "Subsystem", 1, ""},
  {2, "WORD",  "DllCharacteristics", 1, ""},
  {4, "DWORD", "SizeOfStackReserve", 1, ""},
  {4, "DWORD", "SizeOfStackCommit", 1, ""},
  {4, "DWORD", "SizeOfHeapReserve", 1, ""},
  {4, "DWORD", "SizeOfHeapCommit", 1, ""},
  {4, "DWORD", "LoaderFlags", 1, ""},
  {4, "DWORD", "NumberOfRvaAndSizes", 1, ""},
};

HeaderDescription pe_opt_header =
{
  "PE_OPT_HEADER",
  pe_opt_header_members,
  ARRAY_SIZE(pe_opt_header_members)
};

//------------------------------------------------------------------------------
// PE section header description
//------------------------------------------------------------------------------
MemberDescription pe_section_header_members[] = 
{
  { 1, "BYTE",  "Name",                  8, "" },
  { 4, "DWORD", "VirtualSize",           1, "" },
  { 4, "DWORD", "VirtualAddress",        1, "" },
  { 4, "DWORD", "SizeOfRawData",         1, "" },
  { 4, "DWORD", "PointerToRawData",      1, "" },
  { 4, "DWORD", "PointerToRelocations",  1, "" },
  { 4, "DWORD", "PointerToLinenumbers",  1, "" },
  { 2, "WORD",  "NumberOfRelocations",   1, "" },
  { 2, "WORD",  "NumberOfLinenumbers",   1, "" },
  { 4, "DWORD", "Characteristics",       1, "" },
};

HeaderDescription pe_section_header = 
{
  "PE_SECTION_HEADER",
  pe_section_header_members,
  ARRAY_SIZE(pe_section_header_members)
};

//------------------------------------------------------------------------------
// PE section header description
//------------------------------------------------------------------------------
MemberDescription data_directory_members[] = 
{
  { 4, "DWORD", "VirtualAddress", 1, "" },
  { 4, "DWORD", "Size",           1, "" },
};

HeaderDescription data_directory_header = 
{
  "IMAGE_DATA_DIRECTORY",
  data_directory_members,
  ARRAY_SIZE(data_directory_members)
};

//------------------------------------------------------------------------------
// Export directory description
//------------------------------------------------------------------------------
MemberDescription export_directory_members[] = 
{
  {4, "DWORD", "Characteristics",             1, ""},
  {4, "DWORD", "TimeDateStamp",               1, ""},
  {2, "WORD" , "MajorVersion",                1, ""},
  {2, "WORD" , "MinorVersion",                1, ""},
  {4, "DWORD", "Name",                        1, ""},
  {4, "DWORD", "Base",                        1, ""},
  {4, "DWORD", "NumberOfFunctions",           1, ""},
  {4, "DWORD", "NumberOfNames",               1, ""},
  {4, "DWORD", "AddressOfFunctions",          1, ""},
  {4, "DWORD", "AddressOfNames",              1, ""},
  {4, "DWORD", "AddressOfNameOrdinals",       1, ""},
};

HeaderDescription export_directory_header = 
{
  "IMAGE_EXPORT_DIRECTORY",
  export_directory_members,
  ARRAY_SIZE(export_directory_members)
};

//------------------------------------------------------------------------------

HeaderDescription* all_headers[] = 
{
  &mz_header,
  &pe_header,
  &pe_opt_header,
  &pe_section_header,
  &data_directory_header,
  &export_directory_header,
};

//------------------------------------------------------------------------------

int main()
{
  std::cout << "#include <iostream>" << std::endl;
  std::cout << "#include <cctype>" << std::endl;
  std::cout << std::endl;
  std::cout << "typedef unsigned int DWORD;" << std::endl;
  std::cout << "typedef unsigned short WORD;" << std::endl;
  std::cout << "typedef unsigned char BYTE;" << std::endl;
  std::cout << std::endl;
  std::cout << "template<int N>" << std::endl;
  std::cout << "unsigned int read_n(unsigned char const* buffer)" << std::endl;
  std::cout << "{" << std::endl;
  std::cout << "  unsigned int iRet = 0;" << std::endl;
  std::cout << "  for(int i=0;i < N;++i)" << std::endl;
  std::cout << "  {" << std::endl;
  std::cout << "    iRet |= (unsigned int)(buffer[i]) << (i*8);" << std::endl;
  std::cout << "  }" << std::endl;
  std::cout << "  return iRet;" << std::endl;
  std::cout << "}" << std::endl;
  std::cout << std::endl;

  for(int i=0;i < ARRAY_SIZE(all_headers);++i)
  {
    all_headers[i]->GenerateCPP();
    std::cout << std::endl;
  }
  return 0;
}
