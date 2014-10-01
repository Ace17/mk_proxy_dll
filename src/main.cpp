#include <cassert>
#include <cstdlib>
#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <list>
#include <stdexcept>

#include "pe_headers.h"


template<int N>
unsigned int read_n(std::vector<unsigned char> const& buffer, int offset)
{
  unsigned int iRet = 0;
  for(int i=0;i < N;++i)
  {
    if(offset+i >= buffer.size())
      throw std::runtime_error("out of bounds.");
    iRet |= ((unsigned int)(buffer[offset+i]) << i*8);
//    //std::cout << "0x" << std::hex << int(buffer[offset+i]) << std::endl;
//    //std::cout << "iRet = 0x" << std::hex << iRet << std::endl;
  }
  return iRet;
}

unsigned int read_uint(std::vector<unsigned char> const& buffer, int offset)
{
  return read_n<4>(buffer, offset);
}

unsigned int read_ushort(std::vector<unsigned char> const& buffer, int offset)
{
  return read_n<2>(buffer, offset);
}

/*
template<int N>
unsigned int read_n(unsigned char const* buffer)
{
  unsigned int iRet = 0;
  for(int i=0;i < N;++i)
  {
    iRet |= ((unsigned int)(buffer[i]) << i*8);
  }
  return iRet;
}
*/

unsigned int read_uint(unsigned char const* buffer)
{
  return read_n<4>(buffer);
}

unsigned int read_ushort(unsigned char const* buffer)
{
  return read_n<2>(buffer);
}

std::string offset(unsigned int iOffset)
{
  char buffer[256];
  sprintf(buffer, "0x%.8X", iOffset);
  return buffer;
}

struct pe_opt_header_s
{
  unsigned short Magic; // must be 0x010B

  void parse(unsigned char const* buffer)
  {
    Magic = read_ushort(buffer);
    if(Magic != 0x010B)
      throw std::runtime_error("PE opt parse error (bad Magic).");
  }
};

struct pe_section_s
{
  std::string Name;
  unsigned long PhysicalAddress;
  unsigned long VirtualAddress;
  unsigned long SizeOfRawData;

  void parse(unsigned char const* buffer)
  {
    Name = "";
    for(int k=0;k < 8;++k)
      Name += buffer[k];

    PhysicalAddress = read_uint(buffer+12);

    //std::cout << "Section " << Name << " (offset=" << offset(PhysicalAddress) << ")" << std::endl;
  }
};

std::list<pe_section_s> g_Sections;
std::list<std::string> g_ExportedNames;

unsigned int rva_to_offset(PE_SECTION_HEADER const& sh, unsigned int iVirtualAddress)
{
  assert(iVirtualAddress >= sh.VirtualAddress);
  assert(iVirtualAddress < sh.VirtualAddress + sh.VirtualSize);
  return (iVirtualAddress - sh.VirtualAddress) + sh.PointerToRawData;
}

std::string read_string(unsigned char const* buffer)
{
  std::string sRet;
  while(*buffer)
  {
    sRet += *buffer++;
  }
  return sRet;
}

void parse_dll(std::vector<unsigned char> const& buffer)
{
  // parse MZ header
  MZ_HEADER mz_header;
  mz_header.parse(&buffer[0]);
  if(mz_header.e_magic != 0x5A4D)
    throw std::runtime_error("MZ parse error.");
  //std::cout << "Found MZ header at 0x" << offset(0) << " magic=" << offset(mz_header.e_magic) << std::endl;


  PE_HEADER pe_header;
  pe_header.parse(&buffer[mz_header.e_lfanew]);
  // pe_header.print();
  if(pe_header.Magic != 0x4550)
    throw std::runtime_error("PE parse error.");

  PE_OPT_HEADER pe_opt_header;
  pe_opt_header.parse(&buffer[mz_header.e_lfanew+PE_HEADER::size()]);
  // pe_opt_header.print();
  if(pe_opt_header.Magic != 0x010B)
    throw std::runtime_error("PE optional parse error.");

  //std::cout << "NumSections=" << std::dec << pe_header.NumberOfSections << std::endl;
  //std::cout << "NumberOfRvaAndSizes=" << pe_opt_header.NumberOfRvaAndSizes << std::endl;

  std::vector<IMAGE_DATA_DIRECTORY> DataDirectory;
  unsigned char const* pDataDirectory = &buffer[mz_header.e_lfanew+PE_HEADER::size()+PE_OPT_HEADER::size()];
  for(int i=0;i < pe_opt_header.NumberOfRvaAndSizes;++i)
  {
    IMAGE_DATA_DIRECTORY entry;
    entry.parse(&pDataDirectory[i*IMAGE_DATA_DIRECTORY::size()]);
    //entry.print();
    DataDirectory.push_back(entry);
  }

  std::vector<PE_SECTION_HEADER> SectionHeaders;
  unsigned char const* pSections = pDataDirectory + pe_opt_header.NumberOfRvaAndSizes * IMAGE_DATA_DIRECTORY::size();
  for(int i=0;i < pe_header.NumberOfSections;++i)
  {
    PE_SECTION_HEADER sh;
    sh.parse(&pSections[i*PE_SECTION_HEADER::size()]);
    //sh.print();
    SectionHeaders.push_back(sh);
  }

  // find the section who contains the export directory
  int iExportDirectoryVA = DataDirectory[0].VirtualAddress;
  int iExportDirectorySectionIndex = -1;

  //std::cout << "Looking for " << offset(iExportDirectoryVA) << std::endl;
  for(size_t i=0;i < SectionHeaders.size();++i)
  {
    PE_SECTION_HEADER const& sh = SectionHeaders[i];
    //std::cout << "Inspecting section #" << i << " ";
    //std::cout << "[" << offset(sh.VirtualAddress) << ";" << offset(sh.VirtualAddress+sh.VirtualSize) <<  "]";
    //std::cout << std::endl;
    if(iExportDirectoryVA >= sh.VirtualAddress && iExportDirectoryVA < sh.VirtualAddress + sh.VirtualSize)
    {
      //std::cout << "ExportDirectory is in section #" << i << std::endl;
      iExportDirectorySectionIndex = i;
    }
  }

  if(iExportDirectorySectionIndex == -1)
    throw std::runtime_error("Could not find section for export-directory");

  PE_SECTION_HEADER const& sh = SectionHeaders[iExportDirectorySectionIndex];
  int iExportDirectoryPA = rva_to_offset(sh, iExportDirectoryVA);

  IMAGE_EXPORT_DIRECTORY export_directory;
  export_directory.parse(&buffer[iExportDirectoryPA]);
  export_directory.print();

  int iNameArrayPA = rva_to_offset(sh, export_directory.AddressOfNames);

  for(int i=0;i < export_directory.NumberOfFunctions;++i)
  {
    int iFunctionNameRVA = read_uint(&buffer[iNameArrayPA+4*i]);
//    //std::cout << "FunctionName RVA=" << offset(iFunctionNameRVA) << std::endl;
    int iFunctionNamePA = rva_to_offset(sh, iFunctionNameRVA);
    std::string sFunctionName = read_string(&buffer[iFunctionNamePA]);
    ////std::cout << "Function #" << i << " : " << sFunctionName << std::endl;
    g_ExportedNames.push_back(sFunctionName);
  }
}

int main(int argc, char const* argv[])
{
  try
  {
    if(argc != 3)
    {
      std::cerr << "Usage: " << argv[0] << " <original.dll> <proxy.c>" << std::endl;
      return -1;
    }

    std::string sBinFilename = argv[1];
    std::vector<unsigned char> bin_buffer;
    std::ifstream fp_bin(sBinFilename.c_str(), std::ios::binary);
    while(fp_bin.good())
    {
      int c = fp_bin.get();
      bin_buffer.push_back(c);
    }

    //std::cout << "Loaded " << bin_buffer.size() << " bytes." << std::endl;

    parse_dll(bin_buffer);

    std::string sSrcFilename = argv[2];
    std::ofstream fp_out(sSrcFilename.c_str());

    // generate headers
    {
      fp_out << "#include <windows.h>" << std::endl;
      fp_out << "#include <stdio.h>" << std::endl;
    }

    // generate global variables
    {
      std::list<std::string>::const_iterator i_fn = g_ExportedNames.begin();
      fp_out << "HMODULE g_hModule;" << std::endl;
      while(i_fn != g_ExportedNames.end())
      {
        std::string const& sName = *i_fn++;
        fp_out << "static FARPROC g_p" << sName << ";" << std::endl;
        //      fp_out << sName << std::endl;
      }
    }

    // generate InitAddresses function
    {
      fp_out << "int InitAddresses()" << std::endl;
      fp_out << "{" << std::endl;
      fp_out << "  g_hModule = LoadLibrary(\"" << sBinFilename << "\");" << std::endl;
      fp_out << "  if(!g_hModule) return 0;" << std::endl;
      std::list<std::string>::const_iterator i_fn = g_ExportedNames.begin();
      while(i_fn != g_ExportedNames.end())
      {
        std::string const& sName = *i_fn++;
        fp_out << "  g_p" << sName << " = GetProcAddress(g_hModule, \"" << sName << "\");" << std::endl;
      }
      fp_out << "  return 1;" << std::endl;
      fp_out << "}" << std::endl;
      fp_out << std::endl;
    }

    // generate DllMain
    {
      fp_out << "BOOL WINAPI DllMain(HINSTANCE hInst,DWORD reason,LPVOID param)" << std::endl;
      fp_out << "{" << std::endl;
      fp_out << "  if (reason == DLL_PROCESS_ATTACH)" << std::endl;
      fp_out << "  {" << std::endl;
      fp_out << "    if(!InitAddresses())" << std::endl;
      fp_out << "      return FALSE;" << std::endl;
      fp_out << "  }" << std::endl;
      fp_out << "  if (reason == DLL_PROCESS_DETACH)" << std::endl;
      fp_out << "  {" << std::endl;
      fp_out << "    FreeLibrary(g_hModule);" << std::endl;
      fp_out << "  }" << std::endl;
      fp_out << "  return 1;" << std::endl;
      fp_out << "}" << std::endl;
      fp_out << std::endl;
    }

    // generate function stubs
    {
      std::list<std::string>::const_iterator i_fn = g_ExportedNames.begin();
      while(i_fn != g_ExportedNames.end())
      {
        std::string const& sName = *i_fn++;
        fp_out << "extern \"C\" __declspec(naked) void proxy_" << sName << "()" << std::endl;
        fp_out << "{" << std::endl;
		fp_out << "  fprintf(stderr, \"proxy-dll: entering function " << sName << "\\n\");" << std::endl;
        fp_out << "  __asm jmp g_p" << sName << ";" << std::endl;
        fp_out << "}" << std::endl;
        fp_out << std::endl;
      }
    }

    // generate module definition (.def) file
    {
      std::string sDefFilename = sSrcFilename + ".def";
      std::ofstream fp_def_out(sDefFilename.c_str());
      std::list<std::string>::const_iterator i_fn = g_ExportedNames.begin();
      fp_def_out << "EXPORTS" << std::endl;
      while(i_fn != g_ExportedNames.end())
      {
        std::string const& sName = *i_fn++;
        fp_def_out << "  " << sName << "=proxy_" << sName << std::endl;
      }
    }
  }
  catch(std::runtime_error const& e)
  {
    std::cerr << "Runtime error : " << e.what() << std::endl;
  }

  return EXIT_SUCCESS;
}
