/**
 * @file main.cpp
 * @brief Given an input dll, generates C code for a proxy dll.
 * @author Sebastien Alaiwan
 * @date 2014-10-01
 */

/*
 * Copyright (C) 2014 - Sebastien Alaiwan
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <cassert>
#include <cstdlib>
#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <list>
#include <stdexcept>
#include <stdint.h>

#include "pe_headers.h"

template<int N>
uint32_t read_n(std::vector<uint8_t> const& buffer, int offset)
{
  uint32_t iRet = 0;
  for(int i=0;i < N;++i)
  {
    if(offset+i >= buffer.size())
      throw std::runtime_error("out of bounds.");
    iRet |= ((uint32_t)(buffer[offset+i]) << i*8);
  }
  return iRet;
}

uint32_t read_uint(std::vector<uint8_t> const& buffer, int offset)
{
  return read_n<4>(buffer, offset);
}

uint32_t read_ushort(std::vector<uint8_t> const& buffer, int offset)
{
  return read_n<2>(buffer, offset);
}

uint32_t read_uint(uint8_t const* buffer)
{
  return read_n<4>(buffer);
}

uint32_t read_ushort(uint8_t const* buffer)
{
  return read_n<2>(buffer);
}

std::string offset(uint32_t iOffset)
{
  char buffer[256];
  sprintf(buffer, "0x%.8X", iOffset);
  return buffer;
}

std::list<std::string> g_ExportedNames;

uint32_t rva_to_offset(PE_SECTION_HEADER const& sh, uint32_t iVirtualAddress)
{
  assert(iVirtualAddress >= sh.VirtualAddress);
  assert(iVirtualAddress < sh.VirtualAddress + sh.VirtualSize);
  return (iVirtualAddress - sh.VirtualAddress) + sh.PointerToRawData;
}

std::string read_string(uint8_t const* buffer)
{
  std::string sRet;
  while(*buffer)
  {
    sRet += *buffer++;
  }
  return sRet;
}

void parse_dll(std::vector<uint8_t> const& buffer)
{
  // parse MZ header
  MZ_HEADER mz_header;
  mz_header.parse(&buffer[0]);
  if(mz_header.e_magic != 0x5A4D)
    throw std::runtime_error("MZ parse error.");

  PE_HEADER pe_header;
  pe_header.parse(&buffer[mz_header.e_lfanew]);
  if(pe_header.Magic != 0x4550)
    throw std::runtime_error("PE parse error.");

  PE_OPT_HEADER pe_opt_header;
  pe_opt_header.parse(&buffer[mz_header.e_lfanew+PE_HEADER::size()]);
  if(pe_opt_header.Magic != 0x010B)
    throw std::runtime_error("PE optional parse error.");

  std::vector<IMAGE_DATA_DIRECTORY> DataDirectory;
  uint8_t const* pDataDirectory = &buffer[mz_header.e_lfanew+PE_HEADER::size()+PE_OPT_HEADER::size()];
  for(int i=0;i < pe_opt_header.NumberOfRvaAndSizes;++i)
  {
    IMAGE_DATA_DIRECTORY entry;
    entry.parse(&pDataDirectory[i*IMAGE_DATA_DIRECTORY::size()]);
    DataDirectory.push_back(entry);
  }

  std::vector<PE_SECTION_HEADER> SectionHeaders;
  uint8_t const* pSections = pDataDirectory + pe_opt_header.NumberOfRvaAndSizes * IMAGE_DATA_DIRECTORY::size();
  for(int i=0;i < pe_header.NumberOfSections;++i)
  {
    PE_SECTION_HEADER sh;
    sh.parse(&pSections[i*PE_SECTION_HEADER::size()]);
    SectionHeaders.push_back(sh);
  }

  // find the section who contains the export directory
  int iExportDirectoryVA = DataDirectory[0].VirtualAddress;
  int iExportDirectorySectionIndex = -1;

  //std::cout << "Looking for " << offset(iExportDirectoryVA) << std::endl;
  for(size_t i=0;i < SectionHeaders.size();++i)
  {
    PE_SECTION_HEADER const& sh = SectionHeaders[i];
    if(iExportDirectoryVA >= sh.VirtualAddress && iExportDirectoryVA < sh.VirtualAddress + sh.VirtualSize)
    {
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
    int iFunctionNamePA = rva_to_offset(sh, iFunctionNameRVA);
    std::string sFunctionName = read_string(&buffer[iFunctionNamePA]);
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
    std::vector<uint8_t> bin_buffer;
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
      fp_out << "HMODULE g_hModule;" << std::endl;
      for(auto& sName : g_ExportedNames)
      {
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
      for(auto& sName : g_ExportedNames)
      {
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
    for(auto& sName : g_ExportedNames)
    {
      fp_out << "extern \"C\" __declspec(naked) void proxy_" << sName << "()" << std::endl;
      fp_out << "{" << std::endl;
      fp_out << "  fprintf(stderr, \"proxy-dll: entering function " << sName << "\\n\");" << std::endl;
      fp_out << "  __asm jmp g_p" << sName << ";" << std::endl;
      fp_out << "}" << std::endl;
      fp_out << std::endl;
    }

    // generate module definition (.def) file
    {
      std::string sDefFilename = sSrcFilename + ".def";
      std::ofstream fp_def_out(sDefFilename.c_str());
      fp_def_out << "EXPORTS" << std::endl;
      for(auto& sName : g_ExportedNames)
      {
        fp_def_out << "  " << sName << "=proxy_" << sName << std::endl;
      }
    }

    return EXIT_SUCCESS;
  }
  catch(std::runtime_error const& e)
  {
    std::cerr << "Runtime error : " << e.what() << std::endl;
    return EXIT_FAILURE;
  }
}
