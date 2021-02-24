#pragma once

#include <cstring>
#include <iostream>
#include <fstream>
#include <stdio.h>
#include <stdlib.h>
#include <algorithm>
#include <ctime>
#include <windows.h>
#include <cryptdlg.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <cryptuiapi.h>
#include <vector>
#include <msclr\marshal_cppstd.h>

#include "..\\..\\lib\\AdESNet.Common.h"

#ifdef _WIN64
#ifdef _DEBUG
#pragma comment(lib,"..\\..\\lib\\x64\\debug\\zlibstaticd.lib")
#pragma comment(lib, "..\\..\\lib\\x64\\debug\\AdES.lib")
#include "..\\..\\lib\\x64\\debug\\AdES.hpp"
#else
#pragma comment(lib,"..\\..\\lib\\x64\\release\\zlibstatic.lib")
#pragma comment(lib, "..\\..\\lib\\x64\\release\\AdES.lib")
#include "..\\..\\lib\\x64\\release\\AdES.hpp"

#endif

#else
#ifdef _DEBUG
#pragma comment(lib,"..\\..\\lib\\x86\\debug\\zlibstaticd.lib")
#pragma comment(lib, "..\\..\\lib\\x86\\debug\\AdES.lib")
#include "..\\..\\lib\\x86\\debug\\AdES.hpp"
#else
#pragma comment(lib,"..\\..\\lib\\x86\\release\\zlibstatic.lib")
#pragma comment(lib, "..\\..\\lib\\x86\\release\\AdES.lib")
#include "..\\..\\lib\\x86\\release\\AdES.hpp"
#endif
#pragma comment(lib,"vcruntime.lib")
#endif

using namespace System;

namespace AdESNetCLR 
{
	public ref class AdESWrapper 
	{
		AdES* m_AdES;	

	public:
		AdESWrapper() { m_AdES = new AdES(); }
		~AdESWrapper() { this->!AdESWrapper(); }
		!AdESWrapper() { delete m_AdES; }		

		bool IsDebug = false;

		AdESResult^ CAdESSign(
			array<Byte>^ dataToSign, 
			SignatureContext^ signatureContext);

		AdESResult^ PAdESSign(
			array<Byte>^ dataToSign, 
			PAdESSignatureContext^ signatureContext);

		AdESResult^ XAdESSign(
			array<Byte>^ dataToSign, 
			XAdESSignatureContext^ signatureContext);
	};
}
