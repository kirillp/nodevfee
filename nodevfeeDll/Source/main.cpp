#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <WinSock2.h>
#include <Mswsock.h>
#include <stdio.h>
#include "minhook\MinHook.h"

bool Initial = true;

char Wallet[43];

FILE *LogFile = 0;

struct Pool
{
	char Address[256];

	unsigned int Port;
};

Pool Pools[256];

int PoolCount = 0;

char const *Protocols[2] = {"eth_submitLogin", "eth_login"};

int ProtocolCount = 2;

int (__stdcall *sendOriginal)(SOCKET s, const char *buf, int len, int flags);
int (__stdcall *WSASendOriginal)(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
								 LPDWORD lpNumberOfBytesSent, DWORD dwFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);

int (__stdcall *connectOriginal)(SOCKET s, const struct sockaddr *name, int namelen);
BOOL (__stdcall *ConnectExOriginal)(SOCKET s, const struct sockaddr *name, int namelen, PVOID lpSendBuffer, DWORD dwSendDataLength, LPDWORD lpdwBytesSent, LPOVERLAPPED lpOverlapped);

int (__stdcall *WSAIoctlOriginal)(SOCKET s, DWORD dwIoControlCode, LPVOID lpvInBuffer, DWORD cbInBuffer, LPVOID lpvOutBuffer, DWORD cbOutBuffer, LPDWORD lpcbBytesReturned,
						 LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);

static void Error(const char *format, int result)
{
	static char error[1024] = {0};

	wsprintfA(error, format, result);

	MessageBoxA(0, error, "NoDevFeeDll", 0);
}

static char packet[512], packet2[512];

int addWorker(char const *buf, int len, char *packet, int packetSize, const char *pWorker0) {

  static const char worker[] = ",\"worker\":\"devfee\"";
  static const char eth_submitWork[] = "\"eth_submitWork\"";

  const char *submit = strstr(buf, eth_submitWork);

  if (submit && !pWorker0) {
    if (LogFile) fprintf(LogFile, "!!! eth_submitWork add worker");
    if (LogFile && packetSize == 0) {
      fprintf(LogFile, "!!! can not add worker, no memory for new packet\n");
    }
    if (len + 24 < packetSize) {

      char const *submitEnds = submit + sizeof(eth_submitWork) - 1;
      char const *packetEnds = strchr(submitEnds, '}');
      int newLen = 0;
      if (packetEnds && packetEnds < (buf + len)) {
        for (char const *p = buf; p < packetEnds; p++)
          packet[newLen++] = *p;

        for (char const *p = worker; *p; p++)
          packet[newLen++] = *p;

        for (char const *p = packetEnds; *p && (p < buf + len); p++)
          packet[newLen++] = *p;

        packet[newLen] = 0;

        if (LogFile) fprintf(LogFile, " = %4d buf = %s", newLen, packet);
        return newLen;

      } else {
        if (LogFile) fprintf(LogFile, "Error: buf[0] != '{'\n");
      }
    } else {
      if (LogFile) fprintf(LogFile, "Error: len + 24 >= sizeof(packet)\n");
    }
  }
  return 0;
}

static const char wokrer[] = "\"worker\"";

void replaceWorkerDots(char * pWorker0 /* == strstr(buf, wokrer) */) {
  char *pWorker1 = pWorker0 ? strchr(pWorker0 + 8, ':') : 0;
  char *pWorker2 = pWorker1 ? strchr(pWorker1 + 1, '"') : 0;
  if (pWorker2) {
    char * pWorker = pWorker2 + 1;
    char * pWorkerEnd = strchr(pWorker, '"');
    char * pWorkerDot = strchr(pWorker, '.');
    if (pWorkerEnd && pWorkerDot && (pWorkerDot < pWorkerEnd)) {
      *pWorkerEnd = 0;
      if (LogFile) fprintf(LogFile, "Replace worker %s ", pWorker);
      for (char *p = pWorker; p < pWorkerEnd; p++) {
        if (*p == '.') *p = '_';
      }
      if (LogFile) fprintf(LogFile, " -> worker %s\n", pWorker);
      *pWorkerEnd = '"';
    }
  }
}

int OnSend(SOCKET s, char *buf, int len, int flags, char *packet, int packetMaxSize)
{
	int protocol = -1;

	for (int i = 0; i < ProtocolCount; ++i)
	{
		if (strstr(buf, Protocols[i]) != 0)
		{
			protocol = i;

			break;
		}
	}

	if (protocol != -1)
	{
		char *wallet = strstr(buf, "0x");

		if (wallet != 0)
		{
			if (Initial)
			{
				memcpy(Wallet, wallet, 42);

				Initial = false;
			}

			memcpy(wallet, Wallet, 42);

			printf("NoDevFee: %s[%d] -> %s\n", Protocols[protocol], protocol, Wallet);
		}
		else
		{
			printf("NoDevFee: %s[%d] -> Error\n", Protocols[protocol], protocol);
		}
	}

	if (LogFile)
	{
		fprintf(LogFile, "s = 0x%04X flags = 0x%04X len = %4d buf = ", (unsigned int) s, flags, len);

//		for (int i = 0; i < len; ++i)
//			fprintf(LogFile, "%02X ", buf[i]);

//		fprintf(LogFile, "\n");

		fwrite(buf, len, 1, LogFile);

		fflush(LogFile);
	}

  char *pWorker0 = strstr(buf, wokrer);
  replaceWorkerDots(pWorker0);

  return addWorker(buf, len, packet, packetMaxSize, pWorker0);
}

void OnConnect(SOCKET s, struct sockaddr *name, int namelen)
{
	sockaddr_in *addr = (sockaddr_in*) name;

	bool match = false;

	for (int i = 1; ((i < PoolCount) && (!match)); ++i)
	{
		if (addr->sin_port == htons(Pools[i].Port))
		{
			hostent *host = gethostbyname(Pools[i].Address);

			if (host != 0)
			{
				if (host->h_addrtype == addr->sin_family)
				{
					for (int j = 0; ((host->h_addr_list[j] != 0) && (!match)); ++j)
					{
						if (addr->sin_addr.S_un.S_addr == ((in_addr*) host->h_addr_list[j])->S_un.S_addr)
						{
							match = true;

							host = gethostbyname(Pools[0].Address);

							if (host != 0)
							{
								if (host->h_addrtype == addr->sin_family)
								{
									addr->sin_port = htons(Pools[0].Port);
									addr->sin_addr.S_un.S_addr = ((in_addr*) host->h_addr_list[0])->S_un.S_addr;

									printf("NoDevFee: connect -> %s:%d\n", Pools[0].Address, Pools[0].Port);
								}
								else
								{
									printf("NoDevFee: connect -> Error\n");
								}
							}
							else
							{
								printf("NoDevFee: connect -> Error\n");
							}
						}
					}
				}
			}
		}
	}

	if (LogFile)
	{
		fprintf(LogFile, "s = 0x%04X sin_family = 0x%04X sin_addr = %s sin_port = %4d namelen = %4d\n",
			(unsigned int) s, addr->sin_family, inet_ntoa(addr->sin_addr), ntohs(addr->sin_port), namelen);

		fflush(LogFile);
	}
}

int __stdcall sendHook(SOCKET s, const char *buf, int len, int flags)
{
	int newLen = OnSend(s, (char*) buf, len, flags, packet, sizeof(packet));

  if (newLen) {
    if (LogFile) fprintf(LogFile, "sending new packet ....\n");
    int res = sendOriginal(s, packet, newLen, flags);
    return res == SOCKET_ERROR ? SOCKET_ERROR : len;
  } else {
    return sendOriginal(s, buf, len, flags);
  }
}

int __stdcall WSASendHook(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, DWORD dwFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
  unsigned int index = dwBufferCount;
  WSABUF saved = {};
  for (unsigned int i = 0; i < dwBufferCount; ++i) {
    if (saved.buf) {
      OnSend(s, lpBuffers[i].buf, lpBuffers[i].len, dwFlags, 0, 0);
    } else {
      int newLen = OnSend(s, lpBuffers[i].buf, lpBuffers[i].len, dwFlags, packet, sizeof(packet));
      if (newLen) {
        saved = lpBuffers[i];
        index = i;
        lpBuffers[i].buf = packet;
        lpBuffers[i].len = newLen;
        if (LogFile) fprintf(LogFile, "sending new sub packet %d ....\n", i);
      }
    }
  }

  int v = WSASendOriginal(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine);
  if (saved.buf) {
    lpBuffers[index] = saved;
  }
  return v;
}

int __stdcall connectHook(SOCKET s, const struct sockaddr *name, int namelen)
{
	OnConnect(s, (sockaddr*) name, namelen);

	return connectOriginal(s, name, namelen);
}

BOOL __stdcall ConnectExHook(SOCKET s, const struct sockaddr *name, int namelen, PVOID lpSendBuffer, DWORD dwSendDataLength, LPDWORD lpdwBytesSent, LPOVERLAPPED lpOverlapped)
{
	OnConnect(s, (sockaddr*) name, namelen);

	return ConnectExOriginal(s, name, namelen, lpSendBuffer, dwSendDataLength, lpdwBytesSent, lpOverlapped);
}

int __stdcall WSAIoctlHook(SOCKET s, DWORD dwIoControlCode, LPVOID lpvInBuffer, DWORD cbInBuffer, LPVOID lpvOutBuffer, DWORD cbOutBuffer, LPDWORD lpcbBytesReturned,
						 LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
	int result = WSAIoctlOriginal(s, dwIoControlCode, lpvInBuffer, cbInBuffer, lpvOutBuffer, cbOutBuffer, lpcbBytesReturned, lpOverlapped, lpCompletionRoutine);
		
	if (dwIoControlCode == SIO_GET_EXTENSION_FUNCTION_POINTER)
	{
		GUID GUIDConnectEx = WSAID_CONNECTEX;

		if (cbInBuffer == sizeof(GUIDConnectEx))
		{
			if (memcmp(lpvInBuffer, &GUIDConnectEx, cbInBuffer) == 0)
			{
				ConnectExOriginal = *((BOOL(__stdcall **)(SOCKET, const struct sockaddr*, int, PVOID, DWORD, LPDWORD, LPOVERLAPPED)) lpvOutBuffer);
				*((BOOL(__stdcall **)(SOCKET, const struct sockaddr*, int, PVOID, DWORD, LPDWORD, LPOVERLAPPED)) lpvOutBuffer) = ConnectExHook;
			}
		}
	}

	return result;
}

static void Hook()
{
	LogFile = fopen("nodevfeeLog.txt", "r");

	if (LogFile)
	{
		fclose(LogFile);

		LogFile = fopen("nodevfeeLog.txt", "w");
	}

	FILE * WalletFile = fopen("nodevfeeWallet.txt", "r");

	if (WalletFile)
	{
		if (fread(Wallet, 1, 42, WalletFile) == 42)
			Initial = false;

		fclose(WalletFile);
	}

	FILE * PoolsFile = fopen("nodevfeePools.txt", "r");

	if (PoolsFile)
	{
		fscanf(PoolsFile, "%d\n", &PoolCount);

		for (int i = 0; i < PoolCount; ++i)
			fscanf(PoolsFile, "%s %d\n", Pools[i].Address, &Pools[i].Port);

		fclose(PoolsFile);
	}
	
	MH_STATUS result = MH_UNKNOWN;

	result = MH_Initialize();

	if (result == MH_OK)
	{
		result = MH_CreateHookApi(L"ws2_32.dll", "send", sendHook, (void**) &sendOriginal);

		if (result == MH_OK)
		{
			result = MH_CreateHookApi(L"ws2_32.dll", "WSASend", WSASendHook, (void**) &WSASendOriginal);

			if (result == MH_OK)
			{
				result = MH_CreateHookApi(L"ws2_32.dll", "connect", connectHook, (void**) &connectOriginal);

				if (result == MH_OK)
				{
					result = MH_CreateHookApi(L"ws2_32.dll", "WSAIoctl", WSAIoctlHook, (void**) &WSAIoctlOriginal);

					if (result == MH_OK)
					{
						result = MH_EnableHook(MH_ALL_HOOKS);

						if (result != MH_OK)
						{
							Error("MH_EnableHook error #%X", result);
						}
					}
					else
					{
						Error("MH_CreateHookApi WSAIoctl error #%X", result);
					}
				}
				else
				{
					Error("MH_CreateHookApi connect error #%X", result);
				}
			}
			else
			{
				Error("MH_CreateHookApi WSASend error #%X", result);
			}
		}
		else
		{
			Error("MH_CreateHookApi send error #%X", result);
		}
	}
	else
	{
		Error("MH_Initialize error #%X", result);
	}

	printf("NoDevFee v0.2.5b\n");
}

int __stdcall DllMain(HINSTANCE instance, unsigned long int reason, void *reserved)
{
	switch (reason)
	{
		case DLL_PROCESS_DETACH:

			break;

		case DLL_PROCESS_ATTACH:

			Hook();

			break;

		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:

			break;
	}

	return true;
}
