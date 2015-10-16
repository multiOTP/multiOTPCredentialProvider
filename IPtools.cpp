#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include "IPtools.h"

#include "helpers.h"
#include <string.h>

HRESULT GetRDPClientAddress(_In_ int RDPPort, _Outptr_result_nullonfailure_ PWSTR *IPaddress)
{
	//PrintLn("GetRDPClientAddress");
	HRESULT hr = E_NOTIMPL;

	*IPaddress = nullptr;

	PMIB_TCPTABLE2 pTcpTable;
	ULONG ulSize = 0;
	DWORD dwRetVal = 0;

	char szLocalAddr[128];
	char szRemoteAddr[128];
	PWSTR ptAddr;

	struct in_addr IpAddr;

	int i;

	pTcpTable = (MIB_TCPTABLE2 *)MALLOC(sizeof(MIB_TCPTABLE2));
	if (pTcpTable == NULL) {
		PrintLn("GetRDPClientAddress: Error allocating memory\n");
		return 1;
	}
	ulSize = sizeof(MIB_TCPTABLE);
	// Make an initial call to GetTcpTable2 to
	// get the necessary size into the ulSize variable
	if ((dwRetVal = GetTcpTable2(pTcpTable, &ulSize, TRUE)) ==
		ERROR_INSUFFICIENT_BUFFER) {
		FREE(pTcpTable);
		pTcpTable = (MIB_TCPTABLE2 *)MALLOC(ulSize);
		if (pTcpTable == NULL) {
			PrintLn("GetRDPClientAddress: Error allocating memory\n");
			return 1;
		}
	}
	// Make a second call to GetTcpTable2 to get
	// the actual data we require
	if ((dwRetVal = GetTcpTable2(pTcpTable, &ulSize, TRUE)) == NO_ERROR) {
		for (i = 0; i < (int)pTcpTable->dwNumEntries; i++) {
			if ((ntohs((u_short)pTcpTable->table[i].dwLocalPort) == RDPPort) &&
			    (pTcpTable->table[i].dwState == MIB_TCP_STATE_ESTAB)) {
				/*
			PrintLn("\n\tTCP[%d] State: %ld - ", i,
				pTcpTable->table[i].dwState);
			switch (pTcpTable->table[i].dwState) {
			case MIB_TCP_STATE_CLOSED:
				PrintLn("CLOSED\n");
				break;
			case MIB_TCP_STATE_LISTEN:
				PrintLn("LISTEN\n");
				break;
			case MIB_TCP_STATE_SYN_SENT:
				PrintLn("SYN-SENT\n");
				break;
			case MIB_TCP_STATE_SYN_RCVD:
				PrintLn("SYN-RECEIVED\n");
				break;
			case MIB_TCP_STATE_ESTAB:
				PrintLn("ESTABLISHED\n");
				break;
			case MIB_TCP_STATE_FIN_WAIT1:
				PrintLn("FIN-WAIT-1\n");
				break;
			case MIB_TCP_STATE_FIN_WAIT2:
				PrintLn("FIN-WAIT-2 \n");
				break;
			case MIB_TCP_STATE_CLOSE_WAIT:
				PrintLn("CLOSE-WAIT\n");
				break;
			case MIB_TCP_STATE_CLOSING:
				PrintLn("CLOSING\n");
				break;
			case MIB_TCP_STATE_LAST_ACK:
				PrintLn("LAST-ACK\n");
				break;
			case MIB_TCP_STATE_TIME_WAIT:
				PrintLn("TIME-WAIT\n");
				break;
			case MIB_TCP_STATE_DELETE_TCB:
				PrintLn("DELETE-TCB\n");
				break;
			default:
				PrintLn("UNKNOWN dwState value\n");
				break;
			}
			IpAddr.S_un.S_addr = (u_long)pTcpTable->table[i].dwLocalAddr;
			strcpy_s(szLocalAddr, sizeof(szLocalAddr), inet_ntoa(IpAddr));
			PrintLn("\tTCP[%d] Local Addr: %s\n", i, szLocalAddr);
			PrintLn("\tTCP[%d] Local Port: %d \n", i,
				ntohs((u_short)pTcpTable->table[i].dwLocalPort));
			*/
				IpAddr.S_un.S_addr = (u_long)pTcpTable->table[i].dwRemoteAddr;
				strcpy_s(szRemoteAddr, sizeof(szRemoteAddr), inet_ntoa(IpAddr));
				if (strstr( "0.0.0.0", szRemoteAddr) == 0) {
					//PrintLn("Remote Addr:");
					//PrintLn(szRemoteAddr);
					//PrintLn(ntohs((u_short)pTcpTable->table[i].dwLocalPort));
					//PrintLn(ntohs((u_short)pTcpTable->table[i].dwRemotePort));
					//if (strstr("91.199.25.153", szRemoteAddr) != 0) {
					size_t len = strlen(szRemoteAddr);
					ptAddr = static_cast<PWSTR>(CoTaskMemAlloc(sizeof(wchar_t) * (len + 1)));
					MultiByteToWideChar(
						CP_ACP,
						0,
						szRemoteAddr,
						-1,
						ptAddr,
						128);
					*IPaddress = ptAddr;
					hr = 0;
				}
				//*IPaddress = szRemoteAddr;
				/*
				PrintLn("\tTCP[%d] Remote Port: %d\n", i,
					ntohs((u_short)pTcpTable->table[i].dwRemotePort));

				PrintLn("\tTCP[%d] Owning PID: %d\n", i, pTcpTable->table[i].dwOwningPid);
				PrintLn("\tTCP[%d] Offload State: %ld - ", i,
					pTcpTable->table[i].dwOffloadState);
				switch (pTcpTable->table[i].dwOffloadState) {
				case TcpConnectionOffloadStateInHost:
					PrintLn("Owned by the network stack and not offloaded \n");
					break;
				case TcpConnectionOffloadStateOffloading:
					PrintLn("In the process of being offloaded\n");
					break;
				case TcpConnectionOffloadStateOffloaded:
					PrintLn("Offloaded to the network interface control\n");
					break;
				case TcpConnectionOffloadStateUploading:
					PrintLn("In the process of being uploaded back to the network stack \n");
					break;
				default:
					PrintLn("UNKNOWN Offload state value\n");
					break;
				}*/
			}
		}
	}
	else {
		PrintLn("\tGetTcpTable2 failed with %d\n", dwRetVal);
		FREE(pTcpTable);
		return 1;
	}

	if (pTcpTable != NULL) {
		FREE(pTcpTable);
		pTcpTable = NULL;
	}


	return hr;
}
