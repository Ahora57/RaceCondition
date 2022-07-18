#ifndef LOL_HOOK_CHECK

#define LOL_HOOK_CHECK 1
#include "NtApiDef.h"
#include "lazy_importer.h"
#include <iostream>

namespace lol_hook_checker
{
	namespace debug_port_check
	{
		__declspec(noinline) auto is_corrupted(PDEBUG_PORT debug_port) -> VOID
		{
			while (TRUE)
			{
				if (debug_port->debug_port != NULL)
				{
					debug_port->debug_port = NULL;
					debug_port->port_is_detected = TRUE;
				}
				Sleep(1);
			}
		}
		
		__declspec(noinline) auto is_debug_port_lul() -> bool
		{
			HANDLE thread_handle[10] = { 0 };
			ULONG ret_lenght = NULL; 
			NTSTATUS nt_status = STATUS_UNSUCCESSFUL;
			DEBUG_PORT debug_port;

			debug_port.debug_port = NULL;
			debug_port.port_is_detected = FALSE;

			for (auto i = 0; i <= 3; i++)
				thread_handle[i] = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)is_corrupted, &debug_port, NULL, NULL);
			
			for (auto i = 0; i < 0x13337 && debug_port.port_is_detected != TRUE; i++)
				LI_FN(NtQueryInformationProcess).nt_cached()(NtCurrentProcess, ProcessDebugPort, &debug_port.debug_port, sizeof(HANDLE), &ret_lenght);

			for (auto i = 0; i <= 3; i++)
			{
				if (thread_handle[i])
				{
					TerminateThread(thread_handle[i], NULL);
					CloseHandle(thread_handle[i]);
				}
			}
			return debug_port.port_is_detected;
		}
	}

	namespace hyper_bosd
	{
		__declspec(noinline) auto do_corrupted(PHYPER_BSOD hyper_bsod) -> VOID
		{
			while (TRUE)
			{
				Sleep(2);
				if (hyper_bsod->is_alloce_memory != FALSE)
				{
					VirtualFree(hyper_bsod->buffer, NULL, MEM_RELEASE);
					hyper_bsod->buffer = NULL;
					hyper_bsod->is_alloce_memory = FALSE;
				}
			}
		}
		__declspec(noinline) auto loop_bsod_init() -> VOID
		{
			ULONG lenght = NULL;
			HANDLE thread_handle[10] = { 0 };
			HYPER_BSOD hyper_bsod;

			hyper_bsod.buffer = NULL;
			hyper_bsod.is_alloce_memory = FALSE;

			for (auto i = NULL; i <= 3; i++)
				thread_handle[i] = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)do_corrupted, &hyper_bsod, NULL, NULL);

			for (size_t i = NULL; i < 0x13337; i++)
			{
				LI_FN(NtQueryObject).nt_cached()(NULL, ObjectTypesInformation, &lenght, sizeof(ULONG), &lenght);
				VirtualFree(hyper_bsod.buffer, NULL, MEM_RELEASE);

				hyper_bsod.buffer = VirtualAlloc(NULL, lenght, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

				hyper_bsod.is_alloce_memory = TRUE;

				LI_FN(NtQueryObject).nt_cached()(NtCurrentProcess, ObjectTypesInformation, hyper_bsod.buffer, lenght, NULL);
				if (hyper_bsod.buffer)
					VirtualFree(hyper_bsod.buffer, NULL, MEM_RELEASE);
			}

			for (auto i = 0; i <= 3; i++)
			{
				if (thread_handle[i])
				{
					TerminateThread(thread_handle[i], NULL);
					CloseHandle(thread_handle[i]);
				}
			}
		}
	}
	
	namespace hide_thread_checker
	{
		__declspec(noinline) auto is_corrupted(PTHREAD_HIDE thread_is_hide) -> VOID
		{
			while (TRUE)
			{
				if (thread_is_hide->thread_is_hide == FALSE)
				{
					thread_is_hide->thread_is_hide = TRUE;
					thread_is_hide->bad_hide_is_detected = TRUE;
				}
				Sleep(1);
			}
		}

		__declspec(noinline) auto is_bad_hide_thread() -> bool
		{
			HANDLE thread_handle[10] = { 0 };
			ULONG ret_lenght = NULL;
			NTSTATUS nt_status = STATUS_UNSUCCESSFUL;
			THREAD_HIDE thread_hide ;

			thread_hide.bad_hide_is_detected = FALSE;
			thread_hide.thread_is_hide = TRUE; //We don't check NTSTATUS and it's don't be overwrite by system

			for (auto i = NULL; i <= 3; i++)
				thread_handle[i] = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)is_corrupted, &thread_hide, NULL, NULL);

			nt_status = LI_FN(NtSetInformationThread).nt_cached()(NtCurrentThread, ThreadHideFromDebugger, NULL, NULL);
			if (!NT_SUCCESS(nt_status))
			{
				for (auto i = NULL; i <= 3; i++)
				{
					if (thread_handle[i])
					{
						TerminateThread(thread_handle[i], NULL);
						CloseHandle(thread_handle[i]);
					}
				}
				std::cout << "[!] Bad hide thread!\n";
				return FALSE;
			}

			for (auto i = NULL; i < 0x13337 && thread_hide.bad_hide_is_detected != TRUE; i++)
				LI_FN(NtQueryInformationThread).nt_cached()(NtCurrentThread, ThreadHideFromDebugger, &thread_hide.thread_is_hide, sizeof(thread_hide.thread_is_hide), &ret_lenght);
			
			for (auto i = NULL; i <= 3; i++)
			{
				if (thread_handle[i])
				{
					TerminateThread(thread_handle[i], NULL);
					CloseHandle(thread_handle[i]);
				}
			}
			return thread_hide.bad_hide_is_detected;
		}
	}

}

#endif // !LOL_HOOK_CHECK
