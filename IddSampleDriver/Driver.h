#pragma once

#define NOMINMAX
#include <windows.h>
#include <bugcodes.h>
#include <wudfwdm.h>
#include <wdf.h>
#include <iddcx.h>

#include <dxgi1_5.h>
#include <d3d11_2.h>
#include <avrt.h>
#include <wrl.h>

#include <memory>
#include <vector>

#include "Trace.h"

#define IOCTL_ADD_DISPLAY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_REMOVE_DISPLAY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_GET_FRAME CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_WRITE_ACCESS)

namespace Microsoft
{
    namespace WRL
    {
        namespace Wrappers
        {
            // Adds a wrapper for thread handles to the existing set of WRL handle wrapper classes
            typedef HandleT<HandleTraits::HANDLENullTraits> Thread;
        }
    }
}

namespace Microsoft
{
    namespace IndirectDisp
    {
        /// <summary>
        /// Manages the creation and lifetime of a Direct3D render device.
        /// </summary>
        struct IndirectSampleMonitor
        {
            static constexpr size_t szEdidBlock = 128;
            static constexpr size_t szModeList = 3;

            const BYTE pEdidBlock[szEdidBlock];
            const struct SampleMonitorMode {
                DWORD Width;
                DWORD Height;
                DWORD VSync;
            } pModeList[szModeList];
            const DWORD ulPreferredModeIdx;
        };

        /// <summary>
        /// Manages the creation and lifetime of a Direct3D render device.
        /// </summary>
        struct Direct3DDevice
        {
            Direct3DDevice(LUID AdapterLuid);
            Direct3DDevice();
            ~Direct3DDevice();
            HRESULT Init();
            HRESULT Direct3DDevice::UpdateResolution(UINT newWidth, UINT newHeight);
			HRESULT GetFromFrameBuffer(BYTE* pDest, UINT DestSize, UINT* pBytesWritten);

            LUID AdapterLuid;
			UINT Width;
			UINT Height;
            Microsoft::WRL::ComPtr<IDXGIFactory5> DxgiFactory;
            Microsoft::WRL::ComPtr<IDXGIAdapter1> Adapter;
            Microsoft::WRL::ComPtr<ID3D11Device> Device;
            Microsoft::WRL::ComPtr<ID3D11DeviceContext> DeviceContext;

            int ActiveBufferIndex;              // Index of the active buffer

            // Synchronization
            WDFSPINLOCK FrameBufferSpinLock;    // Spinlock for buffer access

            // GPU to CPU Copy
            Microsoft::WRL::ComPtr<ID3D11Texture2D> StagingTexture[2]; // Staging texture for GPU → CPU copy
        };

        /// <summary>
        /// Manages a thread that consumes buffers from an indirect display swap-chain object.
        /// </summary>
        class SwapChainProcessor
        {
        public:
            SwapChainProcessor(IDDCX_SWAPCHAIN hSwapChain, std::shared_ptr<Direct3DDevice> Device, HANDLE NewFrameEvent);
            ~SwapChainProcessor();

            std::shared_ptr<Direct3DDevice> m_Device;

        private:
            static DWORD CALLBACK RunThread(LPVOID Argument);

            void Run();
            void RunCore();

            IDDCX_SWAPCHAIN m_hSwapChain;
            HANDLE m_hAvailableBufferEvent;
            Microsoft::WRL::Wrappers::Thread m_hThread;
            Microsoft::WRL::Wrappers::Event m_hTerminateEvent;
        };

        /// <summary>
        /// Provides a sample implementation of an indirect display driver.
        /// </summary>
        class IndirectDeviceContext
        {
        public:
            IndirectDeviceContext(_In_ WDFDEVICE WdfDevice);
            virtual ~IndirectDeviceContext();

            void InitAdapter();
            NTSTATUS AddDisplay(UINT ConnectorIndex);
			NTSTATUS RemoveDisplay(UINT ConnectorIndex);
			IDDCX_MONITOR GetMonitor(UINT ConnectorIndex);
			bool HasMonitor(UINT ConnectorIndex);

        protected:
            WDFDEVICE m_WdfDevice;
            IDDCX_ADAPTER m_Adapter;

			IDDCX_MONITOR m_Monitors[8]; //We support up to 8 monitors.
        };

        class IndirectMonitorContext
        {
        public:
            IndirectMonitorContext(_In_ IDDCX_MONITOR Monitor);
            virtual ~IndirectMonitorContext();

            void AssignSwapChain(IDDCX_SWAPCHAIN SwapChain, LUID RenderAdapter, HANDLE NewFrameEvent);
            void UnassignSwapChain();

            std::unique_ptr<SwapChainProcessor> m_ProcessingThread;

        private:
            IDDCX_MONITOR m_Monitor;
        } ;
    }
}
