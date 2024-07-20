#include "stdafx.h"
#include "Tpm2.h"
#include "TpmDevice.h"
#include "TpmTypes.h"
#include <algorithm>

using namespace TpmCpp;
// Function to initialize the TPM context
//TpmCpp::Tpm2 tpm;
//std::unique_ptr<TpmCpp::TpmTcpDevice> tpmDevice;
ByteVec nullVec;
#define null  {}

_TPMCPP Tpm2 tpm;
_TPMCPP TpmDevice* device;

// Beginning of the TPM NV indices range used by the samples
constexpr int NvRangeBegin = 2101;
constexpr int NvRangeEnd = 3000;

// Beginning of the TPM persistent objects range used by the samples
constexpr int PersRangeBegin = 2101;
constexpr int PersRangeEnd = 3000;

std::map<_TPMCPP TPM_CC, int> commandsInvoked;
std::map<_TPMCPP TPM_RC, int> responses;
std::vector<_TPMCPP TPM_CC> commandsImplemented;

// Persistent handle for the AES key
const TpmCpp::TPM_HANDLE persistentHandle = TpmCpp::TPM_HANDLE(0x81010004);

using namespace TpmCpp;

class TpmConfig
{
public:
    // All implemented algorithms
    static std::vector<TPM_ALG_ID> ImplementedAlgs;

    // Implemented hash algorithms
    static std::vector<TPM_ALG_ID> HashAlgs;

    // All commands implemented by the TPM
    static std::vector<TPM_CC> ImplementedCommands;

    static void Init(Tpm2& tpm);

    static bool Implements(TPM_CC cmd);
    static bool Implements(TPM_ALG_ID alg);
};


using namespace std;

vector<TPM_ALG_ID> TpmConfig::ImplementedAlgs;

// Implemented hash algorithms
vector<TPM_ALG_ID> TpmConfig::HashAlgs;

// All commands implemented by the TPM
vector<TPM_CC> TpmConfig::ImplementedCommands;


void TpmConfig::Init(Tpm2& tpm)
{
    if (ImplementedCommands.size() > 0)
    {
        _ASSERT(ImplementedAlgs.size() > 0 && HashAlgs.size() > 0);
        return;
    }

    UINT32 startProp = TPM_ALG_ID::FIRST;
    GetCapabilityResponse resp;
    do {
        resp = tpm.GetCapability(TPM_CAP::ALGS, startProp, TPM_ALG_ID::LAST - startProp + 1);

        auto capData = dynamic_cast<TPML_ALG_PROPERTY*>(&*resp.capabilityData);
        auto algProps = capData->algProperties;

        for (const TPMS_ALG_PROPERTY& p : algProps)
        {
            ImplementedAlgs.push_back(p.alg);
            // Note: "equal" vs. "has" is important in the following 'hash' attr check
            if (p.algProperties == TPMA_ALGORITHM::hash && TPM_HASH::DigestSize(p.alg) > 0)
            {
                HashAlgs.push_back(p.alg);
            }
        }
        startProp = (UINT32)algProps.back().alg + 1;
    } while (resp.moreData);

    startProp = TPM_CC::FIRST;
    do {
        const UINT32 MaxVendorCmds = 32;
        resp = tpm.GetCapability(TPM_CAP::COMMANDS, startProp,
            TPM_CC::LAST - startProp + MaxVendorCmds + 1);
        auto capData = dynamic_cast<TPML_CCA*>(&*resp.capabilityData);
        auto cmdAttrs = capData->commandAttributes;

        for (auto iter = cmdAttrs.begin(); iter != cmdAttrs.end(); iter++)
        {
            TPM_CC cc = *iter & 0xFFFF;
            //TPMA_CC maskedAttr = *iter & 0xFFFF0000;

            ImplementedCommands.push_back(cc);
        }
        startProp = (cmdAttrs.back() & 0xFFFF) + 1;
    } while (resp.moreData);
} // TpmConfig::Init()

bool TpmConfig::Implements(TPM_CC cmd)
{
    return find(ImplementedCommands.begin(), ImplementedCommands.end(), cmd)
        != ImplementedCommands.end();
}

bool TpmConfig::Implements(TPM_ALG_ID alg)
{
    return find(ImplementedAlgs.begin(), ImplementedAlgs.end(), alg) != ImplementedAlgs.end();
}





void TpmCallback(const ByteVec& command, const ByteVec& response)
{
    // Extract the command and responses codes from the buffers.
    // Both are 4 bytes long starting at byte 6
    UINT32* commandCodePtr = (UINT32*)&command[6];
    UINT32* responseCodePtr = (UINT32*)&response[6];

    TPM_CC cmdCode = (TPM_CC)ntohl(*commandCodePtr);
    TPM_RC rcCode = (TPM_RC)ntohl(*responseCodePtr);

    // Strip any parameter decorations
    rcCode = Tpm2::ResponseCodeFromTpmError(rcCode);

    commandsInvoked[cmdCode]++;
    responses[rcCode]++;
}

void Announce(const char* testName)
{
    //SetColor(0);
    cout << endl;
    cout << "================================================================================" << endl;
    cout << "        " << testName << endl;
    cout << "================================================================================" << endl;
    cout << endl << flush;
    //SetColor(1);
}

static void TpmCallbackStatic(const ByteVec& command, const ByteVec& response, void* context)
{
    TpmCallback(command, response);
}

void StartCallbacks()
{
    Announce("Installing callback");

    // Install a callback that is invoked after the TPM command has been executed
    tpm._SetResponseCallback(&TpmCallbackStatic, null);
}

void CleanHandlesOfType(Tpm2& tpm, TPM_HT handleType, UINT32 rangeBegin = 0, UINT32 rangeEnd = 0x00FFFFFF)
{
    UINT32  startHandle = (handleType << 24) + rangeBegin,
        rangeSize = rangeEnd - rangeBegin;
    GetCapabilityResponse resp;
    size_t count = 0;
    for (;;)
    {
        resp = tpm.GetCapability(TPM_CAP::HANDLES, startHandle, rangeSize);
        auto handles = dynamic_cast<TPML_HANDLE*>(&*resp.capabilityData)->handle;

        for (auto& h : handles)
        {
            if ((h.handle & 0x00FFFFFF) >= rangeEnd)
                break;
            if (handleType == TPM_HT::NV_INDEX)
            {
                tpm._AllowErrors().NV_UndefineSpace(TPM_RH::OWNER, h);
                if (!tpm._LastCommandSucceeded())
                    fprintf(stderr, "Failed to clean NV index 0x%08X: error %s\n", h.handle, EnumToStr(tpm._GetLastResponseCode()).c_str());
            }
            else if (handleType == TPM_HT::PERSISTENT)
            {
                tpm._AllowErrors().EvictControl(TPM_RH::OWNER, h, h);
                if (!tpm._LastCommandSucceeded())
                    fprintf(stderr, "Failed to clean persistent object 0x%08X: error %s\n", h.handle, EnumToStr(tpm._GetLastResponseCode()).c_str());
            }
            else
                tpm._AllowErrors().FlushContext(h);
            ++count;
        }

        if (!resp.moreData)
            break;
        auto newStart = (UINT32)handles.back().handle + 1;
        rangeSize -= newStart - startHandle;
        startHandle = newStart;
    }

    if (count)
        cout << "Cleaned " << count << " dangling " << EnumToStr(handleType) << " handle" << (count == 1 ? "" : "s") << endl;
    else
        cout << "No dangling " << EnumToStr(handleType) << " handles" << endl;
}

void RecoverTpm()
{
    tpm._AllowErrors()
        .DictionaryAttackLockReset(TPM_RH::LOCKOUT);

    if (!tpm._LastCommandSucceeded())
    {
        tpm._AllowErrors()
            .Shutdown(TPM_SU::CLEAR);

        // If this is a simulator, power-cycle it and clear just to be sure...
        device->PowerCycle();
        tpm.Startup(TPM_SU::CLEAR);

        // Clearing the TPM:
        // - Deletes persistent and transient objects in the Storage and Endorsement hierarchies;
        // - Deletes non-platform NV indices;
        // - Generates new Storage Primary Seed;
        // - Re-enables disabled hierarchies;
        // - Resets Owner, Endorsement, and Lockout auth values and auth policies;
        // - Resets clock, reset and restart counters.
        tpm.Clear(TPM_RH::PLATFORM);
    }

    CleanHandlesOfType(tpm, TPM_HT::LOADED_SESSION);
    CleanHandlesOfType(tpm, TPM_HT::TRANSIENT);
    CleanHandlesOfType(tpm, TPM_HT::PERSISTENT, PersRangeBegin, PersRangeEnd);
    CleanHandlesOfType(tpm, TPM_HT::NV_INDEX, NvRangeBegin, NvRangeEnd);
}

//void InitTpmContext() {
//    tpmDevice = std::make_unique<TpmCpp::TpmTcpDevice>();
//    tpm._SetDevice(*tpmDevice);
//    tpmDevice->Connect("127.0.0.1", 2321);
//}

void InitTpmContext() {
    device = new TpmCpp::TpmTcpDevice("127.0.0.1", 2321);
    if (!device || !device->Connect())
    {
        device = nullptr;
        throw runtime_error("Could not connect to TPM simulator.");
    }
    std::cout << "TPM Simulator connected." << std::endl;

    tpm._SetDevice(*device);

    // if (UseSimulator)
    {
        // This code is normally not needed for a system/platform TPM.
        assert(device->PlatformAvailable() && device->ImplementsPhysicalPresence() &&
            device->PowerCtlAvailable() && device->LocalityCtlAvailable());

        device->PowerCycle();

        // Startup the TPM
        tpm.Startup(TPM_SU::CLEAR);
    }

    // If the simulator was not shut down cleanly ("disorderly shutdown") or a TPM app
    // crashed midway or has bugs the TPM may go into lockout or have objects abandoned
    // in its (limited) internal memory. Try to clean up and recover the TPM.
    RecoverTpm();

    // Install callbacks to collect command execution statistics.
    StartCallbacks();

    TpmConfig::Init(tpm);
}

std::vector<BYTE> StringToByteVec(std::string const& s)
{
    std::vector<BYTE> bytes;
    bytes.reserve(s.size());

    std::transform(std::begin(s), std::end(s), std::back_inserter(bytes), [](char c) {
        return BYTE(c);
        });

    return bytes;
}

// Function to create a custom name (e.g., a simple hash of "MyCustomAESKeyName")
TpmCpp::ByteVec CreateCustomName() {
    std::string customNameStr = "MyCustomAESKeyName";
    return StringToByteVec(customNameStr);
}

// Function to clear an existing NV index
void ClearExistingNVIndex(TpmCpp::TPM_HANDLE handle) {
    using namespace TpmCpp;

    auto nvReadPublicResponse = tpm.NV_ReadPublic(handle);
    if (tpm._GetLastResponseCode() != TPM_RC::SUCCESS) {
        std::cout << "Clearing existing NV index at handle: " << handle << std::endl;
        tpm.NV_UndefineSpace(TPM_RH::OWNER, handle);
        if (tpm._GetLastResponseCode() != TPM_RC::SUCCESS) {
            std::cerr << "Failed to clear existing NV index." << std::endl;
            throw std::runtime_error("Failed to clear existing NV index");
        }
        std::cout << "Existing NV index cleared." << std::endl;
    }
}

// Function to generate an AES key
TpmCpp::TPM_HANDLE GenerateAESKey() {
    using namespace TpmCpp;

    // Define the primary key template
    TPMT_PUBLIC primaryTemplate(TPM_ALG_ID::SHA256,
        TPMA_OBJECT::restricted | TPMA_OBJECT::decrypt | TPMA_OBJECT::userWithAuth | TPMA_OBJECT::sensitiveDataOrigin | TPMA_OBJECT::fixedTPM | TPMA_OBJECT::fixedParent,
        nullVec, // Auth policy
        TPMS_RSA_PARMS(
            TPMT_SYM_DEF_OBJECT(TPM_ALG_ID::AES, 128, TPM_ALG_ID::CFB),
            TPMS_NULL_ASYM_SCHEME(),
            2048,
            0),
        TPM2B_PUBLIC_KEY_RSA());

    // Create the primary key
    auto primaryKey = tpm.CreatePrimary(TPM_RH::OWNER, null, primaryTemplate, null, null).handle;
    std::cout << "Primary key created." << std::endl;

    // Define the AES key template
    TPMT_PUBLIC aesTemplate(
        TPM_ALG_ID::SHA256,
        TPMA_OBJECT::userWithAuth | TPMA_OBJECT::decrypt | TPMA_OBJECT::encrypt | TPMA_OBJECT::sensitiveDataOrigin | TPMA_OBJECT::fixedTPM | TPMA_OBJECT::fixedParent,
        nullVec, // Auth policy
        TPMS_SYMCIPHER_PARMS(TPMT_SYM_DEF_OBJECT(TPM_ALG_ID::AES, 128, TPM_ALG_ID::CFB)),
        TPM2B_DIGEST_SYMCIPHER()
    );

    // Create the AES key
    auto aesKey = tpm.Create(primaryKey, null, aesTemplate, null, null);
    if (tpm._GetLastResponseCode() != TPM_RC::SUCCESS) {
		std::cerr << "Failed to create AES key" << std::endl;
		return 0;
	}
    std::cout << "AES key created." << std::endl;

    // Load the AES key
    auto aesKeyHandle = tpm.Load(primaryKey, aesKey.outPrivate, aesKey.outPublic);
    if (tpm._GetLastResponseCode() != TPM_RC::SUCCESS) {
        std::cerr << "Failed to load AES key" << std::endl;
        tpm.FlushContext(primaryKey);
        return 0;
    }
    std::cout << "AES key loaded." << std::endl;

 //   // Evict the key to a persistent handle
 //   tpm.EvictControl(TPM_RH::OWNER, aesKeyHandle.handle, persistentHandle);
 //   if (tpm._GetLastResponseCode() != TPM_RC::SUCCESS) {
	//	std::cerr << "Failed to evict AES key" << std::endl;
 //       tpm.FlushContext(aesKeyHandle.handle);
 //       tpm.FlushContext(primaryKey);
 //       return 0;
	//}

    //// Set the name for the handle
    //TpmCpp::TPMS_CONTEXT context = tpm.ContextSave(aesKeyHandle.handle);
    //context.savedHandle = persistentHandle.handle;
    //tpm.ContextLoad(context);

    // Read the public part of the key to get its name
    auto readPublicResponse = tpm.ReadPublic(aesKeyHandle.handle).outPublic;
    // handle the response
    if (tpm._GetLastResponseCode() != TPM_RC::SUCCESS)
    {
        std::cerr << "Failed to read public part of AES key." << std::endl;
        tpm.FlushContext(aesKeyHandle.handle);
        tpm.FlushContext(primaryKey);
        throw std::runtime_error("Failed to read public part of AES key");
    }
    std::cout << "AES key public part read." << std::endl;

    //// Manually set the name for the handle
    //aesKeyHandle.SetName(readPublicResponse.GetName());

    // Create and set the custom name
    ByteVec customName = CreateCustomName();
    aesKeyHandle.SetName(customName);

    std::cout << "AES key public part read. Name: ";
    for (BYTE b : aesKeyHandle.GetName()) {
        std::cout << std::hex << static_cast<int>(b) << " ";
    }
    std::cout << std::endl;

    // Clear any existing NV index at the desired handle
    //ClearExistingNVIndex(persistentHandle);

    // Persist the key
    tpm.EvictControl(TPM_RH::OWNER, aesKeyHandle, persistentHandle);
    if (tpm._GetLastResponseCode() != TPM_RC::SUCCESS) {
        std::cerr << "Failed to persist AES key." << std::endl;
        tpm.FlushContext(aesKeyHandle.handle);
        tpm.FlushContext(primaryKey);
        throw std::runtime_error("Failed to persist AES key");
    }
    std::cout << "AES key persisted with handle: " << persistentHandle << std::endl;

    //if (!evictResponse.isSuccess()) {
    //    std::cerr << "Failed to persist AES key: " << evictResponse << std::endl;
    //    tpm.FlushContext(aesKeyHandle.handle);
    //    tpm.FlushContext(primaryKey);
    //    throw std::runtime_error("Failed to persist AES key");
    //}


    // Flush the transient handles
    tpm.FlushContext(aesKeyHandle.handle);
    tpm.FlushContext(primaryKey);

    std::cout << "AES key has been persisted with handle: " << persistentHandle << std::endl;

    return aesKeyHandle;
}

void FinishCallbacks()
{
    Announce("Processing callback data");

    cout << "Commands invoked:" << endl;
    for (auto it = commandsInvoked.begin(); it != commandsInvoked.end(); ++it)
        cout << dec << setfill(' ') << setw(32) << EnumToStr(it->first) << ": count = " << it->second << endl;

    cout << endl << "Responses received:" << endl;
    for (auto it = responses.begin(); it != responses.end(); ++it)
        cout << dec << setfill(' ') << setw(32) << EnumToStr(it->first) << ": count = " << it->second << endl;

    cout << endl << "Commands not exercised:" << endl;
    for (auto it = commandsImplemented.begin(); it != commandsImplemented.end(); ++it)
    {
        if (commandsInvoked.find(*it) == commandsInvoked.end())
            cout << dec << setfill(' ') << setw(1) << EnumToStr(*it) << " ";
    }
    cout << endl;
    tpm._SetResponseCallback(NULL, NULL);
}

// Function to retrieve the AES key handle from a persistent handle
TpmCpp::TPM_HANDLE RetrieveAESKeyHandle() {
    // The handle is directly usable as it is a persistent handle
    return persistentHandle;
}

// Function to encrypt data using the AES key handle
std::vector<BYTE> EncryptData(const std::vector<BYTE>& data, TpmCpp::TPM_HANDLE keyHandle) {
    using namespace TpmCpp;
    ByteVec iv(16, 0); // Initialization Vector (IV) for AES CFB

    // Encrypt the data using the AES key handle
    auto encrypted = tpm.EncryptDecrypt2(keyHandle, data, false, TPM_ALG_ID::CFB, iv).outData;
    return encrypted;
}

// Function to decrypt data using the AES key handle
std::vector<BYTE> DecryptData(const std::vector<BYTE>& data, TpmCpp::TPM_HANDLE keyHandle) {
    using namespace TpmCpp;
    ByteVec iv(16, 0); // Initialization Vector (IV) for AES CFB

    auto decrypted = tpm.EncryptDecrypt2(keyHandle, data, true, TPM_ALG_ID::CFB, iv).outData;
    return decrypted;
}

int main() {
    try {
        InitTpmContext();

        // Uncomment the following line if you need to generate and persist the AES key initially
        //TpmCpp::TPM_HANDLE aesKeyHandle = GenerateAESKey();

        // Retrieve the AES key handle from the persistent handle
        TpmCpp::TPM_HANDLE aesKeyHandle = RetrieveAESKeyHandle();
        if (aesKeyHandle == 0) {
			std::cerr << "Failed to retrieve AES key handle" << std::endl;
			return 1;
		}

        // output generated AES key handle
        auto handle = aesKeyHandle.operator UINT32();
        if (handle == 0) {
            std::cerr << "Failed to generate AES key" << std::endl;
            return 1;
        }

        std::cout << "Generated AES key handle: " << handle << std::endl;

        // Example data to encrypt and decrypt
        //std::vector<BYTE> dataToEncrypt = { 0x01, 0x02, 0x03, 0x04, 0x05 };
        ByteVec dataToEncrypt{ 1, 2, 3, 4, 5, 4, 3, 2, 12, 3, 4, 5 };

        // Encrypt the data
        std::vector<BYTE> encryptedData = EncryptData(dataToEncrypt, aesKeyHandle);
        std::cout << "Encrypted data: ";
        for (BYTE b : encryptedData) {
            std::cout << std::hex << static_cast<int>(b) << " ";
        }
        std::cout << std::endl;

        // Decrypt the data
        std::vector<BYTE> decryptedData = DecryptData(encryptedData, aesKeyHandle);
        std::cout << "Decrypted data: ";
        for (BYTE b : decryptedData) {
            std::cout << std::hex << static_cast<int>(b) << " ";
        }
        std::cout << std::endl;


        // A clean shutdown results in fewer lockout errors.
        tpm.Shutdown(TPM_SU::CLEAR);
        device->PowerOff();
        device->Close();

        // The following routine finalizes and prints the function stats.
        FinishCallbacks();

        delete device;

    }
    catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
