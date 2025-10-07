using System.Net;
using System.Net.Sockets;
using System.Text;
using EzSmb;
using EzSmb.Params;
using IRH.Lib.Model.Remote.CopyFile;
using Serilog;
using SMBLibrary;
using SMBLibrary.Client;
using FileAttributes = SMBLibrary.FileAttributes;

namespace IRH.Lib.Class.Remote.CopyFile;
public class CopyFileToRemote
{
    public CopyFileToRemote(ILogger logger)
    {
        _logger = logger;
    }
    
    private readonly ILogger _logger;
    public async Task CopySingleFileAsync(CopyType copyType, string username, string password, string domain, FileInfo sourceFile, string destinationServer, string shareName, string destinationPath)
    {
        switch (copyType)
        {
            case CopyType.Smb:
                _logger.Information("Selected as Copy Type SMB");
                await CopyFileUsingSmb2Async(username, password, domain, sourceFile, destinationServer, shareName, destinationPath);
                break;
        }
    }
    private async Task CopyFileUsingSmb2Async(string username, string password, string domain, FileInfo sourceFile, string destinationServer, string shareName, string destinationPath)
    {
        using (Node Node = await CreateNodeAsync(username, password, domain, destinationServer, shareName))
        {
            if (Node is not null)
            {
                await CreateFolderPathAsyncWhenNotExists(Node, destinationPath);
                bool FileExists = await CheckIfFileExistsAsync(Node, destinationPath);
            
                if (FileExists == false)
                {
                    using (FileStream FileStream = new FileStream(sourceFile.FullName, FileMode.Open, FileAccess.Read))
                    {
                        _logger.Information($"Start to write File {sourceFile.FullName} to {destinationPath} on {Node.FullPath}");
                        bool Result = await Node.Write(FileStream, destinationPath);

                        if (Result)
                        {
                            _logger.Information($"File {sourceFile.FullName} was written successfully to {destinationPath} on {Node.FullPath}");                        
                        }
                        else
                        {
                            _logger.Error($"Unable to write File {sourceFile.FullName} to {destinationPath} on {Node.FullPath}");   
                        }
                    }
                }
            }
        }
        // SMB2Client Client = new SMB2Client();
        // ISMBFileStore FileStore = await Task.Run(() => CreateSmbFileStore(Client, username, password, domain, destinationServer, shareName));
        //
        // if (FileStore is not null)
        // {
        //     if (!CheckIfFileExists(FileStore, destinationPath, destinationServer))
        //     {
        //         await Task.Run(() => CopyFileFromLocal(FileStore, sourceContent, destinationPath, destinationServer));
        //         DisposeManual(FileStore, Client);
        //     }
        //     else
        //     {
        //         _logger.Error($@"File \\{destinationServer}\{shareName}\{destinationPath} already exists");
        //     }
        // }
    }
    private ISMBFileStore CreateSmbFileStore(SMB2Client client, string username, string password, string domain, string destinationServer, string shareName)
    {
        ISMBFileStore Result = null;
        
        try
        {
            _logger.Information($"Try to Start connection to Server {destinationServer}");
            
            bool RawConnected = client.Connect(destinationServer, SMBTransportType.DirectTCPTransport, DefaultValue.DefaultWaitTime);
            
            if (RawConnected)
            {
                _logger.Information($"Raw Network Connection to Server {destinationServer} was successful");
                _logger.Information($"Try to login at {destinationServer} with {username}@{domain}");
                
                NTStatus LoginStatus = client.Login(domain, username, password);
                
                if(LoginStatus == NTStatus.STATUS_SUCCESS)
                {
                    _logger.Information($"Login at {destinationServer} with {username}@{domain} was successful");
                    _logger.Information($"Try to Connect with Share {shareName} on Server {destinationServer} with {username}@{domain}");

                    NTStatus TreeConnectStatus;
                    
                    Result = client.TreeConnect(shareName, out TreeConnectStatus);
                    
                    if (TreeConnectStatus == NTStatus.STATUS_SUCCESS)
                    {
                        _logger.Information($"Connected to Share {shareName} on Server {destinationServer} with {username}@{domain} successfully");
                    }
                    else
                    {
                        _logger.Error($"Connect to Share {shareName} on Server {destinationServer} with {username}@{domain} failed with Status {TreeConnectStatus}");
                    }
                }
                else
                {
                    _logger.Error($"Login at {destinationServer} with {username}@{domain} failed with Status {LoginStatus}");
                }
            }
            else
            {
                _logger.Error($"Unable to connect to Server {destinationServer}");
            }
        }
        catch (SocketException Exception)
        {
            _logger.Error(Exception, "Error connecting to Server");
        }

        return Result;
    }
    private bool CheckIfFileExists(ISMBFileStore fileStore, string filePath, string remoteServer)
    {
        bool Result = false;
        
        object SmbHandle;
        FileStatus FileStatus;
        fileStore.CreateFile(out SmbHandle, out FileStatus, filePath, AccessMask.GENERIC_READ, FileAttributes.Normal,
            ShareAccess.Read, CreateDisposition.FILE_OPEN, CreateOptions.FILE_NON_DIRECTORY_FILE, null);

        if (FileStatus == FileStatus.FILE_OPENED)
        {
            Result = true;
            NTStatus fileHandleCloseStatus = fileStore.CloseFile(SmbHandle);

            if (fileHandleCloseStatus == NTStatus.STATUS_SUCCESS)
            {
                _logger.Verbose($"Closed Handle to File {filePath} successfully for Check if File Exists on Server: {remoteServer}");
            }
            else
            {
                _logger.Warning($"Unable to close Handle to File {filePath} for Check if File Exists on Server: {remoteServer} with Status {fileHandleCloseStatus}");
            }
        }
        
        return Result;
    }
    private void CopyFileFromLocal(ISMBFileStore fileStore, byte[] sourceContent, string destinationPath, string remoteServer)
    {
        object SmbHandle;

        NTStatus FileCreationStatus = fileStore.CreateFile(out SmbHandle, out _, destinationPath, AccessMask.GENERIC_WRITE, FileAttributes.Normal,
            ShareAccess.Read, CreateDisposition.FILE_CREATE, CreateOptions.FILE_NON_DIRECTORY_FILE, null);

        if (FileCreationStatus == NTStatus.STATUS_SUCCESS)
        {
            int DataWritten;

            _logger.Information($"Start to write File Data {destinationPath} to Server: {remoteServer}");
            
            NTStatus FileWriteStatus = fileStore.WriteFile(out DataWritten, SmbHandle, 0, sourceContent);
            
            if(FileWriteStatus == NTStatus.STATUS_SUCCESS)
            {
                _logger.Information($"File Data {destinationPath} was written successfully to (Bytes written: {DataWritten}) on Server: {remoteServer}");
                fileStore.CloseFile(SmbHandle);
            }
            else
            {
                _logger.Error($"Unable to write File Data {destinationPath} with Status {FileWriteStatus} on Server: {remoteServer}");
            }
        }
        else
        {
            _logger.Error($"Unable to create File {destinationPath} with Status {FileCreationStatus} on Server: {remoteServer}");
        }
    }
    private void DisposeManual(ISMBFileStore fileStore, ISMBClient client)
    {
        fileStore.Disconnect();
        client.Logoff();
        client.Disconnect();
    }
}