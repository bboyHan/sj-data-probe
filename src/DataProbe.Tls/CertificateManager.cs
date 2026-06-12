using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Caching.Memory;
using DataProbe.Core;

namespace DataProbe.Tls;

/// <summary>
/// Manages root CA and dynamically generates per-domain certificates.
/// Root CA key is protected via Windows DPAPI.
/// Generated certs are cached with 1-hour TTL.
/// </summary>
public class CertificateManager : IDisposable
{
    private readonly X509Certificate2 _rootCa;
    private readonly MemoryCache _certCache;
    private readonly DataProbeConfig _config;

    public CertificateManager(DataProbeConfig config)
    {
        _config = config;
        _rootCa = LoadOrCreateRootCa();
        _certCache = new MemoryCache(new MemoryCacheOptions
        {
            SizeLimit = config.CertCacheSize,
        });
    }

    /// <summary>
    /// Get or generate a certificate for the given hostname.
    /// Certificates are signed by the root CA and valid for 1 hour.
    /// </summary>
    public X509Certificate2 GetOrCreateCert(string hostname)
    {
        var cacheKey = $"cert_{hostname}";

        return _certCache.GetOrCreate(cacheKey, entry =>
        {
            entry.Size = 1;
            entry.AbsoluteExpirationRelativeToNow = TimeSpan.FromHours(_config.CertValidHours);
            entry.SlidingExpiration = TimeSpan.FromMinutes(30);

            return GenerateCert(hostname);
        })!;
    }

    private X509Certificate2 GenerateCert(string hostname)
    {
        using var rsa = RSA.Create(2048);

        var certRequest = new CertificateRequest(
            $"CN={hostname}",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        // SAN extension - required by modern browsers
        var sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddDnsName(hostname);
        certRequest.CertificateExtensions.Add(sanBuilder.Build());

        // Key usage
        certRequest.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
                critical: true));

        // Extended key usage - server authentication
        certRequest.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(
                new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, // Server auth
                critical: true));

        // Generate serial number
        var serial = new byte[16];
        RandomNumberGenerator.Fill(serial);
        serial[0] = (byte)(serial[0] & 0x7F); // Ensure positive

        var now = DateTimeOffset.UtcNow;

        var cert = certRequest.Create(
            _rootCa,
            now.AddDays(-1),
            now.AddHours(_config.CertValidHours),
            serial);

        var certWithKey = cert.CopyWithPrivateKey(rsa);
        var pfxData = certWithKey.Export(X509ContentType.Pkcs12);
        return new X509Certificate2(pfxData, "",
            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);
    }

    private X509Certificate2 LoadOrCreateRootCa()
    {
        var caPath = _config.GetCaCertPath();

        if (File.Exists(caPath))
        {
            try
            {
                var encrypted = File.ReadAllBytes(caPath);
                var decrypted = ProtectedData.Unprotect(
                    encrypted, null, DataProtectionScope.CurrentUser);
                return new X509Certificate2(decrypted);
            }
            catch
            {
                // Corrupted or invalid key; regenerate
            }
        }

        return CreateAndSaveRootCa(caPath);
    }

    private X509Certificate2 CreateAndSaveRootCa(string caPath)
    {
        using var rsa = RSA.Create(4096);

        var certRequest = new CertificateRequest(
            _config.CaSubject,
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        // CA extensions
        certRequest.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(
                certificateAuthority: true,
                hasPathLengthConstraint: false,
                pathLengthConstraint: 0,
                critical: true));

        certRequest.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign,
                critical: true));

        var serial = new byte[16];
        RandomNumberGenerator.Fill(serial);
        serial[0] = (byte)(serial[0] & 0x7F);

        var now = DateTimeOffset.UtcNow;
        var cert = certRequest.CreateSelfSigned(now, now.AddYears(10));

        // Export with private key, encrypt with DPAPI
        var exportData = cert.Export(X509ContentType.Pkcs12);
        var protectedData = ProtectedData.Protect(
            exportData, null, DataProtectionScope.CurrentUser);

        Directory.CreateDirectory(Path.GetDirectoryName(caPath)!);
        File.WriteAllBytes(caPath, protectedData);

        return cert;
    }

    /// <summary>
    /// Export root CA certificate as DER bytes for browser installation
    /// </summary>
    public byte[] ExportRootCaCert()
    {
        return _rootCa.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Cert);
    }

    public void Dispose()
    {
        _certCache.Dispose();
        _rootCa.Dispose();
    }
}
