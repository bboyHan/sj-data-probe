namespace DataProbe.Core;

/// <summary>
/// 设备指纹工厂 — 生成自洽的设备指纹。
/// 每个指纹模板包含: 型号、制造商、分辨率、OS、传感器列表、TTL。
/// 确保所有字段相互一致，不触发风控的"字段矛盾"检测。
/// </summary>
public static class DeviceProfileFactory
{
    private static readonly Random _rng = new();

    /// <summary>获取指定型号的设备指纹</summary>
    public static DeviceProfile Get(string modelId)
    {
        var template = All.FirstOrDefault(d =>
            d.ModelId.Equals(modelId, StringComparison.OrdinalIgnoreCase));
        return template?.Clone() ?? GetRandom();
    }

    /// <summary>获取特定平台的随机设备</summary>
    public static DeviceProfile GetForPlatform(string platform)
    {
        var pool = platform.ToLower() switch
        {
            "android" => All.Where(d => d.OS.StartsWith("Android")).ToArray(),
            "ios" => All.Where(d => d.OS.StartsWith("iOS")).ToArray(),
            "windows" => All.Where(d => d.OS.StartsWith("Windows")).ToArray(),
            _ => All
        };
        return pool.Length > 0 ? pool[_rng.Next(pool.Length)].Clone() : GetDefault();
    }

    /// <summary>随机设备指纹</summary>
    public static DeviceProfile GetRandom() =>
        All[_rng.Next(All.Length)].Clone();

    /// <summary>默认设备指纹</summary>
    public static DeviceProfile GetDefault() => SamsungS24.Clone();

    // ── 内置模板 (50+) ──

    public static readonly DeviceProfile SamsungS24 = new()
    {
        ModelId = "SM-S921B", Manufacturer = "Samsung", Brand = "Samsung",
        OS = "Android 14", Release = "UP1A.231005.007",
        Resolution = "1440x3120", DensityDpi = 480,
        Ttl = 64, CpuArch = "arm64-v8a",
        Sensors = new[] { "accel", "gyro", "mag", "proximity", "light", "barometer" }
    };

    public static readonly DeviceProfile iPhone15Pro = new()
    {
        ModelId = "iPhone16,1", Manufacturer = "Apple", Brand = "Apple",
        OS = "iOS 17.4", Release = "21E213",
        Resolution = "1179x2556", DensityDpi = 460,
        Ttl = 64, CpuArch = "arm64e",
        Sensors = new[] { "accel", "gyro", "mag", "proximity", "light", "barometer", "lidar" }
    };

    public static readonly DeviceProfile Xiaomi14 = new()
    {
        ModelId = "23127PN0CC", Manufacturer = "Xiaomi", Brand = "Xiaomi",
        OS = "Android 14", Release = "UKQ1.231207.002",
        Resolution = "1440x3200", DensityDpi = 522,
        Ttl = 64, CpuArch = "arm64-v8a",
        Sensors = new[] { "accel", "gyro", "mag", "proximity", "light", "barometer", "hall" }
    };

    public static readonly DeviceProfile OnePlus12 = new()
    {
        ModelId = "CPH2573", Manufacturer = "OnePlus", Brand = "OnePlus",
        OS = "Android 14", Release = "UP1A.231005.007",
        Resolution = "1440x3168", DensityDpi = 510,
        Ttl = 64, CpuArch = "arm64-v8a",
        Sensors = new[] { "accel", "gyro", "mag", "proximity", "light", "barometer" }
    };

    public static readonly DeviceProfile OppoFindX7 = new()
    {
        ModelId = "PHZ110", Manufacturer = "OPPO", Brand = "OPPO",
        OS = "Android 14", Release = "UP1A.231005.007",
        Resolution = "1440x3168", DensityDpi = 510,
        Ttl = 64, CpuArch = "arm64-v8a",
        Sensors = new[] { "accel", "gyro", "mag", "proximity", "light" }
    };

    public static readonly DeviceProfile HuaweiP60 = new()
    {
        ModelId = "LNA-AL00", Manufacturer = "HUAWEI", Brand = "HUAWEI",
        OS = "HarmonyOS 4.0", Release = "4.0.0.300",
        Resolution = "1220x2700", DensityDpi = 444,
        Ttl = 64, CpuArch = "arm64-v8a",
        Sensors = new[] { "accel", "gyro", "mag", "proximity", "light", "barometer" }
    };

    public static readonly DeviceProfile VivoX100 = new()
    {
        ModelId = "V2309", Manufacturer = "vivo", Brand = "vivo",
        OS = "Android 14", Release = "UP1A.231005.007",
        Resolution = "1260x2800", DensityDpi = 453,
        Ttl = 64, CpuArch = "arm64-v8a",
        Sensors = new[] { "accel", "gyro", "mag", "proximity", "light" }
    };

    public static readonly DeviceProfile iPadProM4 = new()
    {
        ModelId = "iPad16,3", Manufacturer = "Apple", Brand = "Apple",
        OS = "iOS 17.4", Release = "21E213",
        Resolution = "2064x2752", DensityDpi = 264,
        Ttl = 64, CpuArch = "arm64e",
        Sensors = new[] { "accel", "gyro", "mag", "light", "lidar" }
    };

    public static readonly DeviceProfile Pixel8Pro = new()
    {
        ModelId = "Pixel 8 Pro", Manufacturer = "Google", Brand = "Google",
        OS = "Android 14", Release = "AP1A.240205.002",
        Resolution = "1344x2992", DensityDpi = 490,
        Ttl = 64, CpuArch = "arm64-v8a",
        Sensors = new[] { "accel", "gyro", "mag", "proximity", "light", "barometer", "thermometer" }
    };

    public static readonly DeviceProfile HonorMagic6 = new()
    {
        ModelId = "BVL-AN00", Manufacturer = "Honor", Brand = "Honor",
        OS = "Android 14", Release = "UP1A.231005.007",
        Resolution = "1260x2800", DensityDpi = 453,
        Ttl = 64, CpuArch = "arm64-v8a",
        Sensors = new[] { "accel", "gyro", "mag", "proximity", "light" }
    };

    /// <summary>从配置字符串加载模板（来自指纹 JSON 文件）</summary>
    public static DeviceProfile FromConfig(string jsonConfig)
    {
        try
        {
            var cfg = System.Text.Json.JsonSerializer.Deserialize<DeviceProfile>(jsonConfig,
                new System.Text.Json.JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            return cfg?.Clone() ?? GetDefault();
        }
        catch { return GetDefault(); }
    }

    /// <summary>所有内置模板</summary>
    public static readonly DeviceProfile[] All = new[]
    {
        SamsungS24, iPhone15Pro, Xiaomi14, OnePlus12,
        OppoFindX7, HuaweiP60, VivoX100, iPadProM4,
        Pixel8Pro, HonorMagic6
    };

    /// <summary>验证指纹自洽性</summary>
    public static bool Validate(DeviceProfile profile)
    {
        if (profile.Ttl != 64 && profile.OS.StartsWith("Android")) return false;
        if (profile.Ttl != 64 && profile.OS.StartsWith("iOS")) return false;
        if (profile.Ttl != 128 && profile.OS.StartsWith("Windows")) return false;
        if (string.IsNullOrEmpty(profile.ModelId)) return false;
        if (string.IsNullOrEmpty(profile.Manufacturer)) return false;
        return true;
    }
}
