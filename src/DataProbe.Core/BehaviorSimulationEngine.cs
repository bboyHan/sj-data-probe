namespace DataProbe.Core;

/// <summary>
/// 行为仿真引擎 — 在自动化操作中模拟人类行为模式，
/// 避免被风控系统标记为机器操作。
///
/// 仿真维度:
///   ① 操作时序 — 点击间隔、页面停留的正态分布
///   ② 鼠标轨迹 — 贝塞尔曲线路径、加速度、overshoot
///   ③ 触摸轨迹 — 滑动曲率、缩放角度、压力变化
///   ④ 背景噪音 — 定时系统更新检查、NTP 同步、随机页面访问
/// </summary>
public class BehaviorSimulationEngine
{
    private readonly Random _rng = new();
    private DateTime _lastActionTime = DateTime.UtcNow;

    // ── 配置 ──

    /// <summary>速度模式: normal / fast / human</summary>
    public string SpeedMode { get; set; } = "normal";

    /// <summary>是否启用鼠标轨迹模拟</summary>
    public bool SimulateMouseTrails { get; set; } = true;

    /// <summary>是否生成背景流量</summary>
    public bool GenerateBackgroundNoise { get; set; }

    /// <summary>夜间静默时段（不操作）</summary>
    public (int StartHour, int EndHour) SilentHours { get; set; } = (1, 6);

    // ── 时序控制 ──

    /// <summary>获取下一个操作间隔（毫秒）</summary>
    public int GetNextInterval()
    {
        if (IsSilentHours()) return _rng.Next(300000, 600000); // 静默期 5-10 分钟

        return SpeedMode switch
        {
            "fast" => NextGaussian(200, 100, 50, 1000),
            "human" => NextGaussian(2000, 800, 300, 8000),
            _ => NextGaussian(800, 300, 100, 3000) // normal
        };
    }

    /// <summary>获取键盘输入延迟（毫秒/字符）</summary>
    public int GetKeyInterval() => SpeedMode switch
    {
        "fast" => _rng.Next(30, 80),
        "human" => _rng.Next(120, 300),
        _ => _rng.Next(60, 150)
    };

    /// <summary>获取页面停留时间（毫秒）</summary>
    public int GetPageDwellTime() => SpeedMode switch
    {
        "fast" => _rng.Next(1000, 3000),
        "human" => _rng.Next(8000, 30000),
        _ => _rng.Next(3000, 10000)
    };

    /// <summary>记录一次操作的时间戳</summary>
    public void RecordAction() => _lastActionTime = DateTime.UtcNow;

    /// <summary>生成鼠标路径点集（贝塞尔曲线）</summary>
    public (int X, int Y)[] GenerateMousePath(int fromX, int fromY, int toX, int toY)
    {
        if (!SimulateMouseTrails)
            return new[] { (toX, toY) };

        var points = new List<(int X, int Y)>();
        var steps = _rng.Next(8, 20);

        // 控制点（引入曲率和 overshoot）
        var cp1x = fromX + (toX - fromX) / 3 + _rng.Next(-50, 50);
        var cp1y = fromY + _rng.Next(-30, 30);
        var cp2x = fromX + 2 * (toX - fromX) / 3 + _rng.Next(-50, 50);
        var cp2y = toY + _rng.Next(-30, 30);

        for (int i = 0; i <= steps; i++)
        {
            var t = (double)i / steps;
            // 三次贝塞尔
            var x = Math.Pow(1 - t, 3) * fromX + 3 * Math.Pow(1 - t, 2) * t * cp1x +
                    3 * (1 - t) * Math.Pow(t, 2) * cp2x + Math.Pow(t, 3) * toX;
            var y = Math.Pow(1 - t, 3) * fromY + 3 * Math.Pow(1 - t, 2) * t * cp1y +
                    3 * (1 - t) * Math.Pow(t, 2) * cp2y + Math.Pow(t, 3) * toY;
            points.Add(((int)x, (int)y));
        }

        return points.ToArray();
    }

    /// <summary>是否处于静默时段</summary>
    public bool IsSilentHours()
    {
        var now = DateTime.UtcNow.Hour;
        return now >= SilentHours.StartHour && now < SilentHours.EndHour;
    }

    /// <summary>正态分布随机数生成</summary>
    private int NextGaussian(double mean, double stdDev, int min, int max)
    {
        var u1 = _rng.NextDouble();
        var u2 = _rng.NextDouble();
        var randStdNormal = Math.Sqrt(-2.0 * Math.Log(u1)) * Math.Sin(2.0 * Math.PI * u2);
        var randNormal = mean + stdDev * randStdNormal;
        return Math.Clamp((int)randNormal, min, max);
    }
}
