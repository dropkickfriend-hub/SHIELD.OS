package os.shield.droidsentry

import android.bluetooth.BluetoothManager
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanResult as BleScanResult
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.net.Uri
import android.net.wifi.ScanResult
import android.net.wifi.WifiManager
import android.os.Build
import android.os.Environment
import com.getcapacitor.JSArray
import com.getcapacitor.JSObject
import com.getcapacitor.Plugin
import com.getcapacitor.PluginCall
import com.getcapacitor.PluginMethod
import com.getcapacitor.annotation.CapacitorPlugin
import com.getcapacitor.annotation.Permission
import com.getcapacitor.annotation.PermissionCallback
import java.io.File
import java.io.FileInputStream
import java.security.MessageDigest

private val DANGEROUS_PERMISSIONS = setOf(
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
    "android.permission.READ_CALL_LOG",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.READ_CONTACTS",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.PACKAGE_USAGE_STATS",
)

private val STALKERWARE_INDICATORS = listOf(
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.PACKAGE_USAGE_STATS",
)

@CapacitorPlugin(
    name = "Shield",
    permissions = [
        Permission(alias = "wifi", strings = [
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_WIFI_STATE",
            "android.permission.CHANGE_WIFI_STATE",
            "android.permission.NEARBY_WIFI_DEVICES",
        ]),
        Permission(alias = "ble", strings = [
            "android.permission.BLUETOOTH_SCAN",
            "android.permission.BLUETOOTH_CONNECT",
            "android.permission.ACCESS_FINE_LOCATION",
        ]),
    ]
)
class ShieldPlugin : Plugin() {

    @PluginMethod
    fun listInstalledApps(call: PluginCall) {
        val pm = context.packageManager
        val flags = PackageManager.GET_PERMISSIONS
        val installed: List<PackageInfo> = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(flags.toLong()))
        } else {
            @Suppress("DEPRECATION")
            pm.getInstalledPackages(flags)
        }

        val apps = JSArray()
        for (p in installed) {
            val ai: ApplicationInfo = p.applicationInfo ?: continue
            val isSystem = (ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0
            val requested = p.requestedPermissions?.toList().orEmpty()
            val dangerous = requested.filter { it in DANGEROUS_PERMISSIONS }
            val hasLauncher = pm.getLaunchIntentForPackage(p.packageName) != null
            val stalkerMatches = requested.count { it in STALKERWARE_INDICATORS }

            val suspicious = (!isSystem && !hasLauncher) || stalkerMatches >= 2
            val reason = when {
                stalkerMatches >= 2 -> "Requests $stalkerMatches stalkerware-class permissions."
                !isSystem && !hasLauncher -> "Installed app with no launcher icon."
                else -> null
            }

            val installer = try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    pm.getInstallSourceInfo(p.packageName).installingPackageName
                } else {
                    @Suppress("DEPRECATION")
                    pm.getInstallerPackageName(p.packageName)
                }
            } catch (_: Throwable) { null }

            val obj = JSObject()
            obj.put("packageName", p.packageName)
            obj.put("label", ai.loadLabel(pm).toString())
            obj.put("versionName", p.versionName)
            obj.put("installerPackage", installer)
            obj.put("isSystem", isSystem)
            obj.put("dangerousPermissions", JSArray(dangerous))
            obj.put("suspicious", suspicious)
            if (reason != null) obj.put("suspicionReason", reason)
            obj.put("dataDir", ai.dataDir)
            apps.put(obj)
        }

        val ret = JSObject()
        ret.put("apps", apps)
        call.resolve(ret)
    }

    @PluginMethod
    fun uninstallApp(call: PluginCall) {
        val pkg = call.getString("packageName")
        if (pkg == null) {
            call.reject("packageName is required")
            return
        }
        val intent = Intent(Intent.ACTION_DELETE, Uri.parse("package:$pkg"))
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        try {
            activity.startActivity(intent)
            val ret = JSObject()
            ret.put("ok", true)
            ret.put("message", "Uninstall prompt launched for $pkg.")
            call.resolve(ret)
        } catch (t: Throwable) {
            call.reject("Unable to launch uninstaller: ${t.message}")
        }
    }

    @PluginMethod
    fun scanWifi(call: PluginCall) {
        if (getPermissionState("wifi") != com.getcapacitor.PermissionState.GRANTED) {
            requestPermissionForAlias("wifi", call, "wifiPermissionCallback")
            return
        }
        performWifiScan(call)
    }

    @PermissionCallback
    private fun wifiPermissionCallback(call: PluginCall) {
        if (getPermissionState("wifi") == com.getcapacitor.PermissionState.GRANTED) {
            performWifiScan(call)
        } else {
            call.reject("Location permission required for Wi-Fi scan.")
        }
    }

    private fun performWifiScan(call: PluginCall) {
        val wm = context.applicationContext.getSystemService(WifiManager::class.java)
        if (wm == null) {
            call.reject("WifiManager unavailable.")
            return
        }
        @Suppress("DEPRECATION")
        wm.startScan()
        val results: List<ScanResult> = try { wm.scanResults } catch (_: SecurityException) { emptyList() }
        val arr = JSArray()
        for (r in results) {
            val obj = JSObject()
            obj.put("ssid", r.SSID ?: "")
            obj.put("bssid", r.BSSID ?: "")
            obj.put("level", r.level)
            obj.put("frequency", r.frequency)
            obj.put("capabilities", r.capabilities ?: "")
            arr.put(obj)
        }
        val ret = JSObject()
        ret.put("results", arr)
        call.resolve(ret)
    }

    @PluginMethod
    fun listConnections(call: PluginCall) {
        val connections = JSArray()
        for (path in listOf("/proc/net/tcp", "/proc/net/tcp6")) {
            try {
                val file = File(path)
                if (!file.exists()) continue
                file.readLines().drop(1).forEach { line ->
                    val parts = line.trim().split(Regex("\\s+"))
                    if (parts.size < 4) return@forEach
                    val obj = JSObject()
                    obj.put("localAddr", hexAddr(parts[1]))
                    obj.put("remoteAddr", hexAddr(parts[2]))
                    obj.put("state", tcpStateLabel(parts[3]))
                    connections.put(obj)
                }
            } catch (_: Throwable) { /* silently skip; /proc is filtered on modern Android */ }
        }
        val ret = JSObject()
        ret.put("connections", connections)
        call.resolve(ret)
    }

    private fun hexAddr(h: String): String {
        return try {
            val (addr, port) = h.split(":")
            val p = port.toInt(16)
            if (addr.length == 8) {
                // IPv4 little-endian
                val bytes = addr.chunked(2).reversed().map { it.toInt(16) }
                "${bytes[0]}.${bytes[1]}.${bytes[2]}.${bytes[3]}:$p"
            } else {
                "[ipv6]:$p"
            }
        } catch (_: Throwable) { h }
    }

    private fun tcpStateLabel(hex: String): String = when (hex.uppercase()) {
        "01" -> "ESTABLISHED"
        "02" -> "SYN_SENT"
        "03" -> "SYN_RECV"
        "04" -> "FIN_WAIT1"
        "05" -> "FIN_WAIT2"
        "06" -> "TIME_WAIT"
        "07" -> "CLOSE"
        "08" -> "CLOSE_WAIT"
        "09" -> "LAST_ACK"
        "0A" -> "LISTEN"
        "0B" -> "CLOSING"
        else -> "UNKNOWN"
    }

    // ---- BLE scan -----------------------------------------------------------

    private val bleResults = mutableMapOf<String, BleScanResult>()
    private var bleCallback: ScanCallback? = null

    @PluginMethod
    fun scanBle(call: PluginCall) {
        if (getPermissionState("ble") != com.getcapacitor.PermissionState.GRANTED) {
            requestPermissionForAlias("ble", call, "blePermissionCallback")
            return
        }
        performBleScan(call)
    }

    @PermissionCallback
    private fun blePermissionCallback(call: PluginCall) {
        if (getPermissionState("ble") == com.getcapacitor.PermissionState.GRANTED) {
            performBleScan(call)
        } else {
            call.reject("Bluetooth permission required for BLE scan.")
        }
    }

    private fun performBleScan(call: PluginCall) {
        val bm = context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
        val scanner = bm?.adapter?.bluetoothLeScanner
        if (scanner == null) {
            call.reject("Bluetooth LE scanner unavailable.")
            return
        }
        bleResults.clear()
        try {
            bleCallback?.let { scanner.stopScan(it) }
        } catch (_: SecurityException) {}
        val cb = object : ScanCallback() {
            override fun onScanResult(callbackType: Int, result: BleScanResult) {
                bleResults[result.device.address] = result
            }
            override fun onBatchScanResults(results: MutableList<BleScanResult>) {
                for (r in results) bleResults[r.device.address] = r
            }
        }
        bleCallback = cb
        try {
            scanner.startScan(cb)
        } catch (e: SecurityException) {
            call.reject("Bluetooth permission denied: ${e.message}")
            return
        }

        // Collect for ~4s then return snapshot.
        android.os.Handler(android.os.Looper.getMainLooper()).postDelayed({
            try { scanner.stopScan(cb) } catch (_: SecurityException) {}
            val arr = JSArray()
            for (r in bleResults.values) {
                val obj = JSObject()
                val rec = r.scanRecord
                obj.put("address", r.device.address)
                obj.put("name", try { r.device.name } catch (_: SecurityException) { null } ?: rec?.deviceName ?: "")
                obj.put("rssi", r.rssi)
                obj.put("txPower", if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) r.txPower else 0)
                obj.put("connectable", if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) r.isConnectable else true)
                arr.put(obj)
            }
            val ret = JSObject()
            ret.put("devices", arr)
            call.resolve(ret)
        }, 4000)
    }

    // ---- APK hash scan ------------------------------------------------------

    @PluginMethod
    fun scanApkHashes(call: PluginCall) {
        val knownBad = call.getArray("knownBadHashes")
        val badSet = HashSet<String>()
        if (knownBad != null) {
            for (i in 0 until knownBad.length()) {
                badSet.add(knownBad.getString(i).lowercase())
            }
        }
        val pm = context.packageManager
        val installed = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(0L))
        } else {
            @Suppress("DEPRECATION")
            pm.getInstalledPackages(0)
        }

        val findings = JSArray()
        var scanned = 0
        for (p in installed) {
            val ai = p.applicationInfo ?: continue
            val apkPath = ai.sourceDir ?: continue
            val f = File(apkPath)
            if (!f.exists() || f.length() > 512L * 1024 * 1024) continue
            val hash = try { sha256(f) } catch (_: Throwable) { continue }
            scanned++
            if (hash in badSet) {
                val obj = JSObject()
                obj.put("packageName", p.packageName)
                obj.put("label", ai.loadLabel(pm).toString())
                obj.put("path", apkPath)
                obj.put("sha256", hash)
                obj.put("sizeBytes", f.length())
                obj.put("reason", "MalwareBazaar SHA-256 match")
                findings.put(obj)
            }
        }
        val ret = JSObject()
        ret.put("scanned", scanned)
        ret.put("findings", findings)
        call.resolve(ret)
    }

    private fun sha256(f: File): String {
        val md = MessageDigest.getInstance("SHA-256")
        FileInputStream(f).use { fis ->
            val buf = ByteArray(64 * 1024)
            while (true) {
                val n = fis.read(buf)
                if (n <= 0) break
                md.update(buf, 0, n)
            }
        }
        return md.digest().joinToString("") { "%02x".format(it) }
    }

    // ---- Threat-intel helper ------------------------------------------------

    @PluginMethod
    fun fetchThreatIntel(call: PluginCall) {
        // Kotlin side just piggybacks on the JS fetch — this is a hook to keep
        // parity with desktop. Returns empty for now; web/app does the HTTP.
        val ret = JSObject()
        ret.put("bad_ips", 0)
        ret.put("bad_hashes", 0)
        call.resolve(ret)
    }
}
