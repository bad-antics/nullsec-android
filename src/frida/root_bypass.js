/*
 * ═══════════════════════════════════════════════════════════════════
 *  NULLSEC Android Frida Root Detection Bypass
 *  Bypass root and integrity checks on Android applications
 *  @author bad-antics | discord.gg/killers
 * ═══════════════════════════════════════════════════════════════════
 */

const VERSION = "2.0.0";
const AUTHOR = "bad-antics";
const DISCORD = "discord.gg/killers";

const BANNER = `
╭──────────────────────────────────────────╮
│    🤖 NULLSEC ANDROID ROOT BYPASS       │
│    ═══════════════════════════════════  │
│                                          │
│   🔓 Root Detection Bypass               │
│   🛡️  Integrity Check Defeat             │
│   📱 Universal Android Support           │
│                                          │
│          bad-antics | NullSec            │
╰──────────────────────────────────────────╯
`;

// ═══════════════════════════════════════════════════════════════════
// License Management
// ═══════════════════════════════════════════════════════════════════

const LicenseTier = {
    FREE: 0,
    PREMIUM: 1,
    ENTERPRISE: 2
};

let currentLicense = {
    key: "",
    tier: LicenseTier.FREE,
    valid: false
};

function validateLicense(key) {
    if (!key || key.length !== 24) return false;
    if (!key.startsWith("NAND-")) return false;
    
    currentLicense.key = key;
    currentLicense.valid = true;
    
    const typeCode = key.substring(5, 7);
    if (typeCode === "PR") {
        currentLicense.tier = LicenseTier.PREMIUM;
    } else if (typeCode === "EN") {
        currentLicense.tier = LicenseTier.ENTERPRISE;
    } else {
        currentLicense.tier = LicenseTier.FREE;
    }
    
    return true;
}

function isPremium() {
    return currentLicense.valid && currentLicense.tier !== LicenseTier.FREE;
}

// ═══════════════════════════════════════════════════════════════════
// Logging
// ═══════════════════════════════════════════════════════════════════

function log(msg) {
    console.log(`[NullSec Root] ${msg}`);
}

function logSuccess(msg) {
    console.log(`[NullSec Root] ✅ ${msg}`);
}

function logError(msg) {
    console.log(`[NullSec Root] ❌ ${msg}`);
}

function logWarning(msg) {
    console.log(`[NullSec Root] ⚠️ ${msg}`);
}

// ═══════════════════════════════════════════════════════════════════
// Root Bypass Methods
// ═══════════════════════════════════════════════════════════════════

// Track bypassed methods
let bypassedMethods = [];

// Root binary paths to hide
const ROOT_BINARIES = [
    "/system/app/Superuser.apk",
    "/sbin/su",
    "/system/bin/su",
    "/system/xbin/su",
    "/data/local/xbin/su",
    "/data/local/bin/su",
    "/system/sd/xbin/su",
    "/system/bin/failsafe/su",
    "/data/local/su",
    "/su/bin/su",
    "/su/bin",
    "/magisk/.core/bin/su",
    "/system/xbin/busybox",
    "/system/bin/busybox",
    "/data/adb/magisk",
    "/sbin/.magisk"
];

// Root packages to hide
const ROOT_PACKAGES = [
    "com.topjohnwu.magisk",
    "com.noshufou.android.su",
    "com.thirdparty.superuser",
    "eu.chainfire.supersu",
    "com.koushikdutta.superuser",
    "com.zachspong.temprootremovejb",
    "com.ramdroid.appquarantine",
    "com.formyhm.hideroot",
    "com.saurik.substrate",
    "de.robv.android.xposed.installer"
];

/**
 * Bypass File.exists() root checks
 */
function bypassFileExists() {
    try {
        const File = Java.use("java.io.File");
        
        File.exists.implementation = function() {
            const path = this.getAbsolutePath();
            
            for (const rootPath of ROOT_BINARIES) {
                if (path.includes(rootPath) || path.toLowerCase().includes("su") ||
                    path.toLowerCase().includes("magisk") || path.includes("superuser")) {
                    logSuccess(`File.exists() bypass: ${path}`);
                    return false;
                }
            }
            
            return this.exists();
        };
        
        bypassedMethods.push("java.io.File.exists()");
        logSuccess("Hooked File.exists()");
        return true;
    } catch (e) {
        logError(`File.exists() bypass error: ${e}`);
        return false;
    }
}

/**
 * Bypass Runtime.exec() su commands
 */
function bypassRuntimeExec() {
    try {
        const Runtime = Java.use("java.lang.Runtime");
        
        // Hook exec(String)
        Runtime.exec.overload("java.lang.String").implementation = function(cmd) {
            if (cmd.includes("su") || cmd.includes("which") || cmd.includes("busybox")) {
                logSuccess(`Runtime.exec() bypass: ${cmd}`);
                // Return a process that will fail
                return this.exec("echo blocked");
            }
            return this.exec(cmd);
        };
        
        // Hook exec(String[])
        Runtime.exec.overload("[Ljava.lang.String;").implementation = function(cmdArray) {
            const cmd = cmdArray.join(" ");
            if (cmd.includes("su") || cmd.includes("which") || cmd.includes("busybox")) {
                logSuccess(`Runtime.exec([]) bypass: ${cmd}`);
                return this.exec(["echo", "blocked"]);
            }
            return this.exec(cmdArray);
        };
        
        bypassedMethods.push("java.lang.Runtime.exec()");
        logSuccess("Hooked Runtime.exec()");
        return true;
    } catch (e) {
        logError(`Runtime.exec() bypass error: ${e}`);
        return false;
    }
}

/**
 * Bypass ProcessBuilder root checks
 */
function bypassProcessBuilder() {
    try {
        const ProcessBuilder = Java.use("java.lang.ProcessBuilder");
        
        ProcessBuilder.start.implementation = function() {
            const cmdList = this.command();
            const cmd = cmdList.toString();
            
            if (cmd.includes("su") || cmd.includes("which") || cmd.includes("busybox")) {
                logSuccess(`ProcessBuilder.start() bypass: ${cmd}`);
                // Clear the command
                this.command(Java.use("java.util.Arrays").asList(["echo", "blocked"]));
            }
            
            return this.start();
        };
        
        bypassedMethods.push("java.lang.ProcessBuilder.start()");
        logSuccess("Hooked ProcessBuilder.start()");
        return true;
    } catch (e) {
        logError(`ProcessBuilder bypass error: ${e}`);
        return false;
    }
}

/**
 * Bypass PackageManager installed app checks
 */
function bypassPackageManager() {
    try {
        const PackageManager = Java.use("android.app.ApplicationPackageManager");
        
        // Hook getPackageInfo
        PackageManager.getPackageInfo.overload("java.lang.String", "int").implementation = function(pkgName, flags) {
            if (ROOT_PACKAGES.includes(pkgName)) {
                logSuccess(`PackageManager.getPackageInfo() bypass: ${pkgName}`);
                throw Java.use("android.content.pm.PackageManager$NameNotFoundException").$new(pkgName);
            }
            return this.getPackageInfo(pkgName, flags);
        };
        
        // Hook getApplicationInfo
        PackageManager.getApplicationInfo.overload("java.lang.String", "int").implementation = function(pkgName, flags) {
            if (ROOT_PACKAGES.includes(pkgName)) {
                logSuccess(`PackageManager.getApplicationInfo() bypass: ${pkgName}`);
                throw Java.use("android.content.pm.PackageManager$NameNotFoundException").$new(pkgName);
            }
            return this.getApplicationInfo(pkgName, flags);
        };
        
        bypassedMethods.push("android.app.ApplicationPackageManager");
        logSuccess("Hooked PackageManager");
        return true;
    } catch (e) {
        logError(`PackageManager bypass error: ${e}`);
        return false;
    }
}

/**
 * Bypass Build.TAGS check
 */
function bypassBuildTags() {
    try {
        const Build = Java.use("android.os.Build");
        
        // Hook TAGS field
        const originalTags = Build.TAGS.value;
        if (originalTags && originalTags.includes("test-keys")) {
            Build.TAGS.value = "release-keys";
            logSuccess("Build.TAGS changed from test-keys to release-keys");
        }
        
        bypassedMethods.push("android.os.Build.TAGS");
        logSuccess("Hooked Build.TAGS");
        return true;
    } catch (e) {
        logError(`Build.TAGS bypass error: ${e}`);
        return false;
    }
}

/**
 * Bypass System properties check
 */
function bypassSystemProperties() {
    try {
        const SystemProperties = Java.use("android.os.SystemProperties");
        
        SystemProperties.get.overload("java.lang.String").implementation = function(key) {
            const value = this.get(key);
            
            if (key === "ro.build.tags" && value.includes("test-keys")) {
                logSuccess(`SystemProperties.get() bypass: ${key}`);
                return "release-keys";
            }
            
            if (key === "ro.debuggable" && value === "1") {
                logSuccess(`SystemProperties.get() bypass: ${key}`);
                return "0";
            }
            
            if (key === "ro.secure" && value === "0") {
                logSuccess(`SystemProperties.get() bypass: ${key}`);
                return "1";
            }
            
            return value;
        };
        
        bypassedMethods.push("android.os.SystemProperties.get()");
        logSuccess("Hooked SystemProperties.get()");
        return true;
    } catch (e) {
        logError(`SystemProperties bypass error: ${e}`);
        return false;
    }
}

/**
 * Bypass native fopen/access calls (requires Premium)
 */
function bypassNativeCalls() {
    if (!isPremium()) {
        logWarning(`Native bypass is a Premium feature. Get keys at: ${DISCORD}`);
        return false;
    }
    
    try {
        // Hook libc fopen
        const fopen = Module.findExportByName("libc.so", "fopen");
        if (fopen) {
            Interceptor.attach(fopen, {
                onEnter: function(args) {
                    const path = args[0].readUtf8String();
                    
                    for (const rootPath of ROOT_BINARIES) {
                        if (path && path.includes(rootPath)) {
                            logSuccess(`Native fopen() bypass: ${path}`);
                            args[0] = Memory.allocUtf8String("/dev/null");
                        }
                    }
                }
            });
            bypassedMethods.push("libc.so fopen()");
            logSuccess("Hooked native fopen()");
        }
        
        // Hook libc access
        const access = Module.findExportByName("libc.so", "access");
        if (access) {
            Interceptor.attach(access, {
                onEnter: function(args) {
                    this.path = args[0].readUtf8String();
                },
                onLeave: function(retval) {
                    for (const rootPath of ROOT_BINARIES) {
                        if (this.path && this.path.includes(rootPath)) {
                            logSuccess(`Native access() bypass: ${this.path}`);
                            retval.replace(-1);
                        }
                    }
                }
            });
            bypassedMethods.push("libc.so access()");
            logSuccess("Hooked native access()");
        }
        
        // Hook libc stat
        const stat = Module.findExportByName("libc.so", "stat");
        if (stat) {
            Interceptor.attach(stat, {
                onEnter: function(args) {
                    this.path = args[0].readUtf8String();
                },
                onLeave: function(retval) {
                    for (const rootPath of ROOT_BINARIES) {
                        if (this.path && this.path.includes(rootPath)) {
                            logSuccess(`Native stat() bypass: ${this.path}`);
                            retval.replace(-1);
                        }
                    }
                }
            });
            bypassedMethods.push("libc.so stat()");
            logSuccess("Hooked native stat()");
        }
        
        return true;
    } catch (e) {
        logError(`Native bypass error: ${e}`);
        return false;
    }
}

/**
 * Bypass RootBeer library
 */
function bypassRootBeer() {
    try {
        const RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
        
        // Hook all detection methods
        const methods = [
            "isRooted",
            "isRootedWithoutBusyBoxCheck",
            "detectRootManagementApps",
            "detectPotentiallyDangerousApps",
            "detectTestKeys",
            "checkForBusyBoxBinary",
            "checkForSuBinary",
            "checkSuExists",
            "checkForRWPaths",
            "checkForDangerousProps",
            "checkForRootNative",
            "detectRootCloakingApps"
        ];
        
        for (const method of methods) {
            try {
                RootBeer[method].implementation = function() {
                    logSuccess(`RootBeer.${method}() bypassed`);
                    return false;
                };
                bypassedMethods.push(`RootBeer.${method}()`);
            } catch (e) {
                // Method might not exist
            }
        }
        
        logSuccess("RootBeer library bypassed");
        return true;
    } catch (e) {
        // RootBeer not present
        return false;
    }
}

/**
 * Bypass SafetyNet attestation (Premium)
 */
function bypassSafetyNet() {
    if (!isPremium()) {
        logWarning(`SafetyNet bypass is a Premium feature. Get keys at: ${DISCORD}`);
        return false;
    }
    
    try {
        // Note: Full SafetyNet bypass is complex and changes frequently
        // This is a simplified implementation
        
        const SafetyNetClient = Java.use("com.google.android.gms.safetynet.SafetyNetClient");
        
        SafetyNetClient.attest.implementation = function(nonce, apiKey) {
            logSuccess("SafetyNet.attest() intercepted");
            // Return a fake task - full implementation would need to mock the response
            return this.attest(nonce, apiKey);
        };
        
        bypassedMethods.push("SafetyNetClient.attest()");
        logSuccess("SafetyNet hooks installed");
        return true;
    } catch (e) {
        // SafetyNet might not be present
        return false;
    }
}

// ═══════════════════════════════════════════════════════════════════
// Main
// ═══════════════════════════════════════════════════════════════════

function main() {
    console.log(BANNER);
    console.log(`  Version ${VERSION} | ${AUTHOR}`);
    console.log(`  🔑 Premium: ${DISCORD}\n`);
    
    log("Initializing root detection bypass...\n");
    
    Java.perform(function() {
        // Apply all bypass methods
        bypassFileExists();
        bypassRuntimeExec();
        bypassProcessBuilder();
        bypassPackageManager();
        bypassBuildTags();
        bypassSystemProperties();
        bypassRootBeer();
        
        // Premium features
        if (isPremium()) {
            bypassNativeCalls();
            bypassSafetyNet();
        }
        
        // Summary
        log("\n═══════════════════════════════════════════");
        log(`  Bypassed ${bypassedMethods.length} root detection methods`);
        log("═══════════════════════════════════════════\n");
        
        if (bypassedMethods.length > 0) {
            logSuccess("Root detection bypass active!");
        } else {
            logWarning("No root detection methods found");
        }
    });
}

// Run on script load
setTimeout(main, 0);

// Export functions for REPL usage
rpc.exports = {
    status: function() {
        return {
            bypassed: bypassedMethods,
            premium: isPremium()
        };
    },
    setLicense: function(key) {
        return validateLicense(key);
    }
};
