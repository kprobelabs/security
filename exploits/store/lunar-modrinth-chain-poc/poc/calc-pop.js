#!/usr/bin/env node
"use strict";

const { existsSync, mkdirSync, writeFileSync, chmodSync } = require("node:fs");
const { join } = require("node:path");
const { spawn, spawnSync } = require("node:child_process");

const outDir = join(__dirname, "poc-output");
mkdirSync(outDir, { recursive: true });

const markerPath = join(outDir, "marker.txt");
writeFileSync(markerPath, "calc-pop-attempted\n", "utf8");

function detached(command, args, options = {}) {
  const child = spawn(command, args, {
    detached: true,
    stdio: "ignore",
    windowsHide: false,
    ...options,
  });
  child.unref();
}

function commandExists(command) {
  if (process.platform === "win32") {
    return spawnSync("where", [command], { stdio: "ignore" }).status === 0;
  }
  return spawnSync("sh", ["-lc", `command -v ${command}`], {
    stdio: "ignore",
  }).status === 0;
}

function windowsShortcutProof() {
  const shortcutPath = join(outDir, "calc-pop.lnk");
  const jscriptPath = join(outDir, "create-shortcut.js");
  const escapedShortcut = shortcutPath.replace(/\\/g, "\\\\");

  writeFileSync(
    jscriptPath,
    [
      'var shell = WScript.CreateObject("WScript.Shell");',
      `var shortcut = shell.CreateShortcut("${escapedShortcut}");`,
      'shortcut.TargetPath = "calc.exe";',
      'shortcut.WindowStyle = 1;',
      "shortcut.Save();",
      "",
    ].join("\r\n"),
    "utf8"
  );

  const created = spawnSync("cscript.exe", ["//nologo", jscriptPath], {
    stdio: "inherit",
    windowsHide: true,
  });
  if (created.status !== 0 || !existsSync(shortcutPath)) {
    throw new Error("Failed to create Windows shortcut proof");
  }

  detached("cmd.exe", ["/c", "start", "", shortcutPath]);
  return shortcutPath;
}

function macLauncherProof() {
  const launcherPath = join(outDir, "calc-pop.command");
  writeFileSync(launcherPath, "#!/bin/sh\nopen -a Calculator\n", "utf8");
  chmodSync(launcherPath, 0o755);
  detached("open", [launcherPath]);
  return launcherPath;
}

function linuxLauncherProof() {
  const calculators = [
    "gnome-calculator",
    "kcalc",
    "qalculate-gtk",
    "mate-calc",
    "galculator",
    "xcalc",
  ];
  const calculator = calculators.find(commandExists);
  if (!calculator) {
    throw new Error(
      `No supported calculator found. Tried: ${calculators.join(", ")}`
    );
  }

  const launcherPath = join(outDir, "calc-pop.desktop");
  writeFileSync(
    launcherPath,
    [
      "[Desktop Entry]",
      "Type=Application",
      "Name=Calc Pop Proof",
      `Exec=${calculator}`,
      "Terminal=false",
      "",
    ].join("\n"),
    "utf8"
  );
  chmodSync(launcherPath, 0o755);

  if (commandExists("xdg-open")) {
    detached("xdg-open", [launcherPath]);
  } else {
    detached(calculator, []);
  }
  return launcherPath;
}

let opened;
if (process.platform === "win32") {
  opened = windowsShortcutProof();
} else if (process.platform === "darwin") {
  opened = macLauncherProof();
} else if (process.platform === "linux") {
  opened = linuxLauncherProof();
} else {
  throw new Error(`Unsupported platform: ${process.platform}`);
}

console.log("marker: calc-pop-attempted");
console.log(`opened: ${opened}`);
