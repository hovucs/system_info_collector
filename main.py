import argparse
import os
import subprocess
import sys

from os_checker import OSChecker


def tool_check():
    """Check if all required dependencies are available for main."""
    venv_dir = os.path.join(os.path.dirname(__file__), ".venv")
    venv_python = os.path.join(venv_dir, "bin", "python")
    in_venv = os.environ.get("VIRTUAL_ENV") or sys.prefix != sys.base_prefix
    stdout_target = subprocess.DEVNULL
    stderr_target = subprocess.DEVNULL

    try:
        import paramiko
    except Exception:
        if not in_venv:
            if not os.path.exists(venv_python):
                subprocess.check_call(
                    [sys.executable, "-m", "venv", venv_dir],
                    stdout=stdout_target,
                    stderr=stderr_target,
                )
            subprocess.check_call(
                [venv_python, "-m", "pip", "install", "-U", "pip"],
                stdout=stdout_target,
                stderr=stderr_target,
            )
            subprocess.check_call(
                [venv_python, "-m", "pip", "install", "paramiko"],
                stdout=stdout_target,
                stderr=stderr_target,
            )
            os.execv(venv_python, [venv_python] + sys.argv)
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "paramiko"],
            stdout=stdout_target,
            stderr=stderr_target,
        )

def kb_to_gb_tb(value):
        try:
            kb = int(str(value).split()[0])
            gb = kb / (1024 * 1024)
            if gb >= 1024:
                tb = gb / 1024
                return f"{tb:.2f} TB"
            return f"{gb:.2f} GB"
        except Exception:
            return ""


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="System Info Collector")
    parser.add_argument("--bmc_host", required=True, help="BMC hostname")
    parser.add_argument("--bmc_usr", default="root", help="BMC username")
    parser.add_argument("--bmc_pwd", default="0penBmc", help="BMC password")
    parser.add_argument("--os_host", default="", help="OS hostname")
    parser.add_argument("--os_usr", default="amd", help="OS username")
    parser.add_argument("--os_pwd", default="amd123", help="OS password")
    args = parser.parse_args()

    tool_check()

    os_checker = OSChecker(bmc_hostname=args.bmc_host)

    if args.os_host:
        os_checker.os_hostname = args.os_host
    else:
        os_checker.os_hostname = args.bmc_host
    
    if args.bmc_usr:
        os_checker.bmc_username = args.bmc_usr
    
    if args.bmc_pwd:
        os_checker.bmc_password = args.bmc_pwd
   
    if args.os_usr:
        os_checker.os_username = args.os_usr
    
    if args.os_pwd:
        os_checker.os_password = args.os_pwd


    
    try:
        with os_checker.ssh_connection(
            os_checker.os_hostname,
            os_checker.os_username,
            os_checker.os_password,
        ) as conn:
            info = os_checker.get_info(conn=conn)
            cpu = os_checker.get_cpu(conn=conn)
            memory = os_checker.get_memory(conn=conn)
            disk = os_checker.get_disk(conn=conn)
            pci = os_checker.get_pci(conn=conn)
    except Exception as exc:
        print(f"Failed to collect OS info: {exc}")
        raise SystemExit(1)
    print("SYSTEM: "+ args.bmc_host.upper())
    print("=============================")
    print("|     GENERAL INFORMATION     |")
    print("=============================")
    print("BMC HOSTNAME: "+ info["bmc_hostname"])
    print("BMC USERNAME: "+ info["bmc_username"])
    print("BMC PASSWORD: "+ info["bmc_password"])
    print("OS HOSTNAME: "+ info["os_hostname"])
    print("OS USERNAME: "+ info["os_username"])
    print("OS PASSWORD: "+ info["os_password"])
    print("OS: "+ info["OS"])
    print("KERNEL: "+ info["Kernel"])
    print("CMDLINE: "+ info["cmdline"])
    print("IP ADDRESS: "+ info["ip"])
    print("BIOS: "+ info["BIOS"])

    print("\n=============================")
    print("|       CPU INFORMATION      |")
    print("=============================")
    ordered_keys = [
        "Architecture",
        "CPU(s)",
        "On-line CPU(s) list",
        "Model name",
        "Thread(s) per core",
        "Core(s) per socket",
        "Socket(s)",
        "CPU(s) scaling MHz",
        "CPU max MHz",
        "CPU min MHz",
        "BogoMIPS",
    ]
    for key in ordered_keys:
        if key in cpu:
            print(f"{key.upper()}: {cpu[key]}")

    extra_keys = sorted(k for k in cpu.keys() if k not in ordered_keys)
    numa_keys = [k for k in extra_keys if k.startswith("NUMA")]
    cache_keys = [k for k in extra_keys if k.endswith("cache")]
    other_keys = [k for k in extra_keys if k not in set(numa_keys + cache_keys)]

    if numa_keys:
        print("\nNUMA:")
        for key in numa_keys:
            print(f" - {key}: {cpu[key]}")

    if cache_keys:
        print("\nCACHES (sum of all):")
        for key in cache_keys:
            print(f" - {key}: {cpu[key]}")

    if other_keys:
        print("\nOTHER:")
        for key in other_keys:
            print(f" - {key}: {cpu[key]}")

    print("\n=============================")
    print("|      MEMORY INFORMATION    |")
    print("=============================")
    

    total_gb = kb_to_gb_tb(memory["Total"])
    avail_gb = kb_to_gb_tb(memory["Available"])
    used_gb = kb_to_gb_tb(memory["Used"])

    print("TOTAL: "+ memory["Total"] + (f" ({total_gb})" if total_gb else ""))
    print("AVAILABLE: "+ memory["Available"] + (f" ({avail_gb})" if avail_gb else ""))
    print("USED: "+ memory["Used"] + (f" ({used_gb})" if used_gb else ""))

    dimms = memory.get("DIMMs", [])
    if dimms:
        grouped = {}
        for dimm in dimms:
            size = dimm.get("Size", "")
            if size.lower().startswith("no module"):
                continue
            part = dimm.get("Part Number", "").strip() or "Unknown"
            entry = grouped.setdefault(
                part,
                {
                    "count": 0,
                    "sizes": set(),
                    "types": set(),
                    "speeds": set(),
                    "conf_speeds": set(),
                    "manufacturers": set(),
                    "ranks": set(),
                    "volatile_sizes": set(),
                    "form_factors": set(),
                    "mem_tech": set(),
                    "serials": [],
                },
            )
            entry["count"] += 1
            if size:
                entry["sizes"].add(size)
            dtype = dimm.get("Type", "")
            if dtype:
                entry["types"].add(dtype)
            speed = dimm.get("Speed", "")
            if speed:
                entry["speeds"].add(speed)
            conf_speed = dimm.get("Configured Memory Speed", "")
            if conf_speed:
                entry["conf_speeds"].add(conf_speed)
            manufacturer = dimm.get("Manufacturer", "")
            if manufacturer:
                entry["manufacturers"].add(manufacturer)
            rank = dimm.get("Rank", "")
            if rank:
                entry["ranks"].add(rank)
            volatile_size = dimm.get("Volatile Size", "")
            if volatile_size:
                entry["volatile_sizes"].add(volatile_size)
            form_factor = dimm.get("Form Factor", "")
            if form_factor:
                entry["form_factors"].add(form_factor)
            mem_tech = dimm.get("Memory Technology", "")
            if mem_tech:
                entry["mem_tech"].add(mem_tech)
            serial = dimm.get("Serial Number", "")
            locator = dimm.get("Locator", "")
            if serial or locator:
                entry["serials"].append((serial, locator))

        if grouped:
            print("\nDIMMS:")
            for part, entry in grouped.items():
                print(f"- Part: {part}")
                print(f"  Count: {entry['count']}")
                if entry["sizes"]:
                    print(f"  Size: {', '.join(sorted(entry['sizes']))}")
                if entry["types"]:
                    print(f"  Type: {', '.join(sorted(entry['types']))}")
                if entry["speeds"]:
                    print(f"  Speed: {', '.join(sorted(entry['speeds']))}")
                if entry["conf_speeds"]:
                    print(f"  Configured Speed: {', '.join(sorted(entry['conf_speeds']))}")
                if entry["ranks"]:
                    print(f"  Rank: {', '.join(sorted(entry['ranks']))}")
                if entry["volatile_sizes"]:
                    print(f"  Volatile Size: {', '.join(sorted(entry['volatile_sizes']))}")
                if entry["manufacturers"]:
                    print(f"  Manufacturer: {', '.join(sorted(entry['manufacturers']))}")
                if entry["form_factors"]:
                    print(f"  Form Factor: {', '.join(sorted(entry['form_factors']))}")
                if entry["mem_tech"]:
                    print(f"  Memory Technology: {', '.join(sorted(entry['mem_tech']))}")
                if entry["serials"]:
                    print("  Serials:")
                    for serial, locator in entry["serials"]:
                        serial_text = serial or "Unknown"
                        locator_text = locator or "Unknown"
                        print(f"   - {serial_text} @ {locator_text}")

    

    print("\n=============================")
    print("|       DISK INFORMATION     |")
    print("=============================")
    total_disk = disk.get("Total", "")
    used_disk = disk.get("Used", "")
    free_disk = disk.get("Free", "")
    if total_disk:
        print("TOTAL: " + total_disk + (f" ({kb_to_gb_tb(total_disk)})" if kb_to_gb_tb(total_disk) else ""))
    if used_disk:
        print("USED: " + used_disk + (f" ({kb_to_gb_tb(used_disk)})" if kb_to_gb_tb(used_disk) else ""))
    if free_disk:
        print("FREE: " + free_disk + (f" ({kb_to_gb_tb(free_disk)})" if kb_to_gb_tb(free_disk) else ""))
    devices = disk.get("Devices", [])
    if devices:
        print("\nDEVICES:")
        for dev in devices:
            name = dev.get("Name", "")
            size = dev.get("Size", "")
            model = dev.get("Model", "")
            serial = dev.get("Serial", "")
            used = dev.get("Used", "")
            available = dev.get("Available", "")
            if dev.get("Type") != "disk":
                continue
            if not name:
                continue
            size_text = ""
            try:
                size_bytes = int(size)
                size_gb = size_bytes / (1024 ** 3)
                if size_gb >= 1024:
                    size_tb = size_gb / 1024
                    size_text = f"{size_tb:.2f} TB"
                else:
                    size_text = f"{size_gb:.2f} GB"
            except Exception:
                size_text = ""
            print(f"- {name}")
            
            if model:
                print(f"  Model: {model}")
            used_text = kb_to_gb_tb(used)
            avail_text = kb_to_gb_tb(available)
            if serial:
                print(f"  Serial: {serial}")
            if size_text:
                print(f"  Size: {size_text}")
            if used_text:
                print(f"  Used: {used_text}")
            if avail_text:
                print(f"  Available: {avail_text}")

    print("\n=============================")
    print("|       PCI DEVICES          |")
    print("=============================")
    if pci:
        matches = []
        for dev in pci:
            summary = dev.get("summary", "")
            summary_lower = summary.lower()
            if "ethernet controller" in summary_lower:
                matches.append(dev)
                continue
            if "cx" in summary and "nic" in summary_lower:
                matches.append(dev)
                continue
            if "cxl" in summary_lower:
                matches.append(dev)
        if matches:
            for dev in matches:
                address = dev.get("address", "")
                summary = dev.get("summary", "")
                iface = dev.get("iface", "")
                speed = dev.get("speed", "")
                driver = dev.get("driver", "")
                firmware = dev.get("firmware", "")
                serial = dev.get("serial", "")
                part_number = dev.get("part_number", "")
                vendor = dev.get("vendor", "")
                lnkcap = dev.get("lnkcap", "")
                lnksta = dev.get("lnksta", "")
                print(f"{address} {summary}")
                if iface:
                    print(f"  Interface: {iface}")
                if speed:
                    print(f"  Speed: {speed} Mb/s")
                if driver:
                    print(f"  Driver: {driver}")
                if firmware:
                    print(f"  Firmware: {firmware}")
                if vendor:
                    print(f"  Vendor: {vendor}")
                if part_number:
                    print(f"  Part Number: {part_number}")
                if serial:
                    print(f"  Serial: {serial}")
                if lnkcap:
                    print(f"  LnkCap: {lnkcap}")
                if lnksta:
                    print(f"  LnkSta: {lnksta}")
                details = dev.get("details", "")
                if details:
                    print("  Details:")
                    for line in details.splitlines():
                        print(f"    {line}")
        else:
            print("No matching PCI devices found.")
    else:
        print("No PCI devices found.")
            